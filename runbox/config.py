"""Strict, data-only repository configuration. Providers own their options."""

import re
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import yaml


class Error(ValueError):
    """Safe operator-facing error; never include untrusted input."""


def retired_configs(root):
    root = Path(root)
    names = {".infisical.json", ".access.toml", ".access.local.toml"}
    for pattern in (".infisical*.yaml", ".infisical*.yml"):
        names.update(path.name for path in root.glob(pattern))
    return sorted(
        name for name in names if (root / name).exists() or (root / name).is_symlink()
    )


def require(condition, message):
    if not condition:
        raise Error(message)


class Loader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        require(not self.check_event(yaml.AliasEvent), "YAML aliases are unsupported")
        event = self.peek_event()
        require(
            getattr(event, "anchor", None) is None
            and getattr(event, "tag", None) is None,
            "YAML anchors and explicit tags are unsupported",
        )
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        result = {}
        for key, value in node.value:
            name = self.construct_object(key, deep=deep)
            require(
                isinstance(name, str) and name not in result,
                "Invalid or duplicate YAML key",
            )
            result[name] = self.construct_object(value, deep=deep)
        return result


def fields(value, required, optional=()):
    require(
        type(value) is dict
        and set(required) <= set(value) <= set(required) | set(optional),
        "Missing or unsupported configuration fields",
    )
    return value


def word(value):
    require(
        isinstance(value, str)
        and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", value),
        "Invalid profile or bundle identifier",
    )
    return value


def relative(value):
    require(
        isinstance(value, str)
        and value
        and not Path(value).is_absolute()
        and all(p not in (".", "..") for p in value.split("/")),
        "Expected a relative path",
    )
    return value


def url(value, https=False):
    require(isinstance(value, str), "Expected an HTTP URL")
    parsed = urlsplit(value)
    require(
        parsed.scheme in (("https",) if https else ("http", "https"))
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and not parsed.fragment
        and "%" not in value
        and not any(c.isspace() for c in value),
        "Invalid HTTP URL",
    )
    try:
        parsed.port
    except ValueError:
        raise Error("Invalid HTTP port") from None
    return parsed


def infisical(value):
    fields(
        value,
        ("type", "instance", "project-id", "access-bundle"),
        ("source", "login-profile", "no-mcp-servers"),
    )
    if "login-profile" in value:
        require(
            isinstance(value["login-profile"], str)
            and re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,255}", value["login-profile"]
            ),
            "Invalid native login profile",
        )
    if "no-mcp-servers" in value:
        require(
            value["no-mcp-servers"] is True, "MCP server suppression cannot be disabled"
        )
    url(value["instance"], https=True)
    require(
        not urlsplit(value["instance"]).path.rstrip("/"),
        "Instance must be an HTTPS origin",
    )
    try:
        uuid.UUID(value["project-id"])
    except (ValueError, TypeError, AttributeError):
        raise Error("Invalid Agent Vault project identifier") from None
    word(value["access-bundle"])
    if "source" in value:
        source = fields(value["source"], ("project-id", "environment", "secret-path"))
        try:
            uuid.UUID(source["project-id"])
        except (ValueError, TypeError, AttributeError):
            raise Error("Invalid source project identifier") from None
        word(source["environment"])
        path = source["secret-path"]
        require(
            isinstance(path, str)
            and path.startswith("/")
            and not any(p in (".", "..") for p in path.split("/")),
            "Invalid source folder",
        )


PROVIDERS = {"infisical": infisical}


def argument_policy(value):
    require(
        value == "any" or type(value) is list and len(value) <= 64,
        "Invalid command argument policy",
    )
    if value == "any":
        return
    for row in value:
        require(type(row) is list and len(row) <= 64, "Invalid command argument list")
        for token in row:
            if isinstance(token, str):
                require(
                    len(token) <= 4096 and "\0" not in token, "Invalid command argument"
                )
            else:
                fields(token, ("pattern",))
                pattern = token["pattern"]
                # Flat character classes and literals keep matching bounded;
                # groups, alternation, lookarounds and backreferences are excluded.
                require(
                    isinstance(pattern, str)
                    and len(pattern) <= 256
                    and re.fullmatch(
                        r"(?:\[[A-Za-z0-9_./:\\-]+\](?:[+*?]|\{[0-9]{1,4}(?:,[0-9]{0,4})?\})?|[A-Za-z0-9_./: -])+",
                        pattern,
                    ),
                    "Only flat bounded argument patterns are supported",
                )
                try:
                    re.compile(pattern)
                except re.error:
                    raise Error("Invalid argument pattern") from None


def arguments_match(policy, supplied):
    if policy in (None, "any"):
        return True
    return any(
        len(row) == len(supplied)
        and all(
            actual == expected
            if isinstance(expected, str)
            else isinstance(actual, str)
            and len(actual) <= 4096
            and re.fullmatch(expected["pattern"], actual) is not None
            for expected, actual in zip(row, supplied)
        )
        for row in policy
    )


def profile(value):
    fields(
        value,
        ("provider", "session", "environment", "execution"),
        ("http", "ready", "services", "probe"),
    )
    require(type(value.get("ready", True)) is bool, "Invalid readiness flag")
    provider = value["provider"]
    require(
        type(provider) is dict and provider.get("type") in PROVIDERS,
        "Unsupported provider",
    )
    PROVIDERS[provider["type"]](provider)
    session = fields(
        value["session"], ("ttl", "proxy"), ("tunnel", "worker", "renewal")
    )
    if "tunnel" in session or "worker" in session:
        from .sessions import validate

        validate(session)
    require(
        isinstance(session["ttl"], str)
        and re.fullmatch(r"(?:[1-9][0-9]{0,2}m|[1-8]h)", session["ttl"])
        and (int(session["ttl"][:-1]) * (60 if session["ttl"][-1] == "h" else 1))
        <= 480,
        "Session TTL must be between 1m and 8h",
    )
    require(
        isinstance(session["proxy"], str)
        and re.fullmatch(r"127\.0\.0\.1:[0-9]{1,5}", session["proxy"])
        and 1024 <= int(session["proxy"].rsplit(":", 1)[1]) <= 65535,
        "Expected a loopback proxy port",
    )
    env = value["environment"]
    require(type(env) is dict, "Environment must be a mapping of public values")
    reserved = {
        "HOME",
        "PATH",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "NODE_OPTIONS",
        "NODE_EXTRA_CA_CERTS",
        "NODE_TLS_REJECT_UNAUTHORIZED",
    }
    for key, val in env.items():
        require(
            re.fullmatch(r"[A-Z][A-Z0-9_]*", key)
            and key not in reserved
            and not key.startswith(("PYTHON", "DYLD_", "LD_", "INFISICAL", "RUNBOX"))
            and isinstance(val, str)
            and len(val) <= 512
            and "\0" not in val
            and "\n" not in val,
            "Unsupported environment variable or value",
        )
        if key == "HF_HUB_DISABLE_IMPLICIT_TOKEN":
            require(val == "1", "Implicit Hub credentials must remain disabled")
        elif key == "CLERK_ENABLE_KEYLESS":
            require(val == "false", "Reviewed Clerk routes must disable keyless setup")
        elif key == "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY":
            require(
                re.fullmatch(r"pk_test_[A-Za-z0-9_=.-]+", val),
                "Expected public development Clerk configuration",
            )
        elif re.search(r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", key):
            require(
                val.endswith("_placeholder"), "Credentials must be public placeholders"
            )
    execution = value["execution"]
    require(type(execution) is dict, "Missing execution policy")
    kind = execution.get("sandbox")
    if kind == "none" and "command" not in execution:
        fields(execution, ("sandbox",))
        require("http" not in value, "Python HTTP guards require the staging sandbox")
    elif kind == "macos-staging":
        fields(execution, ("sandbox", "workspace", "python"))
        workspace = relative(execution["workspace"])
        require(workspace.startswith(".internal/"), "Staging must be under .internal")
        python = fields(
            execution["python"],
            ("source", "package", "command", "entrypoint"),
            ("arguments",),
        )
        arguments = python.get("arguments")
        require(
            arguments is None
            or (
                type(arguments) is list
                and len(arguments) <= 32
                and all(
                    type(row) is list
                    and len(row) <= 32
                    and all(isinstance(item, str) for item in row)
                    for row in arguments
                )
            ),
            "Invalid command argument allowlist",
        )
        if python["source"] != ".":
            relative(python["source"])
        word(python["command"])
        require(
            re.fullmatch(r"[A-Za-z_]\w*", python["package"]), "Invalid Python package"
        )
        require(
            re.fullmatch(
                r"[A-Za-z_]\w*(\.[A-Za-z_]\w*)*:[A-Za-z_]\w*", python["entrypoint"]
            )
            and python["entrypoint"].split(":")[0].split(".")[0] == python["package"],
            "Entrypoint must belong to the reviewed package",
        )
        require("http" in value, "Staging Python requires an HTTP policy")
    elif kind == "macos-command" or kind == "none" and "command" in execution:
        from .sandbox import validate

        validate(execution)
        require(
            execution.get("client", {}).get("type") != "node-http" or "http" in value,
            "Shared Node HTTP clients require an explicit HTTP policy",
        )
        require(
            execution.get("client", {}).get("type") != "python"
            or "probe" not in execution["client"]
            or "http" in value,
            "Shared Python identity checks require an explicit HTTP policy",
        )
    else:
        raise Error("Unsupported sandbox backend")
    if "services" in value:
        from .services import validate

        validate(value["services"])
    if "http" in value:
        http = fields(
            value["http"],
            ("base-url", "credential-variable", "placeholder", "routes", "probe"),
            ("probe-aliases", "additional-probes", "probe-query"),
        )
        parsed = url(http["base-url"])
        require(
            http["base-url"] == http["base-url"].rstrip("/"),
            "Base URL must not end with a slash",
        )
        require(
            http["credential-variable"] in env
            and env[http["credential-variable"]] == http["placeholder"]
            and http["placeholder"].endswith("_placeholder"),
            "Expected public placeholder is missing",
        )
        routes = http["routes"]
        require(
            type(routes) is list and 0 < len(routes) <= 64,
            "Expected explicit HTTP routes",
        )
        pairs = set()
        primary_pairs = set()
        primary_origin = parsed.scheme + "://" + parsed.netloc
        for route in routes:
            fields(
                route,
                ("method", "path"),
                (
                    "forward-host",
                    "queries",
                    "origin",
                    "credential-header",
                    "placeholder",
                ),
            )
            overrides = {"origin", "credential-header", "placeholder"} & set(route)
            if overrides:
                require(
                    overrides == {"origin", "credential-header", "placeholder"}
                    and execution.get("client", {}).get("type")
                    in ("node-http", "node-next"),
                    "Route credential overrides require an explicit shared Node client",
                )
                origin = url(route["origin"])
                require(
                    route["origin"] == origin.scheme + "://" + origin.netloc
                    and origin.netloc == origin.netloc.lower()
                    and not any(c in route["origin"] for c in ("*", "{", "}"))
                    and origin.port != {"http": 80, "https": 443}[origin.scheme]
                    and (
                        origin.scheme == "https"
                        or origin.hostname in ("127.0.0.1", "localhost")
                    ),
                    "Expected an exact HTTPS or loopback service origin",
                )
                header = route["credential-header"]
                require(
                    isinstance(header, str)
                    and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,63}", header)
                    and header.lower()
                    not in {
                        "authorization",
                        "cookie",
                        "set-cookie",
                        "proxy-authorization",
                        "host",
                        "origin",
                        "content-length",
                        "transfer-encoding",
                    }
                    and isinstance(route["placeholder"], str)
                    and route["placeholder"].endswith("_placeholder")
                    and route["placeholder"] in env.values()
                    and "forward-host" not in route,
                    "Expected a reviewed public service-header placeholder",
                )
            route_origin = route.get("origin", primary_origin)
            require(
                route["method"] in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")
                and isinstance(route["path"], str)
                and route["path"].startswith("/" if overrides else parsed.path + "/")
                and not any(x in route["path"] for x in ("%", "?", "#", "..", "\\")),
                "Invalid exact HTTP route",
            )
            if "forward-host" in route:
                target = url(parsed.scheme + "://" + route["forward-host"])
                require(
                    route["method"] == "GET"
                    and parsed.hostname in ("127.0.0.1", "localhost")
                    and target.hostname in ("127.0.0.1", "localhost")
                    and target.port == parsed.port
                    and not target.path,
                    "Unreviewed route alias",
                )
            template = route["path"].replace("{segment}", "x")
            require(
                "{" not in template
                and "}" not in template
                and (not overrides or "{segment}" not in route["path"])
                and ("{segment}" not in route["path"] or route["method"] == "GET"),
                "Invalid route template",
            )
            queries = route.get("queries", [""])
            require(
                type(queries) is list
                and queries
                and all(isinstance(q, str) and len(q) < 256 for q in queries)
                and len(set(queries)) == len(queries)
                and (queries == [""] or route["method"] == "GET"),
                "Invalid exact query allowlist",
            )
            pair = (route_origin, route["method"], route["path"])
            require(pair not in pairs, "Duplicate HTTP route")
            pairs.add(pair)
            if not overrides:
                primary_pairs.add((route["method"], route["path"]))
        require(
            type(http["probe"]) is str
            and "{" not in http["probe"]
            and ("GET", http["probe"]) in primary_pairs,
            "Online probe must be an allowed GET route",
        )
        query = http.get("probe-query", "")
        require(
            isinstance(query, str)
            and any(
                route["method"] == "GET"
                and route["path"] == http["probe"]
                and "origin" not in route
                and query in route.get("queries", [""])
                for route in routes
            ),
            "Online probe query must match its exact GET allowlist",
        )
        aliases = http.get("probe-aliases", [])
        require(type(aliases) is list, "Invalid readiness aliases")
        for alias in aliases:
            fields(alias, ("method", "path"))
            require(
                alias == {"method": "HEAD", "path": parsed.path},
                "Only the base readiness HEAD may alias the GET probe",
            )
        extra = http.get("additional-probes", [])
        require(
            type(extra) is list
            and len(extra) <= 16
            and all(isinstance(path, str) for path in extra)
            and len(set(extra)) == len(extra),
            "Invalid additional verification inventory",
        )
        for path in extra:
            require(
                "{" not in path
                and any(
                    route["method"] == "GET"
                    and route["path"] == path
                    and "origin" not in route
                    and "" in route.get("queries", [""])
                    for route in routes
                ),
                "Additional verification must use an existing exact GET route",
            )
    if "probe" in value:
        probe = fields(value["probe"], ("execution",), ("http",))
        selected = probe["execution"]
        require(
            type(selected) is dict
            and selected.get("sandbox") in ("macos-command", "none")
            and "command" in selected
            and "probe-argv" in selected
            and not {"inputs", "outputs", "handoff", "readiness"} & set(selected),
            "Independent probes require a fixed command without interactive operations",
        )
        require(
            kind == "none" or selected["sandbox"] == "macos-command",
            "Independent probes must retain required OS sandboxing",
        )
        # Validate a complete execution view without inheriting daemon/worker
        # administration. Its live session still uses the original policy.
        profile(
            {
                "provider": provider,
                "session": {key: session[key] for key in ("ttl", "proxy")},
                "environment": env,
                **probe,
            }
        )
    if "renewal" in session:
        from .renewal import validate as validate_renewal

        validate_renewal(value)
    return value


def online_profile(value):
    """Select only the independently reviewed check policy; never mutate run data."""
    if "probe" not in value:
        return value
    result = {key: item for key, item in value.items() if key not in ("probe", "http")}
    result.update(value["probe"])
    return result


def load(path):
    try:
        require(path.stat().st_size <= 65536, "Configuration exceeds size limit")
        value = yaml.load(path.read_text(), Loader=Loader)
        fields(value, ("version",), ("default", "profiles", "bindings", "brokers"))
        require(
            type(value["version"]) is int and value["version"] == 1,
            "Unsupported config version",
        )
        profiles = value.get("profiles", {})
        require(
            type(profiles) is dict and len(profiles) <= 64,
            "Expected named profiles",
        )
        for name, config in profiles.items():
            word(name)
            profile(config)
        require(
            not profiles or value.get("default") in profiles,
            "Default profile is missing",
        )
        require(
            profiles or "default" not in value, "Default command profile is missing"
        )
        bindings = value.get("bindings", {})
        require(type(bindings) is dict, "Expected named source bindings")
        for name, binding in bindings.items():
            word(name)
            fields(
                binding,
                ("type",),
                (
                    "instance",
                    "source",
                    "branch-environments",
                    "variables",
                    "description",
                    "administration-only",
                ),
            )
            require(
                binding["type"] in ("infisical", "unconfigured"),
                "Unsupported binding provider",
            )
            if binding["type"] == "unconfigured":
                require(
                    not set(binding) & {"instance", "source", "branch-environments"},
                    "Unconfigured inventories cannot select a source",
                )
            else:
                require(
                    "instance" in binding and "source" in binding,
                    "Missing source binding",
                )
                source = fields(
                    binding["source"], ("project-id",), ("environment", "secret-path")
                )
                endpoint = url(binding["instance"], https=True)
                require(
                    endpoint.path in ("", "/api"), "Unsupported inventory API prefix"
                )
                # Incomplete historical inventories remain metadata only. Runnable
                # profiles still require every reviewed source field.
                infisical(
                    {
                        "type": binding["type"],
                        "instance": endpoint.scheme + "://" + endpoint.netloc,
                        "project-id": source["project-id"],
                        "access-bundle": "metadata-only",
                        "source": {
                            "environment": "unconfigured",
                            "secret-path": "/",
                            **source,
                        },
                    }
                )
            require(
                type(binding.get("administration-only", False)) is bool,
                "Invalid administration binding",
            )
            require(
                "description" not in binding or isinstance(binding["description"], str),
                "Invalid source description",
            )
            variables = binding.get("variables", [])
            require(
                type(variables) is list
                and len(set(variables)) == len(variables)
                and all(
                    isinstance(s, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", s)
                    for s in variables
                ),
                "Invalid source variable inventory",
            )
            branches = binding.get("branch-environments", {})
            require(
                type(branches) is dict
                and all(
                    isinstance(k, str) and isinstance(v, str)
                    for k, v in branches.items()
                ),
                "Invalid branch bindings",
            )
        brokers = value.get("brokers", {})
        require(type(brokers) is dict, "Broker metadata must be a named mapping")
        for name, broker in brokers.items():
            word(name)
            require(
                type(broker) is dict
                and broker.get("provider")
                in (
                    "gcp-impersonation",
                    "gcloud-impersonation",
                    "github-app-installation",
                ),
                "Unsupported renewal broker provider",
            )
            fields(
                broker,
                (
                    "provider",
                    "infisical",
                    "github"
                    if broker["provider"] == "github-app-installation"
                    else "google",
                ),
                ("proxy",),
            )
            # The privileged broker validates its full closed schema before credential access.
            require(type(broker["infisical"]) is dict, "Invalid broker source metadata")
        require(profiles or bindings or brokers, "Empty Runbox configuration")
        return value
    except Error:
        raise
    except Exception:
        raise Error("Cannot parse Runbox configuration") from None
