"""Strict, data-only repository configuration. Providers own their options."""

import re
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import yaml


class Error(ValueError):
    """Safe operator-facing error; never include untrusted input."""


def require(condition, message):
    if not condition:
        raise Error(message)


class Loader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        require(not self.check_event(yaml.AliasEvent), "YAML aliases are unsupported")
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
    fields(value, ("type", "instance", "project-id", "access-bundle"), ("source",))
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


def profile(value):
    fields(value, ("provider", "session", "environment", "execution"), ("http",))
    provider = value["provider"]
    require(
        type(provider) is dict and provider.get("type") in PROVIDERS,
        "Unsupported provider",
    )
    PROVIDERS[provider["type"]](provider)
    session = fields(value["session"], ("ttl", "proxy"))
    require(
        isinstance(session["ttl"], str)
        and re.fullmatch(r"([1-9]|[12][0-9]|30)m", session["ttl"]),
        "Session TTL must be between 1m and 30m",
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
        if re.search(r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", key):
            require(
                val.endswith("_placeholder"), "Credentials must be public placeholders"
            )
    execution = value["execution"]
    require(type(execution) is dict, "Missing execution policy")
    kind = execution.get("sandbox")
    if kind == "none":
        fields(execution, ("sandbox",))
        require("http" not in value, "Python HTTP guards require the staging sandbox")
    elif kind == "macos-staging":
        fields(execution, ("sandbox", "workspace", "python"))
        workspace = relative(execution["workspace"])
        require(workspace.startswith(".internal/"), "Staging must be under .internal")
        python = fields(
            execution["python"], ("source", "package", "command", "entrypoint")
        )
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
    else:
        raise Error("Unsupported sandbox backend")
    if "http" in value:
        http = fields(
            value["http"],
            ("base-url", "credential-variable", "placeholder", "routes", "probe"),
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
        for route in routes:
            fields(route, ("method", "path"))
            require(
                route["method"] in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")
                and isinstance(route["path"], str)
                and route["path"].startswith(parsed.path + "/")
                and not any(x in route["path"] for x in ("%", "?", "#", "..", "\\")),
                "Invalid exact HTTP route",
            )
            pair = (route["method"], route["path"])
            require(pair not in pairs, "Duplicate HTTP route")
            pairs.add(pair)
        require(
            type(http["probe"]) is str and ("GET", http["probe"]) in pairs,
            "Online probe must be an allowed GET route",
        )
    return value


def load(path):
    try:
        require(path.stat().st_size <= 65536, "Configuration exceeds size limit")
        value = yaml.load(path.read_text(), Loader=Loader)
        fields(value, ("version", "default", "profiles"))
        require(
            type(value["version"]) is int and value["version"] == 1,
            "Unsupported config version",
        )
        profiles = value["profiles"]
        require(
            type(profiles) is dict and 0 < len(profiles) <= 32,
            "Expected named profiles",
        )
        for name, config in profiles.items():
            word(name)
            profile(config)
        require(value["default"] in profiles, "Default profile is missing")
        return value
    except Error:
        raise
    except Exception:
        raise Error("Cannot parse Runbox configuration") from None
