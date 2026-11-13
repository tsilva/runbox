"""Data-only macOS policy composition for reviewed commands and shared clients."""

import json
import os
import re
import sys
from pathlib import Path

from .config import argument_policy, arguments_match, fields, relative, require, word


def validate(execution):
    sandboxed = execution["sandbox"] == "macos-command"
    fields(
        execution,
        (
            "sandbox",
            "command",
            "argv",
            "arguments",
            "integrity",
            *(("permissions",) if sandboxed else ()),
        ),
        (
            "probe-argv",
            "cwd",
            "workspace",
            "client",
            "dependencies",
            "preloads",
            "inputs",
            "outputs",
            "handoff",
            "sanitize-output",
            "stderr",
            "readiness",
        ),
    )
    word(execution["command"])
    for key in ("argv", "probe-argv"):
        if key in execution:
            require(
                type(execution[key]) is list
                and execution[key]
                and all(
                    isinstance(s, str) and "\0" not in s and "\n" not in s
                    for s in execution[key]
                ),
                "Invalid fixed command vector",
            )
    argument_policy(execution["arguments"])
    if "readiness" in execution:
        from .readiness import validate

        validate(execution["readiness"])
    require(
        type(execution.get("sanitize-output", False)) is bool, "Invalid output policy"
    )
    require(
        execution.get("stderr", "inherit") in ("inherit", "discard"),
        "Invalid error-stream policy",
    )
    if "handoff" in execution:
        from .handoff import validate

        validate(execution["handoff"])
    if "outputs" in execution:
        from .outputs import validate

        validate(execution["outputs"])
        forbidden = {
            key: value
            for key, value in execution.items()
            if key not in ("outputs", "permissions")
        }
        encoded = json.dumps(forbidden)
        for name in execution["outputs"]:
            for selected in (name, name + "-parent"):
                require(
                    "{" + selected + "}" not in encoded,
                    "Selected outputs may appear only in filesystem permissions",
                )
                for key, value in execution.get("permissions", {}).items():
                    if key not in ("read", "write"):
                        require(
                            "{" + selected + "}" not in json.dumps(value),
                            "Selected outputs may appear only in filesystem permissions",
                        )
    if "inputs" in execution:
        from .inputs import validate

        validate(execution["inputs"])
        forbidden = {
            key: value
            for key, value in execution.items()
            if key not in ("inputs", "outputs", "permissions")
        }
        encoded = json.dumps(forbidden)
        for name in execution["inputs"]:
            require(
                "{" + name + "}" not in encoded,
                "Selected payloads may appear only in read permissions",
            )
            for key, value in execution.get("permissions", {}).items():
                if key != "read":
                    require(
                        "{" + name + "}" not in json.dumps(value),
                        "Selected payloads may appear only in read permissions",
                    )
    require(
        execution.get("cwd", "repo") in ("repo", "workspace"),
        "Invalid working directory policy",
    )
    if "workspace" in execution:
        relative(execution["workspace"])
        require(
            execution["workspace"].startswith(".internal/"),
            "Staging must remain under .internal",
        )
    integrity = fields(execution["integrity"], ("files",), ("directories",))
    for paths in integrity.values():
        require(
            type(paths) is list and len(paths) <= 256,
            "Invalid source integrity inventory",
        )
        for path in paths:
            relative(path)
            require(
                "node_modules" not in Path(path).parts,
                "Dependency installations require separate runtime review",
            )
    preloads = execution.get("preloads", [])
    require(
        type(preloads) is list and len(preloads) <= 16,
        "Invalid shared preload inventory",
    )
    for path in preloads:
        relative(path)
        require(
            path.endswith(".mjs") and path in integrity["files"],
            "Preloads must be integrity-pinned modules",
        )
    permissions = fields(
        execution.get(
            "permissions", {"read": [], "write": [], "execute": ["{python}"]}
        ),
        ("read", "write", "execute"),
        ("deny-read", "network", "listen", "listen-ports", "deny-all-writes"),
    )
    for key in ("read", "write", "deny-read"):
        rules = permissions.get(key, [])
        require(type(rules) is list and len(rules) <= 256, "Invalid filesystem policy")
        for rule in rules:
            require(
                type(rule) is dict
                and len(rule) == 1
                and set(rule) <= {"file", "directory", "pattern"},
                "Unsupported filesystem predicate",
            )
            value = next(iter(rule.values()))
            require(
                isinstance(value, str) and "\0" not in value and "\n" not in value,
                "Invalid filesystem predicate",
            )
    require(
        type(permissions["execute"]) is list
        and permissions["execute"]
        and all(isinstance(s, str) for s in permissions["execute"]),
        "Expected explicit executable paths",
    )
    for endpoint in permissions.get("network", []):
        require(
            isinstance(endpoint, str)
            and re.fullmatch(r"localhost:[0-9]{1,5}", endpoint)
            and 1 <= int(endpoint.split(":")[1]) <= 65535,
            "Only explicit existing loopback relays are supported",
        )
    require(
        type(permissions.get("listen", False)) is bool,
        "Invalid loopback listener policy",
    )
    ports = permissions.get("listen-ports", [])
    require(
        type(ports) is list
        and len(ports) <= 16
        and all(type(port) is int and 1024 <= port <= 65535 for port in ports)
        and len(set(ports)) == len(ports)
        and not (ports and permissions.get("listen")),
        "Invalid exact listener inventory",
    )
    require(
        type(permissions.get("deny-all-writes", False)) is bool, "Invalid write policy"
    )
    dependencies = execution.get("dependencies", [])
    require(
        type(dependencies) in (list, dict)
        and all(
            isinstance(s, str) and re.fullmatch(r"(?:@[a-z0-9-]+/)?[a-z0-9-]+", s)
            for s in dependencies
        ),
        "Invalid dependency inventory",
    )
    if type(dependencies) is dict:
        require(
            all(
                isinstance(value, str) and re.fullmatch(r"\d+\.\d+\.\d+", value)
                for value in dependencies.values()
            ),
            "Dependencies require reviewed exact installed versions",
        )
    if "client" in execution:
        client = fields(
            execution["client"],
            ("type",),
            (
                "adapter",
                "provider-export",
                "script",
                "entrypoint",
                "default-model",
                "expected-model",
                "require-model",
                "prepare",
                "framework",
                "hostname",
                "temporary-tsconfig",
                "probe",
                "probe-arguments",
                "root",
                "tsconfig-variable",
            ),
        )
        require(
            client["type"] in ("node-http", "node-next", "python"),
            "Unsupported shared command client",
        )
        if client["type"] == "node-next":
            require(
                set(client)
                <= {
                    "type",
                    "root",
                    "tsconfig-variable",
                    "prepare",
                    "hostname",
                    "temporary-tsconfig",
                    "adapter",
                    "provider-export",
                    "default-model",
                    "expected-model",
                    "require-model",
                },
                "Unsupported shared Next client option",
            )
            if client.get("root", ".") != ".":
                relative(client["root"])
            require(
                isinstance(client.get("tsconfig-variable", "RUNBOX_TSCONFIG"), str)
                and re.fullmatch(
                    r"[A-Z][A-Z0-9_]*",
                    client.get("tsconfig-variable", "RUNBOX_TSCONFIG"),
                ),
                "Invalid temporary configuration variable",
            )
        if client["type"] == "python":
            require(
                set(client)
                <= {"type", "script", "entrypoint", "probe", "probe-arguments"},
                "Unsupported shared Python client option",
            )
            require(
                not ("entrypoint" in client and "script" in client),
                "Select only one Python entrypoint",
            )
            if "entrypoint" in client:
                require(
                    isinstance(client["entrypoint"], str)
                    and re.fullmatch(
                        r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*",
                        client["entrypoint"],
                    ),
                    "Invalid reviewed Python entrypoint",
                )
            if "probe" in client:
                probe = fields(client["probe"], ("checks",), ("count", "format"))
                require(
                    probe.get("format", "json") in ("json", "status"),
                    "Unsupported verification response format",
                )
                require(
                    probe.get("format") != "status"
                    or probe["checks"] == []
                    and "count" not in probe,
                    "Status-only verification cannot ignore response assertions",
                )
                require(
                    type(probe["checks"]) is list and len(probe["checks"]) <= 32,
                    "Invalid response assertions",
                )
                for check in probe["checks"]:
                    fields(check, ("path", "equals"))
                    require(
                        type(check["path"]) is list
                        and all(isinstance(s, str) for s in check["path"])
                        and type(check["equals"]) in (str, int, bool),
                        "Invalid response assertion",
                    )
                if "count" in probe:
                    require(
                        type(probe["count"]) is list
                        and all(isinstance(s, str) for s in probe["count"]),
                        "Invalid response count path",
                    )
            if "probe-arguments" in client:
                require(
                    type(client["probe-arguments"]) is list
                    and all(isinstance(s, str) for s in client["probe-arguments"]),
                    "Invalid read-only arguments",
                )
                require(
                    "script" in client or "entrypoint" in client,
                    "Read-only arguments require an entrypoint",
                )
        require(
            type(client.get("require-model", False)) is bool,
            "Invalid catalog availability policy",
        )
        if "provider-export" in client:
            require(
                isinstance(client["provider-export"], str)
                and re.fullmatch(
                    r"[A-Za-z_$][A-Za-z0-9_$]*", client["provider-export"]
                ),
                "Invalid application provider export",
            )
        if "adapter" in client:
            relative(client["adapter"])
            require(
                client["adapter"] in integrity["files"],
                "The application adapter must be integrity-pinned",
            )
        if "script" in client:
            relative(client["script"])
            require(
                client["script"] in integrity["files"],
                "The application entrypoint must be integrity-pinned",
            )
        for path in client.get("prepare", []):
            relative(path)
            require(
                path in integrity["files"],
                "Preparation scripts must be integrity-pinned",
            )
        require(client.get("framework", "next") == "next", "Unsupported app framework")
        require(
            client.get("hostname", "127.0.0.1") in ("127.0.0.1", "localhost"),
            "Expected loopback app host",
        )
        require(
            type(client.get("temporary-tsconfig", False)) is bool,
            "Invalid temporary app configuration policy",
        )


def substitutions(root, runtime, archive, workspace=None):
    values = {
        "repo": str(root),
        "release": str(archive.parent),
        "home": str(Path.home()),
        "python-host": sys.executable,
        "pid": str(os.getpid()),
        **{k: v for k, v in runtime.items() if isinstance(v, str)},
    }
    values.update(runtime.get("binaries", {}))
    if "ca-file" in runtime:
        import base64

        pem = Path(runtime["ca-file"]).read_bytes()
        require(
            len(pem) <= 65536
            and b"PRIVATE KEY" not in pem
            and b"BEGIN CERTIFICATE" in pem,
            "Expected only the reviewed public CA",
        )
        values["ca-base64"] = base64.b64encode(pem).decode()
    for kind in ("files", "directories"):
        values.update(
            {key: entry["path"] for key, entry in runtime.get(kind, {}).items()}
        )
    for name in ("node", "python"):
        if name in values:
            values[name + "-real"] = str(Path(values[name]).resolve())
    if "node" in values:
        values["node-root"] = str(Path(values["node"]).resolve().parent.parent)
    if workspace:
        values["workspace"] = str(workspace)
    return values


def expand(value, values):
    def replace(match):
        key = match.group(1)
        require(
            key in values and isinstance(values[key], str),
            "Missing approved runtime substitution",
        )
        return values[key]

    return re.sub(r"\{([a-z][a-z0-9-]*)\}", replace, value)


def compile_policy(execution, values, proxy):
    permissions = execution["permissions"]

    def quote(value):
        return json.dumps(expand(value, values))

    def predicate(rule):
        kind, value = next(iter(rule.items()))
        name = {"file": "literal", "directory": "subpath", "pattern": "regex"}[kind]
        if kind == "pattern":
            require(
                value.startswith(("{repo}/", "{workspace}/")),
                "Regex permissions must be rooted in the selected checkout or workspace",
            )
            escaped = {key: re.escape(item) for key, item in values.items()}
            return "(" + name + " " + json.dumps(expand(value, escaped)) + ")"
        target = expand(value, values)
        require(
            Path(target).is_absolute() and ".." not in Path(target).parts,
            "Permission paths must be canonical absolute paths",
        )
        return "(" + name + " " + json.dumps(target) + ")"

    # Every rule is compiled from a closed data schema; repository Scheme is never evaluated.
    lines = [
        "(version 1)",
        "(allow default)",
        "(deny process-exec)",
        "(allow process-exec "
        + " ".join("(literal " + quote(p) + ")" for p in permissions["execute"])
        + ")",
        '(deny mach-lookup (global-name "com.apple.securityd") (global-name "com.apple.securityd.xpc"))',
        "(deny network*)",
        "(allow network-outbound (remote tcp "
        + json.dumps("localhost:" + proxy.rsplit(":", 1)[1])
        + "))",
    ]
    for endpoint in permissions.get("network", []):
        lines.append(
            "(allow network-outbound (remote tcp " + json.dumps(endpoint) + "))"
        )
    if permissions.get("listen"):
        lines += [
            '(allow network-bind (local ip "localhost:*"))',
            '(allow network-inbound (local tcp "localhost:*"))',
        ]
    for port in permissions.get("listen-ports", []):
        endpoint = json.dumps("localhost:" + str(port))
        lines += [
            "(allow network-bind (local ip " + endpoint + "))",
            "(allow network-inbound (local tcp " + endpoint + "))",
        ]
    lines += [
        "(deny file-read-data file-write* (subpath "
        + quote("{home}")
        + ") (subpath "
        + quote("{repo}")
        + "))"
    ]
    if permissions.get("deny-all-writes"):
        lines.append("(deny file-write*)")
    # Reopen only the exact selected output, never its parent or an arbitrary
    # input that might lie beneath a protected credential directory.
    selected_names = set(execution.get("outputs", {}))
    selected_reads = [
        rule
        for rule in permissions["read"]
        if any(
            rule.get(kind) == "{" + name + "}"
            for name in selected_names
            for kind in ("file", "directory")
        )
    ]
    for action, operation, key in (
        ("allow", "file-read-data", "read"),
        ("deny", "file-read-data", "deny-read"),
        ("allow", "file-write*", "write"),
    ):
        rules = [
            rule
            for rule in permissions.get(key, [])
            if key != "read" or rule not in selected_reads
        ]
        if rules:
            lines.append(
                f"({action} {operation} " + " ".join(predicate(p) for p in rules) + ")"
            )
    if selected_reads:
        lines.append(
            "(allow file-read-data "
            + " ".join(predicate(p) for p in selected_reads)
            + ")"
        )
    lines += [
        '(deny file-read-data (regex #"(^|/)[.]env($|[./])") (regex #"(^|/)([.]netrc|[.]access[.]local[.]toml)$"))'
    ]
    return "\n".join(lines)


def command(root, profile, runtime, archive, mode, arguments, workspace=None):
    execution = profile["execution"]
    sandboxed = execution["sandbox"] == "macos-command"
    require(
        not sandboxed
        or sys.platform == "darwin"
        and Path("/usr/bin/sandbox-exec").is_file(),
        "Required macOS command sandbox is unavailable",
    )
    if mode == "run":
        require(
            arguments and arguments[0] == execution["command"],
            "Only the reviewed command is allowed",
        )
        require(
            arguments_match(execution["arguments"], arguments[1:]),
            "Command arguments are outside the reviewed allowlist",
        )
        for name in execution.get("dependencies", []):
            client = execution.get("client", {})
            app_root = (
                root / client.get("root", ".")
                if client.get("type") == "node-next"
                else root
            )
            manifest = json.loads((app_root / "package.json").read_text())
            installed = json.loads(
                (app_root / "node_modules" / name / "package.json").read_text()
            )
            version = manifest.get("dependencies", {}).get(name)
            selected = execution["dependencies"]
            expected = selected[name] if type(selected) is dict else version
            require(
                isinstance(version, str)
                and isinstance(expected, str)
                and re.fullmatch(r"\d+\.\d+\.\d+", expected)
                and version in (expected, "^" + expected, "~" + expected)
                and installed.get("name") == name
                and installed.get("version") == expected,
                "Installed dependencies differ from the reviewed manifest",
            )
    else:
        require("probe-argv" in execution, "No read-only probe is configured")
    values = substitutions(root, runtime, archive, workspace)
    from .inputs import select

    selected_inputs = select(root, execution, arguments if mode == "run" else [])
    require(
        not set(selected_inputs) & set(values),
        "Input and runtime substitutions conflict",
    )
    for name in selected_inputs:
        require(
            "{" + name + "}" not in json.dumps(profile["environment"]),
            "Selected payloads cannot enter the environment",
        )
    values.update(selected_inputs)
    from .outputs import select as select_outputs

    selected_outputs = select_outputs(
        root, execution, arguments if mode == "run" else [], selected_inputs
    )
    require(
        not set(selected_outputs) & set(values),
        "Output and runtime substitutions conflict",
    )
    for name in selected_outputs:
        require(
            "{" + name + "}" not in json.dumps(profile["environment"]),
            "Selected outputs cannot enter the environment",
        )
    values.update(selected_outputs)
    sandbox = (
        [
            "/usr/bin/sandbox-exec",
            "-p",
            compile_policy(execution, values, profile["session"]["proxy"]),
        ]
        if sandboxed
        else []
    )
    import base64

    environment = {
        key: expand(value, values) for key, value in profile["environment"].items()
    }
    selected_execution = execution
    if "probe-arguments" in execution.get("client", {}):
        selected_execution = {
            **execution,
            "client": {
                **execution["client"],
                "probe-arguments": [
                    expand(s, values) for s in execution["client"]["probe-arguments"]
                ],
            },
        }
    payload = {
        "root": str(root),
        "profile": {
            **profile,
            "environment": environment,
            "execution": selected_execution,
        },
        "runtime": runtime,
        "mode": mode,
        "pid": os.getpid(),
        "release": str(archive.parent),
        "home": str(workspace / "home") if workspace else str(Path.home()),
    }
    environment.update(
        {
            "NO_PROXY": "",
            "no_proxy": "",
            "SSL_CERT_FILE": runtime["ca-file"],
            "REQUESTS_CA_BUNDLE": runtime["ca-file"],
            "NODE_EXTRA_CA_CERTS": runtime["ca-file"],
            "NODE_USE_ENV_PROXY": "1",
            "NEXT_TELEMETRY_DISABLED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "HOME": payload["home"],
            "PATH": ":".join(
                [
                    *runtime.get("path", []),
                    "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                ]
            ),
            "RUNBOX_POLICY": base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode(),
        }
    )
    if "node" in runtime:
        environment["PATH"] = (
            str(Path(runtime["node"]).parent) + ":" + environment["PATH"]
        )
    imports = (
        [root / name for name in preloads]
        if (preloads := execution.get("preloads", []))
        else []
    )
    if execution.get("client", {}).get("type") == "node-http" or (
        execution.get("client", {}).get("type") == "node-next" and "http" in profile
    ):
        imports.insert(0, archive.parent / "resources/node-preload.mjs")
    if imports:
        environment["NODE_OPTIONS"] = "--use-env-proxy " + " ".join(
            "--import=" + path.as_uri() for path in imports
        )
    vector = execution["probe-argv"] if mode == "probe" else execution["argv"]
    argv = [expand(s, values) for s in vector]
    if mode == "run":
        argv += arguments[1:]
        if "handoff" in execution:
            argv = [
                runtime["python"],
                "-I",
                "-S",
                "-B",
                str(archive),
                "--handoff",
                *argv,
            ]
    child = [
        "/usr/bin/env",
        *(key + "=" + value for key, value in environment.items()),
        *sandbox,
        *argv,
    ]
    return child, workspace if execution.get("cwd", "repo") == "workspace" else root
