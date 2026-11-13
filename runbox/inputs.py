"""Select explicit repository-local payloads before creating a provider session.

The argument vector includes the public command, for example ``hf upload``.
Input contents are user payload, not executable source. This module never reads
payload bytes or creates files. A nonmatching command gets a /dev/null sentinel.
"""

import os
import re
from pathlib import Path

from .config import fields, relative, require, word


def validate(inputs):
    require(type(inputs) is dict and len(inputs) <= 16, "Invalid input inventory")
    for name, selected in inputs.items():
        word(name)
        require(
            not re.fullmatch(r"argument-[0-9]+", name),
            "Reserved service argument substitution",
        )
        require(
            name
            not in {
                "repo",
                "home",
                "workspace",
                "release",
                "python",
                "python-root",
                "python-real",
                "node",
                "node-root",
                "node-real",
                "infisical",
                "ca-file",
                "ca-fingerprint",
                "ca-base64",
                "pid",
                "python-host",
            },
            "Reserved input substitution",
        )
        fields(
            selected,
            ("argument", "when-prefix", "root", "exclude", "allow"),
            ("path-template",),
        )
        if "path-template" in selected:
            template = selected["path-template"]
            require(
                isinstance(template, str) and template.count("{argument}") == 1,
                "Invalid named payload path template",
            )
            relative(template.replace("{argument}", "selected"))
            require(
                selected["root"] == "repo",
                "Named payloads must remain repository-local",
            )
        require(
            type(selected["argument"]) is int and 1 <= selected["argument"] <= 64,
            "Invalid payload argument index",
        )
        prefix = selected["when-prefix"]
        require(
            type(prefix) is list
            and prefix
            and len(prefix) <= 16
            and all(
                isinstance(s, str) and s and not any(c in s for c in "\0\n")
                for s in prefix
            ),
            "Invalid payload command prefix",
        )
        require(
            selected["root"] in ("repo", "any-file"), "Unsupported explicit input scope"
        )
        require(
            type(selected["exclude"]) is list and type(selected["allow"]) is list,
            "Invalid payload scope",
        )
        for excluded in selected["exclude"]:
            relative(excluded)
            require(
                "/" not in excluded, "Excluded payload roots must be top-level names"
            )
        for allowed in selected["allow"]:
            relative(allowed)
            require(
                len(Path(allowed).parts) >= 2
                and Path(allowed).parts[0] in selected["exclude"],
                "Narrow payload exceptions must remain under an excluded root",
            )


def select(root, execution, arguments):
    inputs = execution.get("inputs", {})
    validate(inputs)
    root = Path(root)
    require(
        root.is_absolute() and root.resolve() == root,
        "Expected a canonical payload checkout",
    )
    selected = {}
    for name, rule in inputs.items():
        selected[name] = "/dev/null"
        prefix = rule["when-prefix"]
        if list(arguments[: len(prefix)]) != prefix:
            continue
        require(len(arguments) > rule["argument"], "Missing explicit payload argument")
        raw = arguments[rule["argument"]]
        require(
            isinstance(raw, str) and raw and not raw.startswith("-"),
            "Invalid explicit payload argument",
        )
        if "path-template" in rule:
            require(
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", raw),
                "Expected one payload name, without path components",
            )
            raw = rule["path-template"].replace("{argument}", raw)
        path = Path(raw)
        path = path if path.is_absolute() else root / path
        require(
            ".." not in path.parts and path.resolve() == path,
            "Payload paths cannot traverse or follow symlinks",
        )
        require(
            path.exists() and (path.is_file() or path.is_dir()),
            "Payload is unavailable",
        )
        if rule["root"] == "any-file":
            require(
                path.is_file() and path.stat().st_uid == os.getuid(),
                "External inputs must select owned regular files",
            )
            require(
                not any(part in rule["exclude"] for part in path.parts),
                "Private paths are not selected inputs",
            )
            selected[name] = str(path)
            continue
        require(
            path.is_relative_to(root) and path != root,
            "Payload must be inside the selected checkout",
        )
        relative_path = path.relative_to(root)
        if relative_path.parts[0] in rule["exclude"]:
            require(
                any(
                    path == root / allowed or path.is_relative_to(root / allowed)
                    for allowed in rule["allow"]
                ),
                "Private repository files are not payloads",
            )
        if path.is_dir():
            # Reject nested links so a directory cannot expand its selected scope.
            for child in path.rglob("*"):
                require(
                    not child.is_symlink(),
                    "Payload directories cannot contain symlinks",
                )
        selected[name] = str(path)
    return selected
