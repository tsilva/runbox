"""Validate explicit output targets without creating files or opening payloads."""

import os
import stat
import re
from pathlib import Path

from .config import fields, relative, require, word


RESERVED = {
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
}


def validate(outputs):
    require(type(outputs) is dict and len(outputs) <= 16, "Invalid output inventory")
    names = set()
    for name, rule in outputs.items():
        word(name)
        require(
            not re.fullmatch(r"argument-[0-9]+", name),
            "Reserved service argument substitution",
        )
        require(
            name not in RESERVED and name + "-parent" not in RESERVED,
            "Reserved output substitution",
        )
        require(
            not names.intersection((name, name + "-parent")),
            "Conflicting output substitutions",
        )
        names.update((name, name + "-parent"))
        fields(
            rule,
            ("argument", "when-prefix", "kind", "separate-from", "exclude"),
            ("within", "relative-to"),
        )
        require(
            type(rule["argument"]) is int and 1 <= rule["argument"] <= 64,
            "Invalid output argument index",
        )
        prefix = rule["when-prefix"]
        require(
            type(prefix) is list
            and 0 < len(prefix) <= 16
            and all(
                isinstance(s, str) and s and not any(c in s for c in "\0\n")
                for s in prefix
            ),
            "Invalid output command prefix",
        )
        require(
            rule["kind"] in ("new-file", "empty-directory", "existing-directory"),
            "Unsupported output target kind",
        )
        if "within" in rule:
            relative(rule["within"])
        require(
            rule.get("relative-to", "absolute") in ("absolute", "repo"),
            "Invalid output path base",
        )
        require(
            rule["kind"] != "existing-directory" or "within" in rule,
            "Existing outputs require a narrowed repository subtree",
        )
        separate = rule["separate-from"]
        require(
            type(separate) is list
            and len(separate) <= 16
            and all(isinstance(s, str) for s in separate),
            "Invalid output separation inventory",
        )
        for selected in separate:
            word(selected)
        excluded = rule["exclude"]
        require(
            type(excluded) is list and len(excluded) <= 32,
            "Invalid output exclusion inventory",
        )
        for path in excluded:
            require(
                isinstance(path, str)
                and path
                and not any(c in path for c in "\0\n")
                and Path(path).is_absolute()
                and ".." not in Path(path).parts,
                "Expected an absolute excluded output path",
            )


def select(root, execution, arguments, inputs=None):
    outputs = execution.get("outputs", {})
    validate(outputs)
    root = Path(root)
    require(
        root.is_absolute() and root.resolve() == root,
        "Expected a canonical output checkout",
    )
    inputs = inputs or {}
    selected = {}
    for name, rule in outputs.items():
        selected[name] = selected[name + "-parent"] = "/dev/null"
        prefix = rule["when-prefix"]
        if list(arguments[: len(prefix)]) != prefix:
            continue
        require(len(arguments) > rule["argument"], "Missing explicit output argument")
        raw = arguments[rule["argument"]]
        require(
            isinstance(raw, str) and raw and not any(c in raw for c in "\0\n"),
            "Invalid explicit output argument",
        )
        path = Path(raw)
        if not path.is_absolute() and rule.get("relative-to") == "repo":
            path = root / path
        require(
            path.is_absolute() and ".." not in path.parts and path.resolve() == path,
            "Output paths must be explicit and canonical without symlinks",
        )
        if rule["kind"] == "new-file":
            require(
                not path.exists() and not path.is_symlink(), "Output file must be new"
            )
            directory = path.parent
        else:
            directory = path
        require(
            directory.is_dir() and directory.resolve() == directory,
            "Output directory must already exist without symlinks",
        )
        info = directory.stat()
        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.getuid()
            and not info.st_mode & 0o077,
            "Output directory must be owner-only",
        )
        if rule["kind"] != "existing-directory":
            require(not any(directory.iterdir()), "Output directory must be empty")
        if "within" in rule:
            allowed = root / rule["within"]
            require(
                allowed.resolve() == allowed
                and directory != allowed
                and directory.is_relative_to(allowed),
                "Output directory must remain beneath its narrowed repository subtree",
            )
        for excluded in rule["exclude"]:
            forbidden = Path(excluded)
            require(
                forbidden.resolve() == forbidden,
                "Excluded output path is not canonical",
            )
            require(
                directory != forbidden and not directory.is_relative_to(forbidden),
                "Output directory cannot use protected state",
            )
        for source in rule["separate-from"]:
            require(
                source in inputs and inputs[source] != "/dev/null",
                "Output separation requires the selected input",
            )
            require(
                directory != Path(inputs[source]).parent,
                "Output directory must be separate from input directories",
            )
        selected[name] = str(path)
        selected[name + "-parent"] = str(directory)
    return selected
