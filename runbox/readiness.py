"""Mutable administrative readiness is a refusal gate, never an access grant."""

import json
import re
from pathlib import Path

from .config import fields, require
from .sandbox import expand, substitutions
from .trust import regular


def validate(value):
    fields(value, ("file", "field", "equals"))
    require(
        isinstance(value["file"], str)
        and re.fullmatch(r"\{[a-z][a-z0-9-]*\}/[^\n\0]+", value["file"]),
        "Readiness must use a named protected runtime directory",
    )
    require(
        isinstance(value["field"], str)
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", value["field"]),
        "Invalid readiness field",
    )
    require(
        type(value["equals"]) in (str, int, bool) and len(str(value["equals"])) <= 128,
        "Invalid readiness condition",
    )


def ready(root, profile, runtime, archive):
    value = profile["execution"].get("readiness")
    if not value:
        return True
    validate(value)
    name = value["file"][1 : value["file"].index("}")]
    entry = runtime.get("directories", {}).get(name)
    require(
        entry and entry.get("private") is True,
        "Readiness directory must be explicitly owner-only",
    )
    base = Path(entry["path"])
    path = Path(expand(value["file"], substitutions(root, runtime, archive)))
    require(
        path.is_relative_to(base) and path != base,
        "Readiness escaped its reviewed state directory",
    )
    regular(path, private=True)
    require(path.stat().st_size <= 65536, "Readiness metadata exceeds its bound")

    def mapping(pairs):
        result = {}
        for key, item in pairs:
            require(key not in result, "Duplicate readiness metadata field")
            result[key] = item
        return result

    try:
        record = json.loads(path.read_text(), object_pairs_hook=mapping)
    except (ValueError, UnicodeError):
        raise ValueError(
            "Invalid readiness metadata; private details withheld"
        ) from None
    require(
        type(record) is dict and value["field"] in record,
        "Readiness condition is missing",
    )
    actual = record[value["field"]]
    return type(actual) is type(value["equals"]) and actual == value["equals"]
