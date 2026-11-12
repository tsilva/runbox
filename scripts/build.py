#!/usr/bin/env python3
"""Build a deterministic standalone archive using the locked PyYAML dependency."""

import hashlib
import json
import sys
import zipfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def build(output):
    output.mkdir(parents=True, exist_ok=True)
    archive = output / "runbox.pyz"
    files = {
        "__main__.py": b"from runbox.__main__ import entry\nraise SystemExit(entry())\n"
    }
    files["licenses/Runbox-LICENSE"] = (ROOT / "LICENSE").read_bytes()
    for package in (ROOT / "runbox", Path(yaml.__file__).parent):
        for path in sorted(package.rglob("*.py")):
            files[str(Path(package.name) / path.relative_to(package))] = (
                path.read_bytes()
            )
    # PyYAML's pure Python SafeLoader is sufficient; no platform-specific extension is bundled.
    import importlib.metadata

    distribution = importlib.metadata.distribution("PyYAML")
    license_path = next(p for p in distribution.files if p.name == "LICENSE")
    files["licenses/PyYAML-LICENSE"] = distribution.locate_file(
        license_path
    ).read_bytes()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            bundle.writestr(info, data)
    sandbox = output / "staging.sb"
    sandbox.write_bytes((ROOT / "runbox/staging.sb").read_bytes())
    manifest = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (archive, sandbox)
    }
    (output / "checksums.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Built runbox.pyz, staging.sb and checksums.json")


if __name__ == "__main__":
    build(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "dist")
