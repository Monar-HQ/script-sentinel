"""Inspect built package contents and write unsigned artifact checksums."""

import hashlib
import json
import tarfile
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
output = root / "dist" / "v1"
wheel = output / "scriptsentinel-1.0.0rc1-py3-none-any.whl"
source = output / "scriptsentinel-1.0.0rc1.tar.gz"
with zipfile.ZipFile(wheel) as archive:
    names = archive.namelist()
    for item in (
        "web/index.html",
        "web/app.js",
        "web/style.css",
        "web/mark.svg",
        "demo/index.html",
        "demo/app.js",
        "knowledge/optimjack.json",
        "script_types.py",
        "py.typed",
    ):
        assert "scriptsentinel/" + item in names, item
    assert not any(
        ".scriptsentinel/" in name or name.endswith((".sqlite3", ".bak", ".env")) for name in names
    )
with tarfile.open(source) as archive:
    names = archive.getnames()
    assert any(name.endswith("/CREDITS.md") for name in names)
    assert any(name.endswith("/assets/brandkit/README.md") for name in names)
    assert any(name.endswith("/assets/brandkit/identity-system.svg") for name in names)
    assert any(name.endswith("/assets/workflow-loop.gif") for name in names)
    assert any(name.endswith("/packaging/visuals/LICENSE-HYPERFRAMES.txt") for name in names)
    assert not any("/.hyperframes/" in name or "/packaging/visuals/renders/" in name for name in names)
    assert not any("/.scriptsentinel/" in name or name.startswith("scriptsentinel-1.0.0rc1/report/") for name in names)
records = []
for path in (
    wheel,
    source,
    output / "scriptsentinel.exe",
    output / "sbom.cdx.json",
    output / "dependency-audit.json",
):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    records.append({"file": path.name, "bytes": path.stat().st_size, "sha256": digest.hexdigest()})
with (output / "artifacts.json").open("w", encoding="utf-8") as stream:
    json.dump({"version": "1.0.0rc1", "signed": False, "artifacts": records}, stream, indent=2)
with (output / "SHA256SUMS.txt").open("w", encoding="utf-8") as stream:
    stream.write("".join(item["sha256"] + "  " + item["file"] + "\n" for item in records))
print("Package contents and unsigned artifact checksums verified.")
