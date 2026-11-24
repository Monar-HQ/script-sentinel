"""Validate a proposal in a temporary copy without running project commands."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup

from . import proposals
from .integrity import matches_sri
from .local_audit import resolve_local_script


def isolated(root: Path, proposal: dict[str, Any], baseline: Path) -> dict[str, Any]:
    root = root.resolve()
    target = proposals.validate(root, proposal, baseline)
    before = BeautifulSoup(target.read_text(encoding="utf-8"), "html.parser")
    after = BeautifulSoup(proposal["replacement"], "html.parser")
    before_scripts = before.find_all("script")
    after_scripts = after.find_all("script")
    if len(before_scripts) != len(after_scripts):
        raise ValueError("Script inventory changed unexpectedly")
    with tempfile.TemporaryDirectory(prefix="scriptsentinel-validation-") as temporary:
        staged = Path(temporary)
        candidate = proposals.confined(staged, target.relative_to(root).as_posix())
        candidate.parent.mkdir(parents=True, exist_ok=True)
        candidate.write_text(proposal["replacement"], encoding="utf-8")
        for relative in proposal["resources"]:
            source = proposals.confined(root, relative)
            destination = proposals.confined(staged, relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        for old, new in zip(before_scripts, after_scripts, strict=True):
            if old.get("src") != new.get("src") or old.get_text() != new.get_text():
                raise ValueError("Script behavior or source reference changed")
            if new.get("src") and not old.get("integrity"):
                source = resolve_local_script(staged, candidate, str(new["src"]))
                if not matches_sri(source.read_bytes(), str(new["integrity"])):
                    raise ValueError("Staged SRI verification failed")
    return {
        "passed": True,
        "checks": [
            "fresh baseline",
            "unchanged script references",
            "unchanged inline code",
            "staged SRI match",
        ],
        "application_tests": "not executed; separate functional review required",
        "proposal_sha256": proposals.digest(json.dumps(proposal, sort_keys=True).encode()),
    }


def apply_reviewed(
    root: Path, proposal: dict[str, Any], baseline: Path, receipt_path: Path, approved: bool
) -> Path:
    if not approved:
        raise ValueError("Explicit approval is required after application review")
    isolated(root, proposal, baseline)
    backup: Path | None = None
    receipt: dict[str, Any] | None = None
    with receipt_path.open("x", encoding="utf-8") as stream:
        try:
            backup = proposals.apply(root, proposal, baseline, approved=True)
            receipt = {
                "file": proposal["file"],
                "backup": backup.relative_to(root.resolve()).as_posix(),
                "before_sha256": proposal["before_sha256"],
                "after_sha256": proposal["after_sha256"],
            }
            json.dump(receipt, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        except Exception:
            if backup is not None and receipt is not None:
                rollback(root, receipt, approved=True)
            raise
    if backup is None:
        raise RuntimeError("Application produced no recovery copy")
    return backup


def rollback(root: Path, receipt: dict[str, Any], approved: bool) -> None:
    if not approved:
        raise ValueError("Rollback requires explicit approval")
    target = proposals.confined(root.resolve(), receipt["file"])
    backup = proposals.confined(root.resolve(), receipt["backup"])
    if proposals.digest(target.read_bytes()) != receipt["after_sha256"]:
        raise ValueError("Target changed since application; refusing to overwrite later work")
    original = backup.read_bytes()
    if proposals.digest(original) != receipt["before_sha256"]:
        raise ValueError("Recovery copy does not match receipt")
    descriptor, temporary = tempfile.mkstemp(dir=target.parent, prefix=".scriptsentinel-restore-")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(original)
        os.chmod(temporary, target.stat().st_mode)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
