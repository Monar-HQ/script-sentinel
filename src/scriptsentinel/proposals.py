"""Reviewable offline SRI proposals with optimistic concurrency and rollback.

Validation covers structure and pinned bytes, not application compatibility.
No project commands, scripts, or model output are executed.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup

from .integrity import compute_hashes
from .local_audit import resolve_local_script


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def confined(root: Path, relative: str) -> Path:
    entry = Path(relative)
    if not relative or entry.anchor or entry.drive or ".." in entry.parts:
        raise ValueError("Expected a workspace-relative path")
    result = (root / relative).resolve()
    if not result.is_relative_to(root.resolve()):
        raise ValueError("Path escapes workspace")
    return result


def read_baseline(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise ValueError("Unsupported baseline schema")
    if not all(
        isinstance(data.get(k), str) and data[k].strip() for k in ("reviewer", "provenance")
    ):
        raise ValueError("Baseline needs reviewer and independently established provenance")
    files = data.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("Baseline files must be a nonempty path to SHA-256 mapping")
    if not all(
        isinstance(k, str) and isinstance(v, str) and re.fullmatch(r"[a-f0-9]{64}", v)
        for k, v in files.items()
    ):
        raise ValueError("Invalid baseline digest")
    return data


def propose(root: Path, html: str, baseline_path: Path) -> dict[str, Any]:
    root = root.resolve()
    target = confined(root, html)
    baseline = read_baseline(baseline_path)
    original = target.read_bytes()
    soup = BeautifulSoup(original.decode("utf-8"), "html.parser")
    if soup.find("base", href=True):
        raise ValueError(
            "HTML base href is unsupported for local SRI proposals; resolve it in an isolated application review"
        )
    resources: dict[str, str] = {}
    for tag in soup.find_all("script", src=True):
        if tag.get("integrity"):
            continue
        src = str(tag["src"])
        script = resolve_local_script(root, target, src)
        relative = script.relative_to(root).as_posix()
        expected = baseline["files"].get(relative)
        content = script.read_bytes()
        if expected is None or digest(content) != expected:
            raise ValueError(f"Script lacks matching reviewed baseline: {relative}")
        resources[relative] = expected
        tag["integrity"] = compute_hashes(content).sri_sha384
        tag["crossorigin"] = "anonymous"
    if not resources:
        raise ValueError("No eligible scripts to patch")
    replacement = str(soup)
    return {
        "schema": 1,
        "file": html,
        "before_sha256": digest(original),
        "after_sha256": digest(replacement.encode("utf-8")),
        "replacement": replacement,
        "resources": resources,
        "baseline_sha256": digest(baseline_path.read_bytes()),
        "diff": "".join(
            difflib.unified_diff(
                original.decode("utf-8").splitlines(True),
                replacement.splitlines(True),
                fromfile=html,
                tofile=html,
            )
        ),
        "validation_scope": "Offline structural/SRI checks only; compatibility testing required",
    }


def validate(root: Path, proposal: dict[str, Any], baseline: Path) -> Path:
    """Recompute the deterministic patch; reject altered or stale proposals."""
    if (
        not isinstance(proposal, dict)
        or proposal.get("schema") != 1
        or not isinstance(proposal.get("file"), str)
    ):
        raise ValueError("Unsupported proposal")
    expected = propose(root, proposal["file"], baseline)
    if proposal != expected:
        raise ValueError("Proposal changed, resources drifted, or baseline is stale")
    return confined(root.resolve(), proposal["file"])


def apply(root: Path, proposal: dict[str, Any], baseline: Path, approved: bool = False) -> Path:
    if not approved:
        raise ValueError("Explicit approval is required after diff and compatibility review")
    target = validate(root, proposal, baseline)
    original = target.read_bytes()
    backup = target.with_name(target.name + ".scriptsentinel-" + digest(original)[:16] + ".bak")
    # Exclusive creation preserves earlier recovery copies, including against symlinks.
    with backup.open("xb") as stream:
        stream.write(original)
    descriptor, temporary = tempfile.mkstemp(prefix=".scriptsentinel-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(proposal["replacement"].encode("utf-8"))
        os.chmod(temporary, stat.S_IMODE(target.stat().st_mode))
        # Recheck immediately before atomic replacement.
        validate(root, proposal, baseline)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return backup
