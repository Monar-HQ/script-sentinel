"""Persistent, local change evidence against an explicitly reviewed snapshot."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .env_detector import detect_environment
from .local_audit import resolve_local_script
from .proposals import confined, read_baseline
from .runtime import Workspace


def snapshot(root: Path) -> dict[str, str]:
    root = root.resolve(strict=True)
    env = detect_environment(str(root))
    if env.metadata.get("unsupported_local_base_href") or env.metadata.get("script_limit") or any(str(key).startswith("size_limit_") for key in env.metadata):
        raise ValueError("Monitoring inventory is incomplete: unsupported base href or discovery limit")
    paths = {Path(item) for item in env.html_files}
    for script in env.discovered_scripts:
        if script.src:
            try:
                paths.add(resolve_local_script(root, Path(script.source_file), script.src))
            except ValueError:
                continue  # remote scripts remain unavailable, never fabricated
    result = {}
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix()
        if path.is_file():
            if path.stat().st_size > 5_000_000:
                raise ValueError("Monitored resource exceeds 5 MB")
            result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            result[relative] = "unavailable"
    return result


def pin(workspace: Workspace, reviewer: str, provenance: str) -> dict[str, Any]:
    if not reviewer.strip() or not provenance.strip():
        raise ValueError("Reviewer and artifact provenance are required")
    observed = snapshot(workspace.root)
    if not observed or "unavailable" in observed.values():
        raise ValueError("Cannot approve an empty inventory or unavailable local artifacts")
    data: dict[str, Any] = {
        "schema": 1,
        "reviewer": reviewer,
        "provenance": provenance,
        "files": observed,
    }
    destination = workspace.state_file("baseline.json")
    with destination.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2)
    workspace.record("baseline-reviewed", {"reviewer": reviewer, "file_count": len(data["files"])})
    return data


def compare(workspace: Workspace) -> dict[str, Any]:
    raw = read_baseline(workspace.state_file("baseline.json"))
    if (
        not isinstance(raw, dict)
        or raw.get("schema") != 1
        or not isinstance(raw.get("files"), dict)
    ):
        raise ValueError("Invalid monitoring baseline")
    expected = raw["files"]
    for relative in expected:
        confined(workspace.root, relative)
    observed = snapshot(workspace.root)
    changes = [
        {
            "file": path,
            "kind": "added"
            if path not in expected
            else "removed"
            if path not in observed
            else "changed",
            "expected": expected.get(path),
            "observed": observed.get(path),
        }
        for path in sorted(set(expected) | set(observed))
        if expected.get(path) != observed.get(path)
    ]
    result = {
        "schema": 1,
        "changes": changes,
        "changed": bool(changes),
        "coverage": "local HTML and referenced local scripts; remote scripts require scoped HTTP monitoring",
    }
    workspace.record("monitor-drift" if changes else "monitor-clean", result)
    return result
