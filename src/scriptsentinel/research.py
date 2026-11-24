"""Versioned research metadata validation; packs contain data, never executable code."""

from __future__ import annotations

import json
from datetime import date
from importlib.resources import files
from pathlib import Path
from typing import Any


def load_pack(path: Path | None = None) -> dict[str, Any]:
    raw = (
        path.read_text(encoding="utf-8")
        if path
        else files("scriptsentinel")
        .joinpath("knowledge", "optimjack.json")
        .read_text(encoding="utf-8")
    )
    if len(raw) > 1_000_000:
        raise ValueError("Research pack exceeds 1 MB")
    pack = json.loads(raw)
    if not isinstance(pack, dict) or pack.get("schema") != 1:
        raise ValueError("Unsupported research schema")
    for key in ("id", "revision", "license", "applicability", "verified_on"):
        if not isinstance(pack.get(key), str) or not pack[key].strip():
            raise ValueError(f"Research pack needs {key}")
    date.fromisoformat(pack["verified_on"])
    if not isinstance(pack.get("sources"), list) or not pack["sources"]:
        raise ValueError("Research pack needs attributed sources")
    for source in pack["sources"]:
        if (
            not isinstance(source, dict)
            or not str(source.get("url", "")).startswith("https://")
            or not source.get("supports")
            or not source.get("status")
        ):
            raise ValueError("Invalid source provenance")
    return pack
