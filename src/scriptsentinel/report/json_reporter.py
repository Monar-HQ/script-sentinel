"""JSON reporter for ScriptSentinel audit reports."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import AuditReport


def render_json(report: AuditReport) -> str:
    """Render the full audit report as deterministic, pretty-printed JSON."""
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False, sort_keys=True)


def write_json(report: AuditReport, path: str | Path) -> None:
    """Write the rendered JSON audit report to ``path``."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_json(report) + "\n", encoding="utf-8")
