"""Compatibility types and retirement notice for the unsafe pre-v1 writer."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class PatchResult:
    file_path: str
    success: bool
    backup_path: str | None
    scripts_patched: int
    csp_injected: bool
    diff_summary: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Patcher:
    """The direct-write API was retired; use proposals and validation."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError(
            "Legacy direct writes were retired in v1. Use propose, validate-proposal "
            "and apply-proposal --approve with reviewed artifact hashes."
        )
