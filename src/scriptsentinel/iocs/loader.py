"""IOC feed loading and validation.

Every IOC record must carry a ``source`` and a ``first_seen`` date; records
without both are rejected rather than silently accepted.  This keeps the feed
auditable: a reader can always trace where an indicator came from and when it
was first observed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VALID_KINDS = frozenset({"domain", "sha256"})


class IOCError(ValueError):
    """Raised when a feed or record fails validation."""


@dataclass(frozen=True, slots=True)
class IOCRecord:
    """A single indicator of compromise."""

    kind: str
    value: str
    source: str
    first_seen: str
    severity: str = "high"
    note: str = ""

    def matches(self, candidate: str) -> bool:
        """Case-insensitive exact match (no substring matching)."""
        return candidate.strip().lower() == self.value


@dataclass(frozen=True, slots=True)
class IOCFeed:
    """A versioned collection of IOC records."""

    feed_id: str
    version: str
    as_of: str
    records: tuple[IOCRecord, ...]
    path: str = ""

    def domains(self) -> frozenset[str]:
        return frozenset(r.value for r in self.records if r.kind == "domain")

    def hashes(self) -> frozenset[str]:
        return frozenset(r.value for r in self.records if r.kind == "sha256")

    def match_domain(self, host: str) -> IOCRecord | None:
        candidate = host.strip().lower()
        for record in self.records:
            if record.kind == "domain" and record.matches(candidate):
                return record
        return None

    def match_hash(self, sha256: str) -> IOCRecord | None:
        candidate = sha256.strip().lower()
        for record in self.records:
            if record.kind == "sha256" and record.matches(candidate):
                return record
        return None

    def digest(self) -> str:
        """Stable digest of the feed contents (used for cache keys)."""
        payload = json.dumps(
            {
                "feed_id": self.feed_id,
                "version": self.version,
                "records": [
                    {
                        "kind": r.kind,
                        "value": r.value,
                        "source": r.source,
                        "first_seen": r.first_seen,
                    }
                    for r in self.records
                ],
            },
            sort_keys=True,
        )
        import hashlib

        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _require_str(container: dict[str, Any], key: str, where: str) -> str:
    value = container.get(key)
    if not isinstance(value, str) or not value.strip():
        raise IOCError(f"{where}: missing or empty '{key}'")
    return value.strip()


def validate_record(raw: dict[str, Any], where: str) -> IOCRecord:
    """Validate one raw IOC record.

    ``source`` and ``first_seen`` are mandatory: an IOC without provenance is
    not admissible.
    """
    if not isinstance(raw, dict):
        raise IOCError(f"{where}: record is not an object")

    kind = _require_str(raw, "kind", where).lower()
    if kind not in VALID_KINDS:
        raise IOCError(f"{where}: unsupported kind '{kind}' (expected domain or sha256)")

    value = _require_str(raw, "value", where)
    source = _require_str(raw, "source", where)
    first_seen = _require_str(raw, "first_seen", where)

    if kind == "sha256":
        value = value.lower()
        if not SHA256_RE.match(value):
            raise IOCError(f"{where}: sha256 value is not 64 lowercase hex chars")
    else:
        if "://" in value or "/" in value:
            raise IOCError(f"{where}: domain value must be a bare hostname, got '{value}'")
        value = value.lower()

    severity = raw.get("severity", "high")
    if not isinstance(severity, str) or severity.strip() not in {
        "critical",
        "high",
        "medium",
        "low",
    }:
        raise IOCError(f"{where}: severity must be critical/high/medium/low")

    note = raw.get("note", "")
    if not isinstance(note, str):
        raise IOCError(f"{where}: note must be a string")

    return IOCRecord(
        kind=kind,
        value=value,
        source=source,
        first_seen=first_seen,
        severity=severity.strip(),
        note=note.strip(),
    )


def load_feed(path: str | Path) -> IOCFeed:
    """Load and validate an IOC feed JSON file."""
    p = Path(path)
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise IOCError(f"feed not found: {p}") from exc
    except json.JSONDecodeError as exc:
        raise IOCError(f"feed is not valid JSON: {p}: {exc}") from exc

    if not isinstance(raw, dict):
        raise IOCError(f"feed root must be an object: {p}")

    feed_id = _require_str(raw, "feed_id", str(p))
    version = _require_str(raw, "version", str(p))
    as_of = _require_str(raw, "as_of", str(p))

    records_raw = raw.get("records")
    if not isinstance(records_raw, list) or not records_raw:
        raise IOCError(f"{p}: 'records' must be a non-empty list")

    records: list[IOCRecord] = []
    for i, item in enumerate(records_raw):
        records.append(validate_record(item, f"{p}:records[{i}]"))

    return IOCFeed(
        feed_id=feed_id, version=version, as_of=as_of, records=tuple(records), path=str(p)
    )


def load_default_feed() -> IOCFeed:
    """Load the packaged OPTIMJACK feed (the tool's first IOC set)."""
    resource = resources.files("scriptsentinel.iocs.feeds").joinpath("optimjack_2026-11-23.json")
    with resources.as_file(resource) as path:
        return load_feed(path)


def merge_feeds(feeds: Iterable[IOCFeed]) -> IOCFeed:
    """Merge feeds into one, keeping the earliest provenance per value."""
    records: dict[tuple[str, str], IOCRecord] = {}
    feed_ids: list[str] = []
    for feed in feeds:
        feed_ids.append(feed.feed_id)
        for record in feed.records:
            records.setdefault((record.kind, record.value), record)
    return IOCFeed(
        feed_id="+".join(feed_ids) or "empty",
        version="merged",
        as_of=max(f.as_of for f in feeds) if feed_ids else "",
        records=tuple(records.values()),
    )
