"""Unit tests for IOC feed loading and validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scriptsentinel.iocs.loader import (
    IOCError,
    IOCFeed,
    IOCRecord,
    load_default_feed,
    load_feed,
    merge_feeds,
    validate_record,
)

TRACKJS = "f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40"
SECOND = "814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f"


def _write(tmp_path: Path, payload: dict[str, object]) -> Path:
    path = tmp_path / "feed.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _feed(records: list[dict[str, object]]) -> dict[str, object]:
    return {"feed_id": "test", "version": "1.0", "as_of": "2026-11-23", "records": records}


def test_default_feed_ships_optimjack_iocs() -> None:
    feed = load_default_feed()
    assert feed.feed_id == "optimjack-2026-11-23"
    assert len(feed.domains()) == 8
    assert feed.hashes() == frozenset({TRACKJS, SECOND})
    assert "1688360.cc" in feed.domains()
    assert "pay-relay.wordpressadmin001.workers.dev" in feed.domains()


def test_every_record_has_source_and_first_seen() -> None:
    feed = load_default_feed()
    for record in feed.records:
        assert record.source
        assert record.first_seen


def test_match_domain_is_case_insensitive_and_exact() -> None:
    feed = load_default_feed()
    assert feed.match_domain("1688360.CC") is not None
    assert feed.match_domain("sub.1688360.cc") is None
    assert feed.match_domain("1688360.cc.evil") is None


def test_match_hash() -> None:
    feed = load_default_feed()
    assert feed.match_hash(TRACKJS) is not None
    assert feed.match_hash(SECOND) is not None
    assert feed.match_hash("0" * 64) is None


def test_missing_source_is_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _feed([{"kind": "domain", "value": "evil.example", "first_seen": "2026-11-23"}]),
    )
    with pytest.raises(IOCError, match="source"):
        load_feed(path)


def test_missing_first_seen_is_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _feed([{"kind": "domain", "value": "evil.example", "source": "unit test"}]),
    )
    with pytest.raises(IOCError, match="first_seen"):
        load_feed(path)


def test_unsupported_kind_is_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _feed(
            [
                {
                    "kind": "ip",
                    "value": "10.0.0.1",
                    "source": "unit test",
                    "first_seen": "2026-11-23",
                }
            ]
        ),
    )
    with pytest.raises(IOCError, match="unsupported kind"):
        load_feed(path)


def test_malformed_sha256_is_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _feed(
            [
                {
                    "kind": "sha256",
                    "value": "abc123",
                    "source": "unit test",
                    "first_seen": "2026-11-23",
                }
            ]
        ),
    )
    with pytest.raises(IOCError, match="64 lowercase hex"):
        load_feed(path)


def test_domain_with_scheme_is_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _feed(
            [
                {
                    "kind": "domain",
                    "value": "http://1688360.cc",
                    "source": "unit test",
                    "first_seen": "2026-11-23",
                }
            ]
        ),
    )
    with pytest.raises(IOCError, match="bare hostname"):
        load_feed(path)


def test_missing_metadata_is_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        {"records": [{"kind": "domain", "value": "x.cc", "source": "s", "first_seen": "d"}]},
    )
    with pytest.raises(IOCError, match="feed_id"):
        load_feed(path)


def test_empty_records_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path, _feed([]))
    with pytest.raises(IOCError, match="non-empty"):
        load_feed(path)


def test_invalid_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(IOCError, match="not valid JSON"):
        load_feed(path)


def test_missing_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(IOCError, match="not found"):
        load_feed(tmp_path / "absent.json")


def test_validate_record_returns_record() -> None:
    record = validate_record(
        {"kind": "domain", "value": "Evil.CC", "source": "src", "first_seen": "2026-11-23"},
        "test",
    )
    assert isinstance(record, IOCRecord)
    assert record.value == "evil.cc"
    assert record.severity == "high"


def test_merge_feeds_dedupes() -> None:
    a = load_default_feed()
    merged = merge_feeds([a, a])
    assert isinstance(merged, IOCFeed)
    assert len(merged.records) == len(a.records)
    assert merged.feed_id == "optimjack-2026-11-23+optimjack-2026-11-23"


def test_digest_is_stable() -> None:
    feed = load_default_feed()
    assert feed.digest() == load_default_feed().digest()
    assert len(feed.digest()) == 64
