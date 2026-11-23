"""Tests for Sigma and Suricata rule exporters."""

from __future__ import annotations

import re
from pathlib import Path
from typing import cast

import pytest
import yaml  # type: ignore[import-untyped]

from scriptsentinel.iocs.loader import load_default_feed
from scriptsentinel.models import (
    AuditReport,
    CSPAnalysis,
    Finding,
    ScanFinding,
    ScanResult,
    ScriptAudit,
)
from scriptsentinel.rules import export_sigma, export_suricata, write_sigma, write_suricata

REQUIRED_SIGMA_KEYS: tuple[str, ...] = (
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "logsource",
    "detection",
    "fields",
    "level",
    "falsepositives",
    "tags",
)
RULE_RE = re.compile(r"^alert (?:http|dns) any any -> any any \(.+\)$")
SID_RE = re.compile(r"\bsid:(\d+);")


def _load_rule(text: str) -> dict[str, object]:
    raw = yaml.safe_load(text)
    assert isinstance(raw, dict)
    return cast("dict[str, object]", raw)


def _flatten(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(f"{_flatten(key)} {_flatten(item)}" for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return " ".join(_flatten(item) for item in value)
    return str(value)


def _alert_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip().startswith("alert ")]


def _sid(rule: str) -> int:
    match = SID_RE.search(rule)
    assert match is not None
    return int(match.group(1))


def _sample_report() -> AuditReport:
    csp_finding = Finding(
        rule_id="CSP-SCRIPT-SRC-UNSCOPED",
        severity="HIGH",
        title="Unscoped script-src",
        description="script-src allows arbitrary origins.",
        recommendation="Restrict script-src to trusted origins.",
        evidence="script-src https://cdn.example",
    )
    scan_finding = ScanFinding(
        rule_id="IOC-MATCH-C2-DOMAIN",
        name="Known Malicious C2 Domain IOC Matched",
        severity="CRITICAL",
        matches_count=1,
        description="Script references 1688360.cc.",
        domains=("1688360.cc",),
    )
    scan = ScanResult(
        target="https://cdn.example/track.js",
        is_suspicious=True,
        findings_count=1,
        findings=(scan_finding,),
    )
    script = ScriptAudit(index=0, kind="external", url="https://cdn.example/track.js", scan=scan)
    return AuditReport(
        target_url="https://shop.example/checkout",
        timestamp="2026-11-23T12:34:56Z",
        status_code=200,
        headers={"content-type": "text/html"},
        csp=CSPAnalysis(
            score=55,
            grade="C",
            directives={"script-src": ("https://cdn.example",)},
            findings=(csp_finding,),
        ),
        scripts=(script,),
        overall_risk="CRITICAL",
        summary={"total_scripts": 1},
    )


def test_export_sigma_emits_required_keys() -> None:
    rule = _load_rule(export_sigma())
    for key in REQUIRED_SIGMA_KEYS:
        assert key in rule

    logsource = rule["logsource"]
    assert isinstance(logsource, dict)
    assert logsource["category"] == "webserver"

    detection = rule["detection"]
    assert isinstance(detection, dict)
    assert isinstance(detection["condition"], str)

    assert isinstance(rule["fields"], list)
    assert isinstance(rule["falsepositives"], list)
    assert isinstance(rule["tags"], list)


def test_export_sigma_includes_all_iocs() -> None:
    feed = load_default_feed()
    rule = _load_rule(export_sigma(feed=feed))
    serialized = _flatten(rule)

    assert len(feed.domains()) == 8
    for domain in feed.domains():
        assert domain in serialized
    for digest in feed.hashes():
        assert digest in serialized

    assert rule["date"] == "2026-11-23"
    assert rule["level"] == "critical"
    assert rule["status"] == "stable"


def test_export_sigma_includes_report_findings() -> None:
    report = _sample_report()
    rule = _load_rule(export_sigma(report=report))
    serialized = _flatten(rule)

    assert "CSP-SCRIPT-SRC-UNSCOPED" in serialized
    assert "IOC-MATCH-C2-DOMAIN" in serialized
    assert "shop.example" in serialized
    assert rule["date"] == "2026-11-23"
    assert rule["level"] == "critical"

    detection = rule["detection"]
    assert isinstance(detection, dict)
    assert "selection_audit_urls" in detection


def test_write_sigma(tmp_path: Path) -> None:
    expected = export_sigma()
    target = tmp_path / "sigma.yml"

    assert write_sigma(target) == target
    written = target.read_text(encoding="utf-8")
    assert written == expected
    assert _load_rule(written)["status"] == "stable"


def test_export_suricata_emits_http_and_dns_rules_for_eight_domains() -> None:
    feed = load_default_feed()
    text = export_suricata()
    rules = _alert_lines(text)

    assert len(rules) == 16
    http_rules = [rule for rule in rules if rule.startswith("alert http ")]
    dns_rules = [rule for rule in rules if rule.startswith("alert dns ")]
    assert len(http_rules) == 8
    assert len(dns_rules) == 8

    for domain in feed.domains():
        assert any(f'content:"{domain}"' in rule for rule in http_rules)
        assert any(f'content:"{domain}"' in rule for rule in dns_rules)

    for rule in rules:
        assert RULE_RE.match(rule) is not None
        assert "sid:" in rule
        assert "rev:1;" in rule


def test_suricata_sids_start_at_base_and_increment() -> None:
    rules = _alert_lines(export_suricata(sid_base=200000))

    assert [_sid(rule) for rule in rules[:8]] == list(range(200000, 200008))
    assert [_sid(rule) for rule in rules[8:]] == list(range(200008, 200016))


def test_export_suricata_accepts_report_without_duplicates() -> None:
    text = export_suricata(report=_sample_report())
    assert len(_alert_lines(text)) == 16


def test_write_suricata(tmp_path: Path) -> None:
    expected = export_suricata()
    target = tmp_path / "suricata.rules"

    assert write_suricata(target) == target
    written = target.read_text(encoding="utf-8")
    assert written == expected
    assert len(_alert_lines(written)) == 16


def test_suricata_rejects_nonpositive_sid_base() -> None:
    with pytest.raises(ValueError, match="sid_base"):
        export_suricata(sid_base=0)
