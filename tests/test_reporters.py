"""Unit tests for JSON and Markdown reporters."""

from __future__ import annotations

import json
from pathlib import Path

from scriptsentinel.models import (
    AuditReport,
    ComplianceItem,
    CSPAnalysis,
    Finding,
    HashDigests,
    IntegrityIssue,
    RemediationPack,
    ScanFinding,
    ScanResult,
    ScriptAudit,
    ScriptIntegrityResult,
    ScriptTagReplacement,
)
from scriptsentinel.report.html_reporter import render_html, write_html
from scriptsentinel.report.json_reporter import render_json, write_json
from scriptsentinel.report.markdown_reporter import render_markdown, write_markdown


def _sample_report() -> AuditReport:
    integrity = ScriptIntegrityResult(
        url="https://cdn.vendor.com/tracker.js",
        status="SCRIPT_DRIFT",
        drift_detected=True,
        declared_integrity="sha256-old",
        calculated=HashDigests("hash256", "hash384", "sha256-new", "sha384-new", 2048),
        issues=(IntegrityIssue("SCRIPT_DRIFT", "CRITICAL", "Script content altered upstream"),),
        suggested_tag='<script src="https://cdn.vendor.com/tracker.js" integrity="sha256-new" crossorigin="anonymous"></script>',
    )
    scan = ScanResult(
        target="https://cdn.vendor.com/tracker.js",
        is_suspicious=True,
        findings_count=1,
        findings=(
            ScanFinding(
                rule_id="SKIM-INPUT-HARVEST",
                name="Input Harvest",
                severity="CRITICAL",
                matches_count=3,
                description="Scrapes CVV and card numbers",
            ),
        ),
    )
    script = ScriptAudit(
        index=0,
        kind="external",
        url="https://cdn.vendor.com/tracker.js",
        integrity=integrity,
        scan=scan,
    )
    csp = CSPAnalysis(
        score=0,
        grade="F",
        directives={"default-src": ("'self'",), "connect-src": ("*",)},
        findings=(
            Finding(
                rule_id="CSP-CONNECT-WILDCARD",
                severity="CRITICAL",
                title="Wildcard connect-src",
                description="Connect-src wildcard permits exfiltration",
                recommendation="Lock down connect-src",
                evidence="connect-src *",
            ),
        ),
    )
    remediation = RemediationPack(
        site_url="https://payments.checkout.com",
        hardened_csp="default-src 'self'; script-src 'self' 'nonce-{NONCE}'",
        sri_replacement_tags=(
            ScriptTagReplacement(
                url="https://cdn.vendor.com/tracker.js",
                tag='<script src="https://cdn.vendor.com/tracker.js" integrity="sha256-new" crossorigin="anonymous"></script>',
            ),
        ),
        nginx_config='add_header Content-Security-Policy "..." always;',
        apache_config='Header set Content-Security-Policy "..."',
        compliance=(
            ComplianceItem(
                standard="PCI-DSS v4.0 Requirement 6.4.3",
                requirement="Manage scripts and SRI",
                status="PASS",
            ),
        ),
    )
    return AuditReport(
        target_url="https://payments.checkout.com",
        timestamp="2026-11-23T18:00:00Z",
        status_code=200,
        headers={"content-security-policy": "default-src 'self'; connect-src *"},
        csp=csp,
        scripts=(script,),
        overall_risk="CRITICAL",
        summary={"overall_risk": "CRITICAL", "total_scripts": 1},
        remediation=remediation,
    )


def test_markdown_reporter(tmp_path: Path):
    report = _sample_report()
    md = render_markdown(report)

    assert "# ScriptSentinel Audit Report" in md
    assert "https://payments.checkout.com" in md
    assert "CRITICAL" in md
    assert "CSP-CONNECT-WILDCARD" in md
    assert "SKIM-INPUT-HARVEST" in md
    assert "SCRIPT_DRIFT" in md
    assert "PCI-DSS v4.0 Requirement 6.4.3" in md

    out_file = tmp_path / "audit.md"
    write_markdown(report, out_file)
    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8") == md


def test_json_reporter(tmp_path: Path):
    report = _sample_report()
    rendered = render_json(report)
    parsed = json.loads(rendered)

    assert parsed["target_url"] == "https://payments.checkout.com"
    assert parsed["overall_risk"] == "CRITICAL"
    assert len(parsed["scripts"]) == 1

    out_file = tmp_path / "audit.json"
    write_json(report, out_file)
    assert out_file.exists()
    assert json.loads(out_file.read_text(encoding="utf-8")) == parsed


def test_html_reporter(tmp_path: Path):
    report = _sample_report()
    rendered = render_html(report)

    assert "<!DOCTYPE html>" in rendered
    assert "https://payments.checkout.com" in rendered
    assert "CRITICAL" in rendered
    assert "badge-critical" in rendered
    assert "SCRIPT_DRIFT" in rendered

    out_file = tmp_path / "audit.html"
    write_html(report, out_file)
    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8") == rendered

