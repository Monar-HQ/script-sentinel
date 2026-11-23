"""Unit tests for ScriptSentinel shared models and compatibility layer."""

from __future__ import annotations

import json

from scriptsentinel.models import (
    AuditReport,
    ComplianceItem,
    HashDigests,
    IntegrityIssue,
    RemediationPack,
    ScanFinding,
    ScanResult,
    ScriptAudit,
    ScriptIntegrityResult,
    ScriptTagReplacement,
)


def test_remediation_pack_dict_compatibility():
    pack = RemediationPack(
        site_url="https://checkout.example.com",
        hardened_csp="default-src 'self'",
        sri_replacement_tags=(
            ScriptTagReplacement(
                url="https://cdn.vendor.com/sdk.js",
                tag='<script src="https://cdn.vendor.com/sdk.js" integrity="sha256-abc"></script>',
            ),
        ),
        nginx_config="add_header Content-Security-Policy ...",
        apache_config="Header set Content-Security-Policy ...",
        compliance=(
            ComplianceItem(
                standard="PCI-DSS v4.0 Requirement 6.4.3",
                requirement="Manage scripts",
                status="PASS",
            ),
        ),
    )

    # Dict-like access
    assert pack.get("hardened_csp") == "default-src 'self'"
    assert pack["hardened_csp"] == "default-src 'self'"
    assert pack.get("missing_key", "default_val") == "default_val"
    assert "hardened_csp" in pack
    assert "missing" not in pack
    assert len(pack.keys()) == 6
    assert len(pack.items()) == 6

    # SRI replacement tags dictionary access
    tags = pack.get("sri_replacement_tags")
    assert isinstance(tags, list)
    assert len(tags) == 1
    assert tags[0]["url"] == "https://cdn.vendor.com/sdk.js"

    # Serialization
    d = pack.to_dict()
    assert d["site_url"] == "https://checkout.example.com"
    json_str = json.dumps(d)
    assert "PCI-DSS v4.0 Requirement 6.4.3" in json_str


def test_script_audit_dict_compatibility():
    integrity = ScriptIntegrityResult(
        url="https://cdn.vendor.com/sdk.js",
        status="VERIFIED",
        drift_detected=False,
        declared_integrity="sha256-abc",
        calculated=HashDigests("a", "b", "sha256-a", "sha384-b", 100),
        issues=(IntegrityIssue("MISSING_SRI", "HIGH", "Missing SRI"),),
        suggested_tag='<script src="https://cdn.vendor.com/sdk.js" integrity="sha256-a"></script>',
    )
    scan = ScanResult(
        target="https://cdn.vendor.com/sdk.js",
        is_suspicious=True,
        findings_count=1,
        findings=(
            ScanFinding(
                rule_id="SKIM-INPUT-HARVEST",
                name="Input Harvest",
                severity="CRITICAL",
                matches_count=2,
                description="Scrapes CVV fields",
            ),
        ),
    )
    audit = ScriptAudit(
        index=0,
        kind="external",
        url="https://cdn.vendor.com/sdk.js",
        integrity=integrity,
        scan=scan,
    )

    # Dict compatibility
    assert audit.get("type") == "external"
    assert audit["type"] == "external"
    assert audit.get("url") == "https://cdn.vendor.com/sdk.js"
    assert audit.get("integrity_audit")["status"] == "VERIFIED"
    assert audit.get("scanner_audit")["is_suspicious"] is True
    assert "type" in audit

    d = audit.to_dict()
    assert d["type"] == "external"
    assert d["integrity_audit"]["status"] == "VERIFIED"


def test_audit_report_factory_and_serialization():
    report = AuditReport.create(
        target_url="https://checkout.example.com/pay",
        status_code=200,
        headers={"content-type": "text/html"},
        csp={"score": 80, "grade": "B", "directives": {"default-src": ["'self'"]}, "findings": []},
        scripts=[
            {
                "index": 0,
                "type": "external",
                "url": "https://cdn.vendor.com/app.js",
                "suggested_tag": '<script src="https://cdn.vendor.com/app.js" integrity="sha256-x"></script>',
            }
        ],
        overall_risk="LOW",
        remediation={
            "hardened_csp": "default-src 'self'",
            "sri_replacement_tags": [{"url": "https://cdn.vendor.com/app.js", "tag": "<script></script>"}],
            "nginx_config": "...",
            "apache_config": "...",
            "compliance": [],
        },
    )

    assert report.target_url == "https://checkout.example.com/pay"
    assert report.csp.grade == "B"
    assert report.csp_report["grade"] == "B"
    assert len(report.scripts) == 1
    assert report.scripts[0].kind == "external"
    assert report.remediation is not None
    assert report.remediation.get("hardened_csp") == "default-src 'self'"

    # Serialization to pure JSON
    data = report.to_dict()
    json_bytes = json.dumps(data)
    assert "https://checkout.example.com/pay" in json_bytes
