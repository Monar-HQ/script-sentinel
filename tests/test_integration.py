"""Live integration checks against the local OPTIJACK victim gateway.

These tests skip cleanly when the lab services are not running, so the unit
suite remains portable while the live verification is reproducible.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from scriptsentinel.auditor import audit_url
from scriptsentinel.csp_analyzer import analyze_csp
from scriptsentinel.rules import export_sigma, export_suricata

STRICT_URL = "http://localhost:8100/strict/checkout"
NO_CSP_URL = "http://localhost:8100/no-csp/checkout"
STRICT_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'nonce-abc123' http://localhost:8001; "
    "connect-src 'self'; "
    "report-uri http://localhost:8200/report"
)
EXPECTED_SHA256 = "1ddc1b32fb1e4bc69c0171d8d34551897e001bd6a2bea9f7f136f34542858b01"


def _lab_available(url: str) -> bool:
    """Return True when the local victim gateway answers."""
    try:
        response = httpx.get(url, timeout=2.0)
    except httpx.HTTPError:
        return False
    return response.status_code == 200


@pytest.mark.integration
def test_live_strict_page_audit() -> None:
    if not _lab_available(STRICT_URL):
        pytest.skip("OPTIJACK victim gateway is not running")

    report = asyncio.run(audit_url(STRICT_URL))

    assert report.status_code == 200
    assert report.csp.grade == "A"
    assert report.csp.score >= 90
    assert report.csp.findings == ()
    assert len(report.scripts) == 1
    external = report.scripts[0]
    assert external.kind == "external"
    assert external.url == "http://localhost:8001/js/acme.js"
    assert external.integrity is not None
    assert external.integrity.status == "MISSING_SRI"
    assert external.integrity.calculated.sha256 == EXPECTED_SHA256
    assert report.remediation is not None
    assert "connect-src 'self'" in report.remediation.hardened_csp
    assert "integrity=\"sha256-HdwbMvseS8acAXHY00VRiX4AG9aivqn38TbzRUKFiwE=\"" in (
        report.remediation.sri_replacement_tags[0].tag
    )


@pytest.mark.integration
def test_live_no_csp_page_audit() -> None:
    if not _lab_available(NO_CSP_URL):
        pytest.skip("OPTIJACK victim gateway is not running")

    report = asyncio.run(audit_url(NO_CSP_URL))

    assert report.status_code == 200
    assert report.csp.grade == "F"
    assert report.csp.score == 0
    assert [finding.rule_id for finding in report.csp.findings] == ["CSP-MISSING"]
    assert report.overall_risk == "CRITICAL"
    assert len(report.scripts) == 1
    assert report.scripts[0].integrity is not None
    assert report.scripts[0].integrity.status == "MISSING_SRI"


@pytest.mark.integration
def test_live_csp_analysis_and_rule_export() -> None:
    if not _lab_available(STRICT_URL):
        pytest.skip("OPTIJACK victim gateway is not running")

    strict = analyze_csp(STRICT_CSP)
    assert strict.grade == "A"
    assert strict.score == 100

    sigma = export_sigma()
    suricata = export_suricata()
    assert "1688360.cc" in sigma
    assert len([line for line in suricata.splitlines() if line.startswith("alert ")]) == 16
