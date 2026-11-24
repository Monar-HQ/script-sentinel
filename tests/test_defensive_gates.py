"""Regression tests for security trust boundaries using harmless synthetic bytes."""

import base64
import hashlib
import json

import pytest

from scriptsentinel import proposals
from scriptsentinel.auto import run_auto_pipeline
from scriptsentinel.cli import main
from scriptsentinel.csp_analyzer import analyze_csp, parse_csp
from scriptsentinel.integrity import compute_hashes, matches_sri


def test_sri_strongest_algorithm_and_multiple_tokens():
    content = b"console.log('synthetic');"
    hashes = compute_hashes(content)
    assert matches_sri(content, "unknown-abc " + hashes.sri_sha384 + " " + hashes.sri_sha256)
    assert not matches_sri(content, hashes.sri_sha256 + " sha512-AAAA")
    sha512 = base64.b64encode(hashlib.sha512(content).digest()).decode()
    assert matches_sri(content, "sha512-AAAA sha512-" + sha512)
    assert not matches_sri(content, "unknown-abc")


def test_csp_first_duplicate_and_empty_source_list():
    assert parse_csp("script-src 'none'; SCRIPT-SRC *")["script-src"] == ["'none'"]
    result = analyze_csp("default-src 'self'; connect-src; report-uri /reports")
    assert "CSP-CONNECT-WILDCARD" not in [f.rule_id for f in result.findings]
    assert analyze_csp("   ").grade == "F"


def test_local_audit_retains_scripts_and_failures(tmp_path):
    (tmp_path / "index.html").write_text(
        '<script src="app.js"></script><script src="missing.js"></script>'
        '<script>eval("synthetic");</script>',
        encoding="utf-8",
    )
    (tmp_path / "app.js").write_bytes(b"console.log('synthetic')")
    report = run_auto_pipeline(str(tmp_path)).audit_report
    assert len(report.scripts) == 3
    assert report.scripts[0].integrity.calculated.byte_count > 0
    assert report.scripts[1].error and report.scripts[1].integrity is None
    assert report.scripts[2].scan.findings


def fixture(tmp_path):
    (tmp_path / "index.html").write_text(
        '<head><script src="app.js"></script></head>', encoding="utf-8"
    )
    script = b"console.log('synthetic')"
    (tmp_path / "app.js").write_bytes(script)
    baseline = tmp_path / "trusted.json"
    baseline.write_text(
        json.dumps(
            {
                "schema": 1,
                "reviewer": "test reviewer",
                "provenance": "synthetic fixture",
                "files": {"app.js": proposals.digest(script)},
            }
        ),
        encoding="utf-8",
    )
    return baseline


def test_proposal_approval_atomic_write_and_recovery(tmp_path):
    baseline = fixture(tmp_path)
    original = (tmp_path / "index.html").read_bytes()
    plan = proposals.propose(tmp_path, "index.html", baseline)
    assert (tmp_path / "index.html").read_bytes() == original
    proposals.validate(tmp_path, plan, baseline)
    with pytest.raises(ValueError, match="approval"):
        proposals.apply(tmp_path, plan, baseline)
    backup = proposals.apply(tmp_path, plan, baseline, approved=True)
    assert backup.read_bytes() == original
    assert "integrity=" in (tmp_path / "index.html").read_text()


@pytest.mark.parametrize("change", ["resource", "proposal", "target", "baseline"])
def test_proposal_rejects_drift_and_tampering(tmp_path, change):
    baseline = fixture(tmp_path)
    plan = proposals.propose(tmp_path, "index.html", baseline)
    if change == "resource":
        (tmp_path / "app.js").write_bytes(b"changed")
    elif change == "proposal":
        plan["replacement"] += "<script>unexpected()</script>"
    elif change == "target":
        (tmp_path / "index.html").write_text("changed", encoding="utf-8")
    else:
        baseline.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError):
        proposals.apply(tmp_path, plan, baseline, approved=True)


def test_path_escape_and_missing_baseline_fail_closed(tmp_path):
    baseline = fixture(tmp_path)
    with pytest.raises(ValueError):
        proposals.propose(tmp_path, "../outside.html", baseline)
    assert main(["monitor", "https://example.invalid", "--baseline", str(tmp_path / "absent")]) == 2


def test_ai_invalid_response_is_advisory_failure(tmp_path):
    from scriptsentinel.ai.agent import AIAgent

    class Client:
        is_available = True

        def generate(self, system, prompt):
            assert "SECRET" not in prompt
            return '{"executive_summary": 1}'

    fixture(tmp_path)
    report = run_auto_pipeline(str(tmp_path)).audit_report
    with pytest.raises(ValueError, match="invalid fields"):
        AIAgent(Client()).analyze_audit(report)


def test_har_inventory_redacts_sensitive_request_data(tmp_path):
    from scriptsentinel.observation import inventory_har

    har = tmp_path / "page.har"
    har.write_text(
        json.dumps(
            {
                "log": {
                    "pages": [{"id": "page-1"}],
                    "entries": [
                        {
                            "pageref": "page-1",
                            "request": {
                                "url": "https://cdn.example/app.js?token=SECRET",
                                "cookies": [{"value": "SECRET"}],
                            },
                            "response": {
                                "status": 200,
                                "content": {"mimeType": "application/javascript", "text": "SECRET"},
                            },
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    result = inventory_har(har, "https://owned.example")
    assert "SECRET" not in json.dumps(result)
    assert result["scripts"][0]["third_party"] is True


def test_har_rejects_mixed_pages(tmp_path):
    from scriptsentinel.observation import inventory_har

    har = tmp_path / "page.har"
    har.write_text('{"log":{"pages":[{"id":"p1"},{"id":"p2"}],"entries":[]}}', encoding="utf-8")
    with pytest.raises(ValueError, match="exactly one"):
        inventory_har(har, "https://owned.example")


def test_provider_key_redaction_and_local_endpoint_boundary():
    from scriptsentinel.ai.client import AIConfig

    assert "SECRET" not in repr(AIConfig("openai", "SECRET", None, "test"))
    assert not AIConfig("custom", None, "http://localhost.attacker.invalid", "test").is_configured
    assert AIConfig("custom", None, "http://127.0.0.1:1234/v1", "test").is_configured


def test_multiple_csp_policies_not_falsely_graded_secure():
    result = analyze_csp("default-src 'none', script-src *")
    assert result.findings[0].rule_id == "CSP-MULTIPLE-POLICIES"


def test_invalid_hash_does_not_hide_unsafe_inline_and_attr_override():
    result = analyze_csp("script-src 'unsafe-inline' 'sha256-not-a-digest'; connect-src 'self'")
    assert "CSP-UNSAFE-INLINE" in [finding.rule_id for finding in result.findings]
    result = analyze_csp(
        "script-src 'nonce-valid'; script-src-attr 'unsafe-inline'; connect-src 'self'"
    )
    assert "CSP-UNSAFE-ATTR" in [finding.rule_id for finding in result.findings]


def test_ai_outage_preserves_core_findings(tmp_path):
    class Client:
        is_available = True

        def generate(self, system, prompt):
            raise TimeoutError("provider unavailable")

    fixture(tmp_path)
    result = run_auto_pipeline(str(tmp_path), ai_client=Client())
    assert result.ai_analysis is None
    assert result.summary["ai_error"]
    assert len(result.audit_report.scripts) == 1


def test_http_error_is_not_reported_as_success():
    import asyncio

    import httpx

    from scriptsentinel.auditor import audit_url

    transport = httpx.MockTransport(lambda request: httpx.Response(404, text="missing"))
    report = asyncio.run(audit_url("https://example.invalid", transport=transport))
    assert report.error
    assert report.overall_risk == "ERROR"
