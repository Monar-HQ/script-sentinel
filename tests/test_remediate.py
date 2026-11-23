import pytest
from scriptsentinel.remediate import generate_remediation_pack

def test_generate_remediation_pack():
    site_url = "https://example.com/checkout"
    csp_analysis = {
        "score": 0,
        "grade": "F",
        "findings": [{"rule_id": "CSP-MISSING", "severity": "CRITICAL"}]
    }
    scripts_audit = [
        {
            "url": "https://cdn.optimizely-edge.com/geo.js",
            "suggested_tag": '<script src="https://cdn.optimizely-edge.com/geo.js" integrity="sha256-AbCdEf=" crossorigin="anonymous"></script>'
        }
    ]

    pack = generate_remediation_pack(site_url, csp_analysis, scripts_audit)
    assert pack["site_url"] == site_url
    assert "https://cdn.optimizely-edge.com" in pack["hardened_csp"]
    assert "connect-src 'self'" in pack["hardened_csp"]
    assert "report-uri /api/csp-report" in pack["hardened_csp"]
    assert len(pack["sri_replacement_tags"]) == 1
    assert "add_header Content-Security-Policy" in pack["nginx_config"]
    assert "Header set Content-Security-Policy" in pack["apache_config"]
    assert len(pack["compliance"]) == 2
