from scriptsentinel.csp_analyzer import analyze_csp, parse_csp


def test_parse_csp_empty():
    assert parse_csp(None) == {}
    assert parse_csp("") == {}
    assert parse_csp("   ") == {}


def test_parse_csp_valid():
    raw = (
        "default-src 'self'; script-src https://cdn.example.com 'unsafe-inline'; connect-src 'self'"
    )
    directives = parse_csp(raw)
    assert "default-src" in directives
    assert directives["default-src"] == ["'self'"]
    assert "script-src" in directives
    assert directives["script-src"] == ["https://cdn.example.com", "'unsafe-inline'"]
    assert directives["connect-src"] == ["'self'"]


def test_analyze_csp_missing():
    res = analyze_csp(None)
    assert res["grade"] == "F"
    assert res["score"] == 0
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "CSP-MISSING" in rule_ids


def test_analyze_csp_unsafe_eval():
    header = (
        "default-src 'self'; script-src 'self' 'unsafe-eval'; connect-src 'self'; report-uri /csp"
    )
    res = analyze_csp(header)
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "CSP-UNSAFE-EVAL" in rule_ids


def test_analyze_csp_unsafe_inline():
    header = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; connect-src 'self'; report-uri /csp"
    )
    res = analyze_csp(header)
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "CSP-UNSAFE-INLINE" in rule_ids


def test_analyze_csp_strict_dynamic_with_open_connect():
    header = "default-src 'self'; script-src 'nonce-abc123' 'strict-dynamic'; connect-src *; report-uri /csp"
    res = analyze_csp(header)
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "CSP-STRICT-DYNAMIC-RISK" in rule_ids
    assert "CSP-CONNECT-WILDCARD" in rule_ids


def test_analyze_csp_strict_hardened():
    header = (
        "default-src 'self'; "
        "script-src 'self' 'nonce-rAnd0m'; "
        "connect-src 'self'; "
        "report-uri /api/csp-report"
    )
    res = analyze_csp(header)
    assert res["grade"] == "A"
    assert res["score"] >= 90
    assert len(res["findings"]) == 0
