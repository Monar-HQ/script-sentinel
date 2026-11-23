import pytest
import base64
import hashlib
from scriptsentinel.integrity import compute_hashes, audit_script_integrity

def test_compute_hashes():
    data = b"console.log('hello secure world');"
    hashes = compute_hashes(data)

    expected_sha256 = hashlib.sha256(data).hexdigest()
    expected_sri = f"sha256-{base64.b64encode(hashlib.sha256(data).digest()).decode('ascii')}"

    assert hashes["sha256"] == expected_sha256
    assert hashes["sri_sha256"] == expected_sri
    assert hashes["byte_count"] == len(data)

def test_audit_missing_sri():
    data = b"console.log('vendor script');"
    res = audit_script_integrity(
        script_url="https://cdn.vendor.com/sdk.js",
        content=data,
        declared_integrity=None
    )
    assert res["status"] == "MISSING_SRI"
    assert len(res["issues"]) == 1
    assert res["issues"][0]["type"] == "MISSING_SRI"
    assert res["suggested_tag"].startswith('<script src="https://cdn.vendor.com/sdk.js" integrity="sha256-')

def test_audit_integrity_verified():
    data = b"console.log('clean script');"
    hashes = compute_hashes(data)
    res = audit_script_integrity(
        script_url="https://cdn.vendor.com/sdk.js",
        content=data,
        declared_integrity=hashes["sri_sha256"]
    )
    assert res["status"] == "VERIFIED"
    assert len(res["issues"]) == 0

def test_audit_integrity_mismatch():
    data = b"console.log('tampered script');"
    res = audit_script_integrity(
        script_url="https://cdn.vendor.com/sdk.js",
        content=data,
        declared_integrity="sha256-AAAAfakehash123="
    )
    assert res["status"] == "INTEGRITY_MISMATCH"
    assert any(i["type"] == "INTEGRITY_MISMATCH" for i in res["issues"])

def test_audit_script_drift():
    data = b"console.log('modified vendor code');"
    baseline = "0000000000000000000000000000000000000000000000000000000000000000"
    res = audit_script_integrity(
        script_url="https://cdn.vendor.com/sdk.js",
        content=data,
        baseline_sha256=baseline
    )
    assert res["drift_detected"] is True
    assert res["status"] == "SCRIPT_DRIFT"
    assert any(i["type"] == "SCRIPT_DRIFT" for i in res["issues"])
