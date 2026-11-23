"""
Script Integrity & Drift Detector
Handles cryptographic hashing, SRI generation, and baseline drift auditing.
"""

import base64
import hashlib
from typing import Any


def compute_hashes(content: bytes) -> dict[str, str]:
    sha256_bytes = hashlib.sha256(content).digest()
    sha384_bytes = hashlib.sha384(content).digest()

    sha256_hex = hashlib.sha256(content).hexdigest()
    sha384_hex = hashlib.sha384(content).hexdigest()

    sha256_sri = f"sha256-{base64.b64encode(sha256_bytes).decode('ascii')}"
    sha384_sri = f"sha384-{base64.b64encode(sha384_bytes).decode('ascii')}"

    return {
        "sha256": sha256_hex,
        "sha384": sha384_hex,
        "sri_sha256": sha256_sri,
        "sri_sha384": sha384_sri,
        "byte_count": len(content),
    }


def audit_script_integrity(
    script_url: str,
    content: bytes,
    declared_integrity: str | None = None,
    baseline_sha256: str | None = None,
) -> dict[str, Any]:
    calculated = compute_hashes(content)
    status = "VERIFIED"
    issues = []

    # 1. Check if SRI is missing entirely
    if not declared_integrity:
        status = "MISSING_SRI"
        issues.append(
            {
                "type": "MISSING_SRI",
                "severity": "HIGH",
                "message": f"Script '{script_url}' is loaded without a Subresource Integrity (SRI) attribute. Any upstream vendor compromise executes without cryptographic verification.",
            }
        )
    else:
        # Verify declared integrity against calculated
        if declared_integrity not in (calculated["sri_sha256"], calculated["sri_sha384"]):
            status = "INTEGRITY_MISMATCH"
            issues.append(
                {
                    "type": "INTEGRITY_MISMATCH",
                    "severity": "CRITICAL",
                    "message": f"Cryptographic integrity mismatch! Declared '{declared_integrity}', but resource hashes to '{calculated['sri_sha256']}'. Resource will be blocked by browser.",
                }
            )

    # 2. Check for script drift against baseline
    drift_detected = False
    if baseline_sha256 and calculated["sha256"] != baseline_sha256.lower():
        drift_detected = True
        status = "SCRIPT_DRIFT"
        issues.append(
            {
                "type": "SCRIPT_DRIFT",
                "severity": "CRITICAL",
                "message": f"Script drift detected! Current SHA-256 '{calculated['sha256']}' differs from pinned baseline '{baseline_sha256}'. Upstream script has been modified.",
            }
        )

    return {
        "url": script_url,
        "status": status,
        "drift_detected": drift_detected,
        "declared_integrity": declared_integrity,
        "calculated": calculated,
        "issues": issues,
        "suggested_tag": f'<script src="{script_url}" integrity="{calculated["sri_sha256"]}" crossorigin="anonymous"></script>',
    }
