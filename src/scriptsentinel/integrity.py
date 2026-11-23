"""Cryptographic integrity and script-drift detection for ScriptSentinel."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping

from .models import HashDigests, IntegrityIssue, ScriptIntegrityResult

__all__ = [
    "audit_script_integrity",
    "compute_hashes",
    "validate_html_script_tags",
]


def compute_hashes(content: bytes) -> HashDigests:
    """Compute SHA-256 and SHA-384 hex digests plus SRI base64 strings."""
    sha256_bytes = hashlib.sha256(content).digest()
    sha384_bytes = hashlib.sha384(content).digest()
    return HashDigests(
        sha256=hashlib.sha256(content).hexdigest(),
        sha384=hashlib.sha384(content).hexdigest(),
        sri_sha256=f"sha256-{base64.b64encode(sha256_bytes).decode('ascii')}",
        sri_sha384=f"sha384-{base64.b64encode(sha384_bytes).decode('ascii')}",
        byte_count=len(content),
    )


def audit_script_integrity(
    script_url: str,
    content: bytes,
    declared_integrity: str | None = None,
    baseline_sha256: str | None = None,
) -> ScriptIntegrityResult:
    """Verify SRI, declared digests, and pinned baseline drift for one script."""
    calculated = compute_hashes(content)
    status = "VERIFIED"
    drift_detected = False
    issues: list[IntegrityIssue] = []

    if not declared_integrity:
        status = "MISSING_SRI"
        issues.append(
            IntegrityIssue(
                type="MISSING_SRI",
                severity="HIGH",
                message=(
                    f"Script '{script_url}' is loaded without a Subresource Integrity "
                    "attribute. Any upstream vendor compromise executes without "
                    "cryptographic verification."
                ),
            )
        )
    elif declared_integrity not in (calculated.sri_sha256, calculated.sri_sha384):
        status = "INTEGRITY_MISMATCH"
        issues.append(
            IntegrityIssue(
                type="INTEGRITY_MISMATCH",
                severity="CRITICAL",
                message=(
                    f"Declared integrity '{declared_integrity}' does not match the "
                    f"calculated digest '{calculated.sri_sha256}'. The browser will "
                    "block the resource."
                ),
            )
        )

    if baseline_sha256 is not None and calculated.sha256 != baseline_sha256.lower():
        drift_detected = True
        status = "SCRIPT_DRIFT"
        issues.append(
            IntegrityIssue(
                type="SCRIPT_DRIFT",
                severity="CRITICAL",
                message=(
                    f"Current SHA-256 '{calculated.sha256}' differs from pinned "
                    f"baseline '{baseline_sha256.lower()}'. Upstream script content "
                    "has changed."
                ),
            )
        )

    suggested_tag = (
        f'<script src="{script_url}" integrity="{calculated.sri_sha256}" '
        'crossorigin="anonymous"></script>'
    )
    return ScriptIntegrityResult(
        url=script_url,
        status=status,
        drift_detected=drift_detected,
        declared_integrity=declared_integrity,
        calculated=calculated,
        issues=tuple(issues),
        suggested_tag=suggested_tag,
    )


def validate_html_script_tags(
    html: str,
    baseline_hashes: Mapping[str, str] | None = None,
) -> tuple[IntegrityIssue, ...]:
    """Validate external script tags for missing SRI, mismatch, and baseline drift.

    This is an HTML-only check: it does not fetch scripts, so it can flag
    ``MISSING_SRI`` and ``SCRIPT_DRIFT`` when the declared integrity differs
    from a pinned baseline digest. ``INTEGRITY_MISMATCH`` requires the actual
    script bytes and is produced by ``audit_script_integrity``.
    """
    from bs4 import BeautifulSoup

    baseline = baseline_hashes or {}
    issues: list[IntegrityIssue] = []
    soup = BeautifulSoup(html, "html.parser")

    for element in soup.find_all("script"):
        src = element.get("src")
        if not isinstance(src, str) or not src.strip():
            continue
        script_url = src.strip()
        declared = element.get("integrity")
        declared_text = declared.strip() if isinstance(declared, str) else None

        if declared_text is None:
            issues.append(
                IntegrityIssue(
                    type="MISSING_SRI",
                    severity="HIGH",
                    message=f"External script '{script_url}' has no integrity attribute.",
                )
            )
            continue

        pinned = baseline.get(script_url)
        if pinned is None:
            continue

        pinned_lower = pinned.strip().lower()
        if declared_text not in {f"sha256-{pinned_lower}", f"sha384-{pinned_lower}"} and (
            declared_text.lower() not in {pinned_lower, f"sha256-{pinned_lower}"}
        ):
                issues.append(
                    IntegrityIssue(
                        type="SCRIPT_DRIFT",
                        severity="CRITICAL",
                        message=(
                            f"Declared integrity '{declared_text}' does not match pinned "
                            f"baseline '{pinned}' for '{script_url}'."
                        ),
                    )
                )

    return tuple(issues)
