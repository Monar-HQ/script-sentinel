"""Cryptographic integrity and script-drift detection for ScriptSentinel."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from collections.abc import Mapping
from html import escape

from .models import HashDigests, IntegrityIssue, ScriptIntegrityResult

__all__ = [
    "audit_script_integrity",
    "compute_hashes",
    "validate_html_script_tags",
]


def matches_sri(content: bytes, metadata: str) -> bool:
    """Match any digest at the strongest recognized SRI algorithm level.

    Unknown metadata is ignored. With no usable metadata this audit reports
    an invalid declaration rather than claiming cryptographic verification.
    """
    candidates: dict[int, list[tuple[str, str]]] = {}
    for token in metadata.split():
        match = re.fullmatch(r"(sha256|sha384|sha512)-([A-Za-z0-9+/_-]+={0,2})(?:\?\S*)?", token)
        if match:
            algorithm, digest = match.groups()
            candidates.setdefault(int(algorithm[3:]), []).append((algorithm, digest))
    if not candidates:
        return False
    for algorithm, digest in candidates[max(candidates)]:
        expected = base64.b64encode(hashlib.new(algorithm, content).digest()).decode("ascii")
        normalized = digest.replace("-", "+").replace("_", "/").rstrip("=")
        if hmac.compare_digest(expected.rstrip("="), normalized):
            return True
    return False


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
    elif not matches_sri(content, declared_integrity):
        status = "INTEGRITY_MISMATCH"
        issues.append(
            IntegrityIssue(
                type="INTEGRITY_MISMATCH",
                severity="CRITICAL",
                message=(
                    f"Declared integrity '{declared_integrity}' does not match the "
                    f"calculated digest '{calculated.sri_sha256}'. No matching supported "
                    "digest at the strongest declared algorithm was found."
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
        f'<script src="{escape(script_url, quote=True)}" integrity="{calculated.sri_sha256}" '
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

        # A SHA-256 hex baseline can only be compared with a SHA-256
        # declaration; SHA-384/512 cannot be derived without resource bytes.
        pinned_lower = pinned.strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", pinned_lower):
            raise ValueError("HTML baseline must contain SHA-256 hex digests")
        expected = "sha256-" + base64.b64encode(bytes.fromhex(pinned_lower)).decode("ascii")
        sha256_tokens = [token for token in declared_text.split() if token.startswith("sha256-")]
        if sha256_tokens and expected not in sha256_tokens:
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
