"""Behavioral JavaScript scanner for ScriptSentinel.

Detects payment/credential field harvesting, DOM input interception, clipboard
access, dynamic evaluation, base64 unpacking, network beacons, and matches
against packaged IOC feeds.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
from pathlib import Path

from .iocs.loader import IOCError, load_default_feed
from .models import ScanFinding, ScanResult, Severity

__all__ = ["scan_script_content"]

_MALICIOUS_FEED_PATH = Path(__file__).parent / "iocs" / "feeds" / "malicious_c2.json"


def _load_ioc_domains() -> tuple[str, ...]:
    """Load OPTIMJACK domains from the packaged feed plus legacy C2 feed domains."""
    domains: set[str] = set()
    with contextlib.suppress(IOCError):
        domains.update(load_default_feed().domains())
    try:
        raw = json.loads(_MALICIOUS_FEED_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raw = {}
    legacy = raw.get("domains", []) if isinstance(raw, dict) else []
    if isinstance(legacy, list):
        domains.update(str(domain).strip().lower() for domain in legacy if str(domain).strip())
    return tuple(sorted(domains))


def _load_ioc_hashes() -> tuple[str, ...]:
    """Load SHA-256 indicators from the packaged OPTIMJACK feed."""
    try:
        return tuple(sorted(load_default_feed().hashes()))
    except IOCError:
        return ()


KNOWN_IOC_DOMAINS: tuple[str, ...] = _load_ioc_domains()
KNOWN_IOC_HASHES: tuple[str, ...] = _load_ioc_hashes()

_PATTERNS: tuple[tuple[str, str, Severity, str, str], ...] = (
    (
        "SKIM-INPUT-HARVEST",
        "Payment & Credential Field Scraping",
        "CRITICAL",
        (
            r"(?:card(?:number|_no)?|cvv|cvc|expir(?:y|ation)|password|passwd|ssn)"
            r"\b['\"]?\s*(?:,|:|=|\.value|\.getAttribute)"
        ),
        "Script inspects or extracts payment card, CVV, or credential field values.",
    ),
    (
        "SKIM-DOM-LISTENER",
        "Global Input / Keystroke Interceptor",
        "HIGH",
        r"addEventListener\s*\(\s*['\"](?:input|change|keydown|keyup|keypress|submit)['\"]",
        "Attaches global listeners to harvest keystrokes or form submissions.",
    ),
    (
        "SKIM-CLIPBOARD-TAMPER",
        "Clipboard Read / Write Access",
        "HIGH",
        r"navigator\.(?:clipboard\.(?:readText|writeText)|clipboard)\b",
        "Interacts directly with the clipboard for credential theft or payload swapping.",
    ),
    (
        "SKIM-EVAL-EXEC",
        "Dynamic Code Evaluation",
        "CRITICAL",
        r"\b(?:eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['\"][^,])",
        "Executes dynamic strings, often used to unpack obfuscated payloads.",
    ),
    (
        "SKIM-BASE64-UNPACK",
        "Base64 Decoding / Obfuscation Unpacker",
        "MEDIUM",
        r"\b(?:window\.)?(?:atob|btoa)\s*\(",
        "Decodes or encodes base64 strings dynamically at runtime.",
    ),
    (
        "SKIM-EXFIL-BEACON",
        "Network Exfiltration Beacon",
        "HIGH",
        r"navigator\.sendBeacon\s*\(",
        "Uses asynchronous sendBeacon to exfiltrate data during page unload.",
    ),
)


def _domain_present(content: str, domain: str) -> bool:
    """Return True only for an exact hostname occurrence (no substring matches)."""
    pattern = rf"(?<![\w.-]){re.escape(domain)}(?![\w.-])"
    return re.search(pattern, content, re.IGNORECASE) is not None


def _hash_present(content: str, digest: str) -> bool:
    """Return True only for an exact SHA-256 hex occurrence."""
    pattern = rf"(?<![\da-f]){re.escape(digest)}(?![\da-f])"
    return re.search(pattern, content, re.IGNORECASE) is not None


def scan_script_content(content_str: str, script_name: str = "inline") -> ScanResult:
    """Scan JavaScript source for skimmer behaviors and IOC matches."""
    findings: list[ScanFinding] = []

    for rule_id, name, severity, pattern, description in _PATTERNS:
        matches = re.findall(pattern, content_str, re.IGNORECASE)
        if matches:
            findings.append(
                ScanFinding(
                    rule_id=rule_id,
                    name=name,
                    severity=severity,
                    matches_count=len(matches),
                    description=description,
                )
            )

    matched_domains = [domain for domain in KNOWN_IOC_DOMAINS if _domain_present(content_str, domain)]
    if matched_domains:
        findings.append(
            ScanFinding(
                rule_id="IOC-MATCH-C2-DOMAIN",
                name="Known Malicious C2 Domain IOC Matched",
                severity="CRITICAL",
                matches_count=len(matched_domains),
                description=f"Script references known adversary C2 host(s): {', '.join(matched_domains)}",
                domains=tuple(matched_domains),
            )
        )

    matched_hashes = [digest for digest in KNOWN_IOC_HASHES if _hash_present(content_str, digest)]
    computed = hashlib.sha256(content_str.encode("utf-8")).hexdigest()
    if computed in KNOWN_IOC_HASHES and computed not in matched_hashes:
        matched_hashes.append(computed)
    if matched_hashes:
        findings.append(
            ScanFinding(
                rule_id="IOC-MATCH-C2-HASH",
                name="Known Malicious Script Hash IOC Matched",
                severity="CRITICAL",
                matches_count=len(matched_hashes),
                description=f"Script matches known malicious SHA-256 indicator(s): {', '.join(matched_hashes)}",
            )
        )

    is_suspicious = any(finding.severity in ("CRITICAL", "HIGH") for finding in findings)
    return ScanResult(
        target=script_name,
        is_suspicious=is_suspicious,
        findings_count=len(findings),
        findings=tuple(findings),
    )
