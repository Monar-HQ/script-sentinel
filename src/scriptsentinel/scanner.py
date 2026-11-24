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
        "Sensitive Field Access Pattern",
        "HIGH",
        (
            r"(?:card(?:number|_no)?|cvv|cvc|expir(?:y|ation)|password|passwd|ssn)"
            r"\b['\"]?\s*(?:,|:|=|\.value|\.getAttribute)"
        ),
        "Pattern resembles access to sensitive fields. Legitimate forms use these fields; review data handling and destinations.",
    ),
    (
        "SKIM-DOM-LISTENER",
        "Input / Submit Listener Pattern",
        "MEDIUM",
        r"addEventListener\s*\(\s*['\"](?:input|change|keydown|keyup|keypress|submit)['\"]",
        "Pattern matches an input or form event listener. This does not establish global interception or malicious intent.",
    ),
    (
        "SKIM-CLIPBOARD-TAMPER",
        "Clipboard Read / Write Access",
        "MEDIUM",
        r"navigator\.(?:clipboard\.(?:readText|writeText)|clipboard)\b",
        "Pattern references clipboard capabilities; review purpose and permissions before inferring tampering.",
    ),
    (
        "SKIM-EVAL-EXEC",
        "Dynamic Code Evaluation",
        "HIGH",
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
        "Beacon API Pattern",
        "LOW",
        r"navigator\.sendBeacon\s*\(",
        "Pattern references sendBeacon, also used by ordinary analytics. Destination and data flow require review.",
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
    from .ast_analysis import ast_findings

    findings.extend(ast_findings(content_str))

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
                name="Packaged Hunting Domain Indicator Matched",
                severity="HIGH",
                matches_count=len(matched_domains),
                description=f"Source references packaged hunting indicator(s): {', '.join(matched_domains)}. Verify feed provenance and runtime context; this alone is not proof of compromise.",
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
                name="Packaged Hunting Hash Indicator Matched",
                severity="HIGH",
                matches_count=len(matched_hashes),
                description=f"Source matches packaged SHA-256 indicator(s): {', '.join(matched_hashes)}. Verify the feed's lab/incident provenance before making an attribution.",
            )
        )

    is_suspicious = any(finding.severity in ("CRITICAL", "HIGH") for finding in findings)
    return ScanResult(
        target=script_name,
        is_suspicious=is_suspicious,
        findings_count=len(findings),
        findings=tuple(findings),
    )
