"""Content-Security-Policy parsing and risk analysis for ScriptSentinel."""

from __future__ import annotations

import base64
import binascii
import re

from .models import CSPAnalysis, Finding, Grade, Severity

__all__ = ["analyze_csp", "parse_csp"]


def _valid_hash_source(value: str) -> bool:
    match = re.fullmatch(r"'sha(256|384|512)-([A-Za-z0-9+/_-]+={0,2})'", value)
    if not match:
        return False
    algorithm, encoded = match.groups()
    encoded = encoded.replace("-", "+").replace("_", "/")
    try:
        return (
            len(base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True))
            == int(algorithm) // 8
        )
    except binascii.Error:
        return False


_SEVERITY_PENALTY: dict[Severity, int] = {
    "CRITICAL": 35,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 0,
}


def parse_csp(csp_header: str | None) -> dict[str, list[str]]:
    """Parse a CSP header into directive names mapped to token lists."""
    if not csp_header:
        return {}

    directives: dict[str, list[str]] = {}
    for raw_segment in csp_header.strip().split(";"):
        segment = raw_segment.strip()
        if not segment:
            continue
        parts = segment.split()
        if not parts:
            continue
        name = parts[0].lower()
        values = parts[1:]
        # CSP processing keeps the first occurrence of a directive.
        directives.setdefault(name, values)
    return directives


def _grade_for_score(score: int) -> Grade:
    """Map a 0-100 security score to a letter grade."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 50:
        return "C"
    if score >= 30:
        return "D"
    return "F"


def _finding(
    rule_id: str,
    severity: Severity,
    title: str,
    description: str,
    recommendation: str,
    evidence: str = "",
) -> Finding:
    """Build a typed CSP finding."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        recommendation=recommendation,
        evidence=evidence,
    )


def analyze_csp(csp_header: str | None) -> CSPAnalysis:
    """Analyze a CSP header and return a typed ``CSPAnalysis``."""
    if csp_header and "," in csp_header:
        policies = [
            analyze_csp(policy.strip()) for policy in csp_header.split(",") if policy.strip()
        ]
        if not policies:
            return analyze_csp(None)
        common = set.intersection(*({f.rule_id for f in policy.findings} for policy in policies))
        shared = tuple(f for f in policies[0].findings if f.rule_id in common)
        score = max(0, 100 - sum(_SEVERITY_PENALTY[f.severity] for f in shared))
        return CSPAnalysis(
            score=score,
            grade=_grade_for_score(score),
            directives={},
            raw=csp_header,
            findings=(
                _finding(
                    "CSP-MULTIPLE-POLICIES",
                    "INFO",
                    "Multiple CSP policies evaluated independently",
                    "Browsers enforce each policy independently. Only posture signals shared by all policies are included in the aggregate grade.",
                    "Host/path intersections, browser versions and runtime compatibility still require browser validation. Directives are never merged.",
                ),
                *shared,
            ),
        )
    directives = parse_csp(csp_header)
    findings: list[Finding] = []

    if not csp_header or not csp_header.strip():
        findings.append(
            _finding(
                "CSP-MISSING",
                "CRITICAL",
                "Content-Security-Policy Header Missing",
                (
                    "The application returns no Content-Security-Policy header. Injected "
                    "third-party JavaScript executes with full origin authority and can "
                    "exfiltrate DOM inputs, cookies, and tokens without restriction."
                ),
                (
                    "Deploy a strict CSP enforcing default-src 'self', script-src with "
                    "cryptographic nonces, and a restricted connect-src."
                ),
            )
        )
        return CSPAnalysis(
            score=0,
            grade="F",
            directives={},
            findings=tuple(findings),
            raw=None,
        )

    script_src = directives.get("script-src", directives.get("default-src", []))
    script_lower = [value.lower() for value in script_src]

    if "'unsafe-eval'" in script_lower:
        findings.append(
            _finding(
                "CSP-UNSAFE-EVAL",
                "CRITICAL",
                "'unsafe-eval' Permitted in script-src",
                (
                    "Allows execution of strings as code via eval(), Function(), and "
                    "setTimeout(). Skimmers such as OPTIJACK Variant C use eval() "
                    "fallbacks to unpack obfuscated payloads in memory."
                ),
                "Remove 'unsafe-eval' from script-src and refactor dynamic evaluation.",
                "'unsafe-eval'",
            )
        )

    element_src = directives.get("script-src-elem", script_src)
    element_lower = [value.lower() for value in element_src]
    has_nonce = any(re.fullmatch(r"'nonce-[a-zA-Z0-9+/_-]+={0,2}'", value) for value in element_src)
    has_hash = any(_valid_hash_source(value) for value in element_src)
    if (
        "script-src-elem" not in directives
        and "script-src" not in directives
        and "default-src" not in directives
    ) or any(v in ("*", "http:", "https:", "data:") for v in element_lower):
        findings.append(
            _finding(
                "CSP-SCRIPT-UNRESTRICTED",
                "HIGH",
                "Script elements have broad or absent source restrictions",
                "The effective script element source list does not narrowly limit script origins.",
                "Use reviewed nonce/hash policies and validate legitimate script loading in isolation.",
            )
        )
    if "'unsafe-inline'" in element_lower and not (has_nonce or has_hash):
        findings.append(
            _finding(
                "CSP-UNSAFE-INLINE",
                "CRITICAL",
                "'unsafe-inline' Allowed Without Nonce/Hash",
                (
                    "Allows arbitrary inline <script> tags and event handlers, enabling "
                    "inline payload execution and cross-site scripting."
                ),
                "Remove 'unsafe-inline' and deploy per-response cryptographic nonces.",
                "'unsafe-inline'",
            )
        )

    connect_values = directives.get("connect-src", directives.get("default-src", []))
    attr_sources = directives.get("script-src-attr", script_src)
    attr_has_crypto = any(
        re.fullmatch(r"'nonce-[a-zA-Z0-9+/_-]+={0,2}'", value) or _valid_hash_source(value)
        for value in attr_sources
    )
    if "'unsafe-inline'" in [value.lower() for value in attr_sources] and not attr_has_crypto:
        findings.append(
            _finding(
                "CSP-UNSAFE-ATTR",
                "HIGH",
                "Inline event handlers are broadly allowed",
                "The effective script attribute source list permits inline event handlers.",
                "Move handlers to reviewed scripts or use a tested event-handler hash policy.",
            )
        )
    if "'strict-dynamic'" in script_lower and (
        ("connect-src" not in directives and "default-src" not in directives)
        or "*" in connect_values
    ):
        findings.append(
            _finding(
                "CSP-STRICT-DYNAMIC-RISK",
                "HIGH",
                "'strict-dynamic' Enabled Without Restricted connect-src",
                (
                    "A compromised vendor script holding a valid nonce can dynamically "
                    "inject child loader scripts; an open connect-src lets those children "
                    "exfiltrate to adversary infrastructure."
                ),
                "Restrict connect-src to 'self' and approved API origins.",
                "'strict-dynamic'",
            )
        )

    if (
        ("connect-src" not in directives and "default-src" not in directives)
        or "*" in connect_values
        or any(value in {"http:", "https:"} for value in connect_values)
    ):
        findings.append(
            _finding(
                "CSP-CONNECT-WILDCARD",
                "CRITICAL",
                "Missing or Wildcard connect-src Exfiltration Vector",
                (
                    "connect-src governs fetch(), XMLHttpRequest, sendBeacon(), and "
                    "WebSockets. Missing or wildcard values permit exfiltration of "
                    "cardholder data and credentials to arbitrary C2 servers."
                ),
                "Set connect-src explicitly to 'self' and trusted backend API origins.",
                "*" if "*" in connect_values else "connect-src absent",
            )
        )

    if "report-uri" not in directives and "report-to" not in directives:
        findings.append(
            _finding(
                "CSP-REPORTING-ABSENT",
                "MEDIUM",
                "CSP Violation Reporting Not Configured",
                (
                    "Browser violation reports are not collected, leaving SOC and "
                    "security teams blind to browser-side injection attacks and policy blocks."
                ),
                "Add report-uri or report-to to stream violations into the SIEM.",
                "no report-uri/report-to",
            )
        )

    penalty = sum(_SEVERITY_PENALTY[finding.severity] for finding in findings)
    score = max(0, 100 - penalty)
    grade = _grade_for_score(score)

    typed_directives = {name: tuple(values) for name, values in directives.items()}
    return CSPAnalysis(
        score=score,
        grade=grade,
        directives=typed_directives,
        findings=tuple(findings),
        raw=csp_header,
    )
