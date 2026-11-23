"""Content-Security-Policy parsing and risk analysis for ScriptSentinel."""

from __future__ import annotations

from .models import CSPAnalysis, Finding, Grade, Severity

__all__ = ["analyze_csp", "parse_csp"]

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
        directives.setdefault(name, []).extend(values)
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
    directives = parse_csp(csp_header)
    findings: list[Finding] = []

    if not csp_header:
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

    has_nonce = any(value.startswith("'nonce-") for value in script_lower)
    has_hash = any(
        value.startswith("'sha256-") or value.startswith("'sha384-") for value in script_lower
    )
    if "'unsafe-inline'" in script_lower and not (has_nonce or has_hash):
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
    if "'strict-dynamic'" in script_lower and (
        not connect_values or "*" in connect_values
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

    if not connect_values or "*" in connect_values or any(
        value in {"http:", "https:"} for value in connect_values
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
