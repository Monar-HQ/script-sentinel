"""
CSP Misconfiguration Analyzer
Evaluates Content-Security-Policy headers against client-side supply-chain risks.
"""

from typing import Dict, List, Any, Optional

class CSPFinding:
    def __init__(self, rule_id: str, severity: str, title: str, description: str, recommendation: str):
        self.rule_id = rule_id
        self.severity = severity  # CRITICAL, HIGH, MEDIUM, LOW, INFO
        self.title = title
        self.description = description
        self.recommendation = recommendation

    def to_dict(self) -> Dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation
        }

def parse_csp(csp_header: Optional[str]) -> Dict[str, List[str]]:
    if not csp_header:
        return {}
    directives = {}
    tokens = csp_header.strip().split(";")
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        parts = token.split()
        directive_name = parts[0].lower()
        directive_values = parts[1:]
        directives[directive_name] = directive_values
    return directives

def analyze_csp(csp_header: Optional[str]) -> Dict[str, Any]:
    findings: List[CSPFinding] = []
    directives = parse_csp(csp_header)

    if not csp_header:
        findings.append(CSPFinding(
            "CSP-MISSING",
            "CRITICAL",
            "Content-Security-Policy Header Missing",
            "The web application returns no Content-Security-Policy header. Any injected third-party JavaScript executes with full origin authority and can exfiltrate DOM inputs, cookies, and tokens without restriction.",
            "Deploy a strict Content-Security-Policy header enforcing default-src 'self', script-src with cryptographic nonces, and restricted connect-src."
        ))
        return {
            "score": 0,
            "grade": "F",
            "directives": {},
            "findings": [f.to_dict() for f in findings],
            "raw": None
        }

    script_src = directives.get("script-src", directives.get("default-src", []))
    connect_src = directives.get("connect-src", directives.get("default-src", []))

    # 1. Check for unsafe-eval
    if "'unsafe-eval'" in [s.lower() for s in script_src]:
        findings.append(CSPFinding(
            "CSP-UNSAFE-EVAL",
            "CRITICAL",
            "'unsafe-eval' Keyword Permitted in script-src",
            "Allows execution of strings as code via eval(), Function(), and setTimeout(). Skimmers (such as OPTIJACK Variant C) use eval() fallbacks to unpack obfuscated payloads in memory.",
            "Remove 'unsafe-eval' from script-src. Refactor dynamic evaluations to static functions."
        ))

    # 2. Check for unsafe-inline without nonces
    has_nonce = any(s.lower().startswith("'nonce-") for s in script_src)
    has_hash = any(s.lower().startswith("'sha256-") or s.lower().startswith("'sha384-") for s in script_src)
    if "'unsafe-inline'" in [s.lower() for s in script_src] and not (has_nonce or has_hash):
        findings.append(CSPFinding(
            "CSP-UNSAFE-INLINE",
            "CRITICAL",
            "'unsafe-inline' Allowed Without Nonce/Hash",
            "Allows execution of arbitrary inline <script> tags and event handlers, enabling cross-site scripting (XSS) and inline payload execution.",
            "Remove 'unsafe-inline' and replace with per-response cryptographically random nonces (e.g. 'nonce-<random>')."
        ))

    # 3. Check for strict-dynamic risks
    if "'strict-dynamic'" in [s.lower() for s in script_src]:
        if not connect_src or "*" in connect_src:
            findings.append(CSPFinding(
                "CSP-STRICT-DYNAMIC-EXFIL-RISK",
                "HIGH",
                "'strict-dynamic' Enabled Without Restricted connect-src",
                "While 'strict-dynamic' simplifies nonce deployment, any compromised vendor script carrying a valid nonce can dynamically inject and execute child skimmer scripts. Without a strict connect-src, exfiltration succeeds.",
                "Ensure connect-src is strictly locked down to 'self' and pre-approved API endpoints to prevent child scripts from dialing out to rogue C2 servers."
            ))

    # 4. Check connect-src exfiltration exposure
    if not connect_src or "*" in connect_src or "http:" in connect_src or "https:" in connect_src:
        findings.append(CSPFinding(
            "CSP-CONNECT-WILDCARD",
            "CRITICAL",
            "Wildcard or Unrestricted connect-src Exfiltration Vector",
            "connect-src governs fetch(), XMLHttpRequest, navigator.sendBeacon(), and WebSockets. An open connect-src allows compromised third-party scripts to exfiltrate stolen cardholder data and credentials to arbitrary C2 servers.",
            "Restrict connect-src explicitly to 'self' and trusted backend API origins. Do not use wildcards."
        ))

    # 5. Check reporting configuration
    if "report-uri" not in directives and "report-to" not in directives:
        findings.append(CSPFinding(
            "CSP-REPORTING-ABSENT",
            "MEDIUM",
            "CSP Violation Reporting Not Configured",
            "Browser violation reports are not collected. SOC and security teams remain blind when browser-side injection attacks or policy blocks occur.",
            "Add 'report-uri /api/csp-report' or modern Reporting API 'report-to' directives to stream violations into your SIEM/Kafka broker."
        ))

    # Compute Score
    penalty = 0
    for f in findings:
        if f.severity == "CRITICAL":
            penalty += 35
        elif f.severity == "HIGH":
            penalty += 20
        elif f.severity == "MEDIUM":
            penalty += 10
        elif f.severity == "LOW":
            penalty += 5

    score = max(0, 100 - penalty)
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 30:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": score,
        "grade": grade,
        "directives": directives,
        "findings": [f.to_dict() for f in findings],
        "raw": csp_header
    }
