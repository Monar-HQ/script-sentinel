"""Autonomous Security & Remediation Agent for ScriptSentinel.

Provides frontier AI reasoning for:
1. Deep Threat Analysis: Explains skimmer behavior, DOM harvest vectors, and blast radius.
2. Smart Policy Synthesis: Crafts surgical Content-Security-Policies tailored to real application dependencies.
3. Automated Patch Formulation: Preserves legitimate vendor tags (Stripe, PayPal, Google) while sealing exfiltration routes.
4. Executive CISO Advisory: Generates high-impact briefings with PCI-DSS v4.0 compliance evidence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..env_detector import EnvironmentProfile
from ..models import AuditReport
from .client import AIClient


@dataclass(frozen=True, slots=True)
class AIAuditAnalysis:
    """Structured response from the AI Security Agent."""
    threat_narrative: str
    smart_csp: str
    remediation_recommendations: list[str]
    compliance_assessment: str
    executive_summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat_narrative": self.threat_narrative,
            "smart_csp": self.smart_csp,
            "remediation_recommendations": self.remediation_recommendations,
            "compliance_assessment": self.compliance_assessment,
            "executive_summary": self.executive_summary,
        }


SYSTEM_PROMPT = """You are ScriptSentinel's Autonomous Security & Remediation Agent, developed by MONAR.
You are an elite AppSec and Client-Side Supply-Chain Defense Engineer.
You analyze third-party JavaScript risks, Subresource Integrity (SRI) drift, Content-Security-Policy (CSP) bypasses, Magecart formjackers, and OPTIJACK / CVE-2026-132224 attack vectors.

Your objectives:
1. Deliver ruthless technical precision. Name specific DOM manipulation APIs, event listeners, and exfiltration mechanisms.
2. Formulate surgical, hardened CSP headers and SRI tags that eliminate exfiltration vectors without breaking legitimate business functionality.
3. Map every risk directly to PCI-DSS v4.0 Requirement 6.4.3 (script authorization and integrity) and Requirement 11.6.1 (tamper-detection mechanisms).
4. Tone: Authoritative, direct, technical, zero marketing fluff.
"""


class AIAgent:
    """Security agent orchestrating intelligent triage and patch generation."""

    def __init__(self, client: AIClient | None = None) -> None:
        self.client = client or AIClient()

    @property
    def is_available(self) -> bool:
        return self.client.is_available

    def analyze_audit(
        self,
        report: AuditReport,
        env: EnvironmentProfile | None = None,
    ) -> AIAuditAnalysis:
        """Executes full AI-assisted triage on an audit report and environment."""
        if not self.is_available:
            raise RuntimeError("AI Client is not available or unconfigured.")

        target_url = getattr(report, "target_url", getattr(report, "url", "unknown"))
        prompt = f"""Target URL/Resource: {target_url}
HTTP Status: {report.status_code}
CSP Health Grade: {report.csp.grade} (Score: {report.csp.score}/100)
Raw CSP Header: {report.csp.raw}
CSP Violations Flagged:
{json.dumps([f.to_dict() for f in report.csp.findings], indent=2)}

Discovered JavaScript Inventory & Behavioral Analysis:
{json.dumps([s.to_dict() for s in report.scripts], indent=2)}

Environment Profile:
{json.dumps(env.to_dict() if env else {}, indent=2)}

Task:
Perform a comprehensive client-side security assessment.
Return a valid JSON object with the following exact keys:
{{
  "threat_narrative": "Detailed technical analysis of the attack vectors, DOM exfiltration risk, and skimmer behavior.",
  "smart_csp": "A complete, production-ready, hardened Content-Security-Policy header string tailored to this target.",
  "remediation_recommendations": ["Action item 1", "Action item 2", ...],
  "compliance_assessment": "PCI-DSS v4.0 Req 6.4.3 and 11.6.1 compliance evaluation.",
  "executive_summary": "High-level 2-3 sentence executive summary for CISO/Security Directors."
}}
Output only valid, raw JSON. Do not include markdown code block formatting around the JSON if possible.
"""

        raw_response = self.client.generate(SYSTEM_PROMPT, prompt).strip()

        # Strip potential markdown fences
        if raw_response.startswith("```"):
            lines = raw_response.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            raw_response = "\n".join(lines).strip()

        try:
            parsed = json.loads(raw_response)
            return AIAuditAnalysis(
                threat_narrative=str(parsed.get("threat_narrative", "")),
                smart_csp=str(parsed.get("smart_csp", "")),
                remediation_recommendations=list(parsed.get("remediation_recommendations", [])),
                compliance_assessment=str(parsed.get("compliance_assessment", "")),
                executive_summary=str(parsed.get("executive_summary", "")),
            )
        except json.JSONDecodeError:
            # Fallback if model output wasn't strict JSON
            return AIAuditAnalysis(
                threat_narrative=raw_response,
                smart_csp=report.remediation.hardened_csp if report.remediation else "default-src 'self'",
                remediation_recommendations=["Review flagged CSP misconfigurations", "Enforce Subresource Integrity"],
                compliance_assessment="Requires immediate remediation to comply with PCI-DSS v4.0.",
                executive_summary="Target exhibits client-side supply-chain exposure.",
            )

    def explain_threat(self, rule_id: str, context: dict[str, Any]) -> str:
        """Explains a single detection rule finding and its exploitation mechanism."""
        if not self.is_available:
            return f"Rule {rule_id}: Exploitation mechanism analysis requires an active AI engine."

        user_prompt = f"""Explain rule ID: {rule_id}
Context:
{json.dumps(context, indent=2)}

Explain how adversaries exploit this vector in client-side supply-chain attacks (e.g. Magecart or OPTIJACK).
Keep it under 150 words, cold, technical, and precise.
"""
        return self.client.generate(SYSTEM_PROMPT, user_prompt)
