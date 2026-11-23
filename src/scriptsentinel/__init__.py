"""CodeSentinel / ScriptSentinel.

Open-source client-side supply-chain defense: audit third-party JavaScript,
detect suspicious dependencies, monitor script integrity, identify CSP
misconfigurations, and generate verifiable remediations.
"""

from __future__ import annotations

from .auditor import audit_url
from .models import (
    AuditReport,
    ComplianceItem,
    CSPAnalysis,
    Finding,
    HashDigests,
    IntegrityIssue,
    RemediationPack,
    ScanFinding,
    ScanResult,
    ScriptAudit,
    ScriptIntegrityResult,
    ScriptTagReplacement,
)
from .remediate import generate_remediation_pack

__version__ = "0.1.0"

__all__ = [
    "AuditReport",
    "CSPAnalysis",
    "ComplianceItem",
    "Finding",
    "HashDigests",
    "IntegrityIssue",
    "RemediationPack",
    "ScanFinding",
    "ScanResult",
    "ScriptAudit",
    "ScriptIntegrityResult",
    "ScriptTagReplacement",
    "__version__",
    "audit_url",
    "generate_remediation_pack",
]
