"""Shared typed data models for ScriptSentinel.

All engines return immutable dataclasses so reporters, CLI, and tests can
consume one stable contract.  ``to_dict`` methods produce JSON-safe payloads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
RiskRating = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "ERROR"]
Grade = Literal["A", "B", "C", "D", "F"]
ScriptKind = Literal["external", "inline"]


@dataclass(frozen=True, slots=True)
class Finding:
    """A single security finding from CSP analysis or remediation review."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    recommendation: str = ""
    evidence: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class CSPAnalysis:
    """Structured CSP evaluation result."""

    score: int
    grade: Grade
    directives: dict[str, tuple[str, ...]]
    findings: tuple[Finding, ...]
    raw: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "grade": self.grade,
            "directives": {name: list(values) for name, values in self.directives.items()},
            "findings": [finding.to_dict() for finding in self.findings],
            "raw": self.raw,
        }


@dataclass(frozen=True, slots=True)
class HashDigests:
    """SHA-256 / SHA-384 hex and SRI representations."""

    sha256: str
    sha384: str
    sri_sha256: str
    sri_sha384: str
    byte_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "sha256": self.sha256,
            "sha384": self.sha384,
            "sri_sha256": self.sri_sha256,
            "sri_sha384": self.sri_sha384,
            "byte_count": self.byte_count,
        }


@dataclass(frozen=True, slots=True)
class IntegrityIssue:
    """One integrity or drift issue."""

    type: str
    severity: Severity
    message: str

    def to_dict(self) -> dict[str, object]:
        return {"type": self.type, "severity": self.severity, "message": self.message}


@dataclass(frozen=True, slots=True)
class ScriptIntegrityResult:
    """Integrity verification result for one script."""

    url: str
    status: str
    drift_detected: bool
    declared_integrity: str | None
    calculated: HashDigests
    issues: tuple[IntegrityIssue, ...]
    suggested_tag: str

    def to_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "status": self.status,
            "drift_detected": self.drift_detected,
            "declared_integrity": self.declared_integrity,
            "calculated": self.calculated.to_dict(),
            "issues": [issue.to_dict() for issue in self.issues],
            "suggested_tag": self.suggested_tag,
        }


@dataclass(frozen=True, slots=True)
class ScanFinding:
    """One behavioral finding from JavaScript content."""

    rule_id: str
    name: str
    severity: Severity
    matches_count: int
    description: str
    domains: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "matches_count": self.matches_count,
            "description": self.description,
        }
        if self.domains:
            payload["domains"] = list(self.domains)
        return payload


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Behavioral scan result for one script."""

    target: str
    is_suspicious: bool
    findings_count: int
    findings: tuple[ScanFinding, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "is_suspicious": self.is_suspicious,
            "findings_count": self.findings_count,
            "findings": [finding.to_dict() for finding in self.findings],
        }


@dataclass(frozen=True, slots=True)
class ScriptAudit:
    """Inventory + integrity + behavioral scan for one script element."""

    index: int
    kind: ScriptKind
    url: str | None = None
    nonce: str | None = None
    declared_integrity: str | None = None
    integrity: ScriptIntegrityResult | None = None
    scan: ScanResult | None = None
    error: str | None = None
    suggested_tag: str | None = None
    length: int | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"index": self.index, "type": self.kind}
        for key, value in (
            ("url", self.url),
            ("nonce", self.nonce),
            ("declared_integrity", self.declared_integrity),
            ("integrity_audit", self.integrity.to_dict() if self.integrity else None),
            ("scanner_audit", self.scan.to_dict() if self.scan else None),
            ("error", self.error),
            ("suggested_tag", self.suggested_tag),
            ("length", self.length),
        ):
            if value is not None:
                payload[key] = value
        return payload


@dataclass(frozen=True, slots=True)
class ScriptTagReplacement:
    """A ready-to-paste SRI script tag."""

    url: str
    tag: str

    def to_dict(self) -> dict[str, object]:
        return {"url": self.url, "tag": self.tag}


@dataclass(frozen=True, slots=True)
class ComplianceItem:
    """PCI-DSS mapping entry."""

    standard: str
    requirement: str
    status: str

    def to_dict(self) -> dict[str, object]:
        return {"standard": self.standard, "requirement": self.requirement, "status": self.status}


@dataclass(frozen=True, slots=True)
class RemediationPack:
    """Site-tailored remediation output."""

    site_url: str
    hardened_csp: str
    sri_replacement_tags: tuple[ScriptTagReplacement, ...]
    nginx_config: str
    apache_config: str
    compliance: tuple[ComplianceItem, ...]

    def __getitem__(self, item: str) -> object:
        if item == "sri_replacement_tags":
            return [tag.to_dict() for tag in self.sri_replacement_tags]
        if item == "compliance":
            return [c.to_dict() for c in self.compliance]
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def to_dict(self) -> dict[str, object]:
        return {
            "site_url": self.site_url,
            "hardened_csp": self.hardened_csp,
            "sri_replacement_tags": [tag.to_dict() for tag in self.sri_replacement_tags],
            "nginx_config": self.nginx_config,
            "apache_config": self.apache_config,
            "compliance": [item.to_dict() for item in self.compliance],
        }


@dataclass(frozen=True, slots=True)
class AuditReport:
    """Complete audit result consumed by every reporter."""

    target_url: str
    timestamp: str
    status_code: int | None
    headers: dict[str, str]
    csp: CSPAnalysis
    scripts: tuple[ScriptAudit, ...]
    overall_risk: RiskRating
    summary: dict[str, object] = field(default_factory=dict)
    remediation: RemediationPack | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "target_url": self.target_url,
            "timestamp": self.timestamp,
            "status_code": self.status_code,
            "headers": self.headers,
            "overall_risk": self.overall_risk,
            "summary": self.summary,
            "csp": self.csp.to_dict(),
            "scripts": [script.to_dict() for script in self.scripts],
        }
        if self.remediation is not None:
            payload["remediation"] = self.remediation.to_dict()
        if self.error is not None:
            payload["error"] = self.error
        return payload
