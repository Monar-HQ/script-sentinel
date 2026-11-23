"""Shared typed data models for ScriptSentinel.

All engines return immutable dataclasses so reporters, CLI, and tests can
consume one stable contract.  ``to_dict`` methods produce JSON-safe payloads,
and mapping helpers (``get``, ``__getitem__``) provide backward compatibility.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

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

    def __getitem__(self, item: str) -> object:
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: object = None) -> object:
        try:
            return self[item]
        except KeyError:
            return default

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

    def __getitem__(self, item: str) -> object:
        if item == "findings":
            return [f.to_dict() for f in self.findings]
        if item == "directives":
            return {name: list(values) for name, values in self.directives.items()}
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: object = None) -> object:
        try:
            return self[item]
        except KeyError:
            return default

    def keys(self) -> tuple[str, ...]:
        return ("score", "grade", "directives", "findings", "raw")

    def items(self) -> list[tuple[str, object]]:
        return [(k, self[k]) for k in self.keys()]

    def values(self) -> list[object]:
        return [self[k] for k in self.keys()]

    def __contains__(self, item: object) -> bool:
        return item in self.keys()

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

    def __getitem__(self, item: str) -> object:
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: object = None) -> object:
        try:
            return self[item]
        except KeyError:
            return default

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

    def __getitem__(self, item: str) -> object:
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: object = None) -> object:
        try:
            return self[item]
        except KeyError:
            return default

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

    def __getitem__(self, item: str) -> object:
        if item == "calculated":
            return self.calculated.to_dict()
        if item == "issues":
            return [issue.to_dict() for issue in self.issues]
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: object = None) -> object:
        try:
            return self[item]
        except KeyError:
            return default

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

    def __getitem__(self, item: str) -> object:
        if item == "domains":
            return list(self.domains)
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: object = None) -> object:
        try:
            return self[item]
        except KeyError:
            return default

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

    def __getitem__(self, item: str) -> object:
        if item == "findings":
            return [f.to_dict() for f in self.findings]
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: object = None) -> object:
        try:
            return self[item]
        except KeyError:
            return default

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

    def __getitem__(self, item: str) -> object:
        if item == "type":
            return self.kind
        if item == "integrity_audit":
            return self.integrity.to_dict() if self.integrity else {}
        if item == "scanner_audit":
            return self.scan.to_dict() if self.scan else {}
        if hasattr(self, item):
            val = getattr(self, item)
            return val
        raise KeyError(item)

    def get(self, item: str, default: object = None) -> object:
        try:
            return self[item]
        except KeyError:
            return default

    def keys(self) -> tuple[str, ...]:
        return (
            "index",
            "type",
            "url",
            "nonce",
            "declared_integrity",
            "integrity_audit",
            "scanner_audit",
            "error",
            "suggested_tag",
            "length",
        )

    def items(self) -> list[tuple[str, object]]:
        return [(k, self.get(k)) for k in self.keys() if self.get(k) is not None]

    def __contains__(self, item: object) -> bool:
        return item in self.keys() or hasattr(self, str(item))

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

    def __getitem__(self, item: str) -> object:
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: object = None) -> object:
        try:
            return self[item]
        except KeyError:
            return default

    def to_dict(self) -> dict[str, object]:
        return {"url": self.url, "tag": self.tag}


@dataclass(frozen=True, slots=True)
class ComplianceItem:
    """PCI-DSS mapping entry."""

    standard: str
    requirement: str
    status: str

    def __getitem__(self, item: str) -> object:
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: object = None) -> object:
        try:
            return self[item]
        except KeyError:
            return default

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

    def get(self, item: str, default: object = None) -> object:
        try:
            return self[item]
        except KeyError:
            return default

    def keys(self) -> tuple[str, ...]:
        return (
            "site_url",
            "hardened_csp",
            "sri_replacement_tags",
            "nginx_config",
            "apache_config",
            "compliance",
        )

    def items(self) -> list[tuple[str, object]]:
        return [(k, self[k]) for k in self.keys()]

    def values(self) -> list[object]:
        return [self[k] for k in self.keys()]

    def __contains__(self, item: object) -> bool:
        return item in self.keys()

    def to_dict(self) -> dict[str, object]:
        return {
            "site_url": self.site_url,
            "hardened_csp": self.hardened_csp,
            "sri_replacement_tags": [tag.to_dict() for tag in self.sri_replacement_tags],
            "nginx_config": self.nginx_config,
            "apache_config": self.apache_config,
            "compliance": [item.to_dict() for item in self.compliance],
        }


def _coerce_finding(item: Finding | dict[str, Any]) -> Finding:
    if isinstance(item, Finding):
        return item
    return Finding(
        rule_id=str(item.get("rule_id", "")),
        severity=str(item.get("severity", "INFO")),  # type: ignore[arg-type]
        title=str(item.get("title", "")),
        description=str(item.get("description", "")),
        recommendation=str(item.get("recommendation", "")),
        evidence=str(item.get("evidence", "")),
    )


def _coerce_csp_analysis(item: CSPAnalysis | dict[str, Any] | None) -> CSPAnalysis:
    if isinstance(item, CSPAnalysis):
        return item
    if not item:
        return CSPAnalysis(score=0, grade="F", directives={}, findings=())
    directives_raw = item.get("directives", {})
    directives: dict[str, tuple[str, ...]] = {}
    for k, v in directives_raw.items():
        if isinstance(v, (list, tuple)):
            directives[k] = tuple(str(x) for x in v)
        elif isinstance(v, str):
            directives[k] = tuple(v.split())
        else:
            directives[k] = ()
    findings = tuple(_coerce_finding(f) for f in item.get("findings", ()))
    return CSPAnalysis(
        score=int(item.get("score", 0)),
        grade=str(item.get("grade", "F")),  # type: ignore[arg-type]
        directives=directives,
        findings=findings,
        raw=item.get("raw"),
    )


def _coerce_hash_digests(item: HashDigests | dict[str, Any] | None) -> HashDigests:
    if isinstance(item, HashDigests):
        return item
    d = item or {}
    return HashDigests(
        sha256=str(d.get("sha256", "")),
        sha384=str(d.get("sha384", "")),
        sri_sha256=str(d.get("sri_sha256", "")),
        sri_sha384=str(d.get("sri_sha384", "")),
        byte_count=int(d.get("byte_count", 0)),
    )


def _coerce_script_integrity(
    item: ScriptIntegrityResult | dict[str, Any] | None,
) -> ScriptIntegrityResult | None:
    if isinstance(item, ScriptIntegrityResult) or item is None:
        return item
    issues = tuple(
        iss
        if isinstance(iss, IntegrityIssue)
        else IntegrityIssue(
            type=str(iss.get("type", "")),
            severity=str(iss.get("severity", "INFO")),  # type: ignore[arg-type]
            message=str(iss.get("message", "")),
        )
        for iss in item.get("issues", ())
    )
    return ScriptIntegrityResult(
        url=str(item.get("url", "")),
        status=str(item.get("status", "UNKNOWN")),
        drift_detected=bool(item.get("drift_detected", False)),
        declared_integrity=item.get("declared_integrity"),
        calculated=_coerce_hash_digests(item.get("calculated")),
        issues=issues,
        suggested_tag=str(item.get("suggested_tag", "")),
    )


def _coerce_scan_result(item: ScanResult | dict[str, Any] | None) -> ScanResult | None:
    if isinstance(item, ScanResult) or item is None:
        return item
    findings = tuple(
        f
        if isinstance(f, ScanFinding)
        else ScanFinding(
            rule_id=str(f.get("rule_id", "")),
            name=str(f.get("name", "")),
            severity=str(f.get("severity", "INFO")),  # type: ignore[arg-type]
            matches_count=int(f.get("matches_count", 0)),
            description=str(f.get("description", "")),
            domains=tuple(str(d) for d in f.get("domains", ())),
        )
        for f in item.get("findings", ())
    )
    return ScanResult(
        target=str(item.get("target", "")),
        is_suspicious=bool(item.get("is_suspicious", False)),
        findings_count=int(item.get("findings_count", len(findings))),
        findings=findings,
    )


def _coerce_script_audit(item: ScriptAudit | dict[str, Any], default_index: int = 0) -> ScriptAudit:
    if isinstance(item, ScriptAudit):
        return item
    kind_raw = item.get("type") or item.get("kind") or "external"
    kind: ScriptKind = "inline" if kind_raw == "inline" else "external"
    return ScriptAudit(
        index=int(item.get("index", default_index)),
        kind=kind,
        url=item.get("url"),
        nonce=item.get("nonce"),
        declared_integrity=item.get("declared_integrity"),
        integrity=_coerce_script_integrity(item.get("integrity_audit") or item.get("integrity")),
        scan=_coerce_scan_result(item.get("scanner_audit") or item.get("scan")),
        error=item.get("error"),
        suggested_tag=item.get("suggested_tag"),
        length=item.get("length"),
    )


def _coerce_remediation_pack(
    item: RemediationPack | dict[str, Any] | None, site_url: str = ""
) -> RemediationPack | None:
    if isinstance(item, RemediationPack) or item is None:
        return item
    tags = tuple(
        t
        if isinstance(t, ScriptTagReplacement)
        else ScriptTagReplacement(url=str(t.get("url", "")), tag=str(t.get("tag", "")))
        for t in item.get("sri_replacement_tags", ())
    )
    compliance = tuple(
        c
        if isinstance(c, ComplianceItem)
        else ComplianceItem(
            standard=str(c.get("standard", "")),
            requirement=str(c.get("requirement", "")),
            status=str(c.get("status", "")),
        )
        for c in item.get("compliance", ())
    )
    return RemediationPack(
        site_url=str(item.get("site_url", site_url)),
        hardened_csp=str(item.get("hardened_csp", "")),
        sri_replacement_tags=tags,
        nginx_config=str(item.get("nginx_config", "")),
        apache_config=str(item.get("apache_config", "")),
        compliance=compliance,
    )


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

    @classmethod
    def create(
        cls,
        target_url: str,
        timestamp: str | None = None,
        status_code: int | None = None,
        headers: dict[str, str] | None = None,
        csp: CSPAnalysis | dict[str, Any] | None = None,
        scripts: Sequence[ScriptAudit | dict[str, Any]] = (),
        overall_risk: RiskRating = "LOW",
        summary: dict[str, object] | None = None,
        remediation: RemediationPack | dict[str, Any] | None = None,
        error: str | None = None,
    ) -> AuditReport:
        """Create a typed AuditReport from dataclasses or dictionary inputs."""
        ts = timestamp or datetime.now(timezone.utc).isoformat()
        coerced_csp = _coerce_csp_analysis(csp)
        coerced_scripts = tuple(_coerce_script_audit(s, idx) for idx, s in enumerate(scripts))
        coerced_remediation = _coerce_remediation_pack(remediation, site_url=target_url)

        if summary is None:
            external_count = sum(1 for s in coerced_scripts if s.kind == "external")
            inline_count = len(coerced_scripts) - external_count
            summary = {
                "total_scripts": len(coerced_scripts),
                "external_scripts": external_count,
                "inline_scripts": inline_count,
                "csp_grade": coerced_csp.grade,
                "csp_score": coerced_csp.score,
                "overall_risk": overall_risk,
            }

        return cls(
            target_url=target_url,
            timestamp=ts,
            status_code=status_code,
            headers=dict(headers or {}),
            csp=coerced_csp,
            scripts=coerced_scripts,
            overall_risk=overall_risk,
            summary=dict(summary),
            remediation=coerced_remediation,
            error=error,
        )

    @property
    def csp_report(self) -> dict[str, object]:
        """Backward-compatible dict representation of the CSP analysis."""
        return self.csp.to_dict()

    def __getitem__(self, item: str) -> object:
        if item == "csp":
            return self.csp.to_dict()
        if item == "csp_report":
            return self.csp.to_dict()
        if item == "scripts":
            return [s.to_dict() for s in self.scripts]
        if item == "remediation":
            return self.remediation.to_dict() if self.remediation else None
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)

    def get(self, item: str, default: object = None) -> object:
        try:
            return self[item]
        except KeyError:
            return default

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

