"""Core auditor and pipeline orchestrator.

Fetches a target page, evaluates its Content-Security-Policy, inventories every
``<script>`` element, fetches external dependencies, verifies their cryptographic
integrity, scans their behaviour, and synthesizes an actionable remediation pack.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any, cast
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup, Tag

from .csp_analyzer import analyze_csp
from .integrity import audit_script_integrity
from .models import (
    AuditReport,
    ComplianceItem,
    CSPAnalysis,
    Finding,
    Grade,
    HashDigests,
    IntegrityIssue,
    RemediationPack,
    RiskRating,
    ScanFinding,
    ScanResult,
    ScriptAudit,
    ScriptIntegrityResult,
    ScriptTagReplacement,
    Severity,
)
from .remediate import generate_remediation_pack
from .scanner import scan_script_content

__all__ = ["AuditReport", "audit_url"]


def _utc_timestamp() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _text(payload: Mapping[str, Any], key: str, default: str = "") -> str:
    """Read a string field from a sibling-engine payload."""
    value = payload.get(key, default)
    return value if isinstance(value, str) else default


def _integer(payload: Mapping[str, Any], key: str, default: int = 0) -> int:
    """Read an integer field from a sibling-engine payload."""
    value = payload.get(key, default)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _flag(payload: Mapping[str, Any], key: str, default: bool = False) -> bool:
    """Read a boolean field from a sibling-engine payload."""
    value = payload.get(key, default)
    return value if isinstance(value, bool) else default


def _string_tuple(value: object) -> tuple[str, ...]:
    """Normalise a sequence of strings into an immutable tuple."""
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return ()


def _coerce_finding(item: Mapping[str, Any]) -> Finding:
    """Convert a CSP finding payload into a typed model."""
    severity = cast(Severity, _text(item, "severity", "INFO"))
    return Finding(
        rule_id=_text(item, "rule_id"),
        severity=severity,
        title=_text(item, "title"),
        description=_text(item, "description"),
        recommendation=_text(item, "recommendation"),
        evidence=_text(item, "evidence"),
    )


def _coerce_csp(payload: CSPAnalysis | Mapping[str, Any]) -> CSPAnalysis:
    """Convert CSP analyzer output into a typed ``CSPAnalysis``."""
    if isinstance(payload, CSPAnalysis):
        return payload

    directives_raw = payload.get("directives", {})
    directives: dict[str, tuple[str, ...]] = {}
    if isinstance(directives_raw, Mapping):
        for name, values in directives_raw.items():
            directives[str(name)] = _string_tuple(values)

    findings_raw = payload.get("findings", ())
    findings_sequence = findings_raw if isinstance(findings_raw, (list, tuple)) else ()
    findings = tuple(
        _coerce_finding(item) for item in findings_sequence if isinstance(item, Mapping)
    )

    raw_value = payload.get("raw")
    raw = raw_value if isinstance(raw_value, str) else None

    return CSPAnalysis(
        score=_integer(payload, "score"),
        grade=cast(Grade, _text(payload, "grade", "F")),
        directives=directives,
        findings=findings,
        raw=raw,
    )


def _coerce_integrity(payload: ScriptIntegrityResult | Mapping[str, Any]) -> ScriptIntegrityResult:
    """Convert integrity engine output into a typed ``ScriptIntegrityResult``."""
    if isinstance(payload, ScriptIntegrityResult):
        return payload

    calculated_raw = payload.get("calculated", {})
    calculated_map = calculated_raw if isinstance(calculated_raw, Mapping) else {}
    calculated = HashDigests(
        sha256=_text(calculated_map, "sha256"),
        sha384=_text(calculated_map, "sha384"),
        sri_sha256=_text(calculated_map, "sri_sha256"),
        sri_sha384=_text(calculated_map, "sri_sha384"),
        byte_count=_integer(calculated_map, "byte_count"),
    )

    issues_raw = payload.get("issues", ())
    issues_sequence = issues_raw if isinstance(issues_raw, (list, tuple)) else ()
    issues = tuple(
        IntegrityIssue(
            type=_text(item, "type"),
            severity=cast(Severity, _text(item, "severity", "INFO")),
            message=_text(item, "message"),
        )
        for item in issues_sequence
        if isinstance(item, Mapping)
    )

    declared_raw = payload.get("declared_integrity")
    declared = declared_raw if isinstance(declared_raw, str) else None

    return ScriptIntegrityResult(
        url=_text(payload, "url"),
        status=_text(payload, "status", "UNKNOWN"),
        drift_detected=_flag(payload, "drift_detected"),
        declared_integrity=declared,
        calculated=calculated,
        issues=issues,
        suggested_tag=_text(payload, "suggested_tag"),
    )


def _coerce_scan(payload: ScanResult | Mapping[str, Any]) -> ScanResult:
    """Convert scanner output into a typed ``ScanResult``."""
    if isinstance(payload, ScanResult):
        return payload

    findings_raw = payload.get("findings", ())
    findings_sequence = findings_raw if isinstance(findings_raw, (list, tuple)) else ()
    findings = tuple(
        ScanFinding(
            rule_id=_text(item, "rule_id"),
            name=_text(item, "name"),
            severity=cast(Severity, _text(item, "severity", "INFO")),
            matches_count=_integer(item, "matches_count"),
            description=_text(item, "description"),
            domains=_string_tuple(item.get("domains")),
        )
        for item in findings_sequence
        if isinstance(item, Mapping)
    )

    return ScanResult(
        target=_text(payload, "target"),
        is_suspicious=_flag(payload, "is_suspicious"),
        findings_count=_integer(payload, "findings_count", len(findings)),
        findings=findings,
    )


def _coerce_remediation(payload: RemediationPack | Mapping[str, Any]) -> RemediationPack:
    """Convert remediation engine output into a typed ``RemediationPack``."""
    if isinstance(payload, RemediationPack):
        return payload

    tags_raw = payload.get("sri_replacement_tags", ())
    tags_sequence = tags_raw if isinstance(tags_raw, (list, tuple)) else ()
    tags = tuple(
        ScriptTagReplacement(url=_text(item, "url"), tag=_text(item, "tag"))
        for item in tags_sequence
        if isinstance(item, Mapping)
    )

    compliance_raw = payload.get("compliance", ())
    compliance_sequence = compliance_raw if isinstance(compliance_raw, (list, tuple)) else ()
    compliance = tuple(
        ComplianceItem(
            standard=_text(item, "standard"),
            requirement=_text(item, "requirement"),
            status=_text(item, "status"),
        )
        for item in compliance_sequence
        if isinstance(item, Mapping)
    )

    return RemediationPack(
        site_url=_text(payload, "site_url"),
        hardened_csp=_text(payload, "hardened_csp"),
        sri_replacement_tags=tags,
        nginx_config=_text(payload, "nginx_config"),
        apache_config=_text(payload, "apache_config"),
        compliance=compliance,
    )


def _attribute_text(element: Tag, attribute: str) -> str | None:
    """Read a normalised string attribute from a BeautifulSoup tag."""
    value = element.get(attribute)
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped else None
    if isinstance(value, (list, tuple)):
        joined = " ".join(str(item) for item in value).strip()
        return joined if joined else None
    return None


def _inline_text(element: Tag) -> str:
    """Extract the textual body of an inline ``<script>`` element."""
    return element.get_text()


def _audit_inline_script(index: int, element: Tag, nonce: str | None) -> ScriptAudit:
    """Scan an inline script element."""
    content = _inline_text(element)
    try:
        scan_result = _coerce_scan(scan_script_content(content, f"inline_script_{index}"))
    except Exception as exc:
        return ScriptAudit(
            index=index,
            kind="inline",
            url=None,
            nonce=nonce,
            declared_integrity=None,
            integrity=None,
            scan=None,
            error=f"Failed to scan inline script {index}: {type(exc).__name__}: {exc}",
            suggested_tag=None,
            length=len(content),
        )

    return ScriptAudit(
        index=index,
        kind="inline",
        url=None,
        nonce=nonce,
        declared_integrity=None,
        integrity=None,
        scan=scan_result,
        error=None,
        suggested_tag=None,
        length=len(content),
    )


async def _audit_external_script(
    client: httpx.AsyncClient,
    index: int,
    script_url: str,
    nonce: str | None,
    declared_integrity: str | None,
    baseline_sha256: str | None,
) -> ScriptAudit:
    """Fetch and audit one external script dependency."""
    try:
        response = await client.get(script_url)
    except Exception as exc:
        return ScriptAudit(
            index=index,
            kind="external",
            url=script_url,
            nonce=nonce,
            declared_integrity=declared_integrity,
            integrity=None,
            scan=None,
            error=f"Failed to retrieve script {script_url}: {type(exc).__name__}: {exc}",
            suggested_tag=None,
            length=None,
        )

    if response.status_code >= 400:
        return ScriptAudit(
            index=index,
            kind="external",
            url=script_url,
            nonce=nonce,
            declared_integrity=declared_integrity,
            integrity=None,
            scan=None,
            error=f"HTTP {response.status_code} while fetching script {script_url}",
            suggested_tag=None,
            length=None,
        )

    content = response.content
    try:
        integrity_result = _coerce_integrity(
            audit_script_integrity(script_url, content, declared_integrity, baseline_sha256)
        )
        scan_result = _coerce_scan(scan_script_content(response.text, script_url))
    except Exception as exc:
        return ScriptAudit(
            index=index,
            kind="external",
            url=script_url,
            nonce=nonce,
            declared_integrity=declared_integrity,
            integrity=None,
            scan=None,
            error=f"Failed to audit script {script_url}: {type(exc).__name__}: {exc}",
            suggested_tag=None,
            length=None,
        )

    return ScriptAudit(
        index=index,
        kind="external",
        url=script_url,
        nonce=nonce,
        declared_integrity=declared_integrity,
        integrity=integrity_result,
        scan=scan_result,
        error=None,
        suggested_tag=integrity_result.suggested_tag,
        length=len(content),
    )


def _compute_risk(
    csp: CSPAnalysis, scripts: Sequence[ScriptAudit], parse_error: str | None
) -> RiskRating:
    """Derive overall risk from CSP, integrity, scan, and fetch outcomes."""
    if parse_error is not None:
        return "ERROR"

    critical = False
    high = False
    medium = False

    for csp_finding in csp.findings:
        if csp_finding.severity == "CRITICAL":
            critical = True
        elif csp_finding.severity == "HIGH":
            high = True
        elif csp_finding.severity == "MEDIUM":
            medium = True

    if csp.grade in ("D", "F"):
        high = True

    for script in scripts:
        if script.error is not None:
            high = True
        if script.integrity is not None:
            for issue in script.integrity.issues:
                if issue.severity == "CRITICAL":
                    critical = True
                elif issue.severity == "HIGH":
                    high = True
                elif issue.severity == "MEDIUM":
                    medium = True
        if script.scan is not None:
            for scan_finding in script.scan.findings:
                if scan_finding.severity == "CRITICAL":
                    critical = True
                elif scan_finding.severity == "HIGH":
                    high = True
                elif scan_finding.severity == "MEDIUM":
                    medium = True

    if critical:
        return "CRITICAL"
    if high:
        return "HIGH"
    if medium:
        return "MEDIUM"
    return "LOW"


def _build_summary(
    csp: CSPAnalysis,
    scripts: Sequence[ScriptAudit],
    overall_risk: RiskRating,
    error: str | None,
) -> dict[str, object]:
    """Build the machine-readable executive summary."""
    external_count = sum(1 for script in scripts if script.kind == "external")
    inline_count = sum(1 for script in scripts if script.kind == "inline")
    verified_count = sum(
        1
        for script in scripts
        if script.integrity is not None and script.integrity.status == "VERIFIED"
    )
    integrity_issue_count = sum(
        len(script.integrity.issues) for script in scripts if script.integrity is not None
    )
    suspicious_count = sum(
        1 for script in scripts if script.scan is not None and script.scan.is_suspicious
    )
    fetch_failure_count = sum(1 for script in scripts if script.error is not None)

    summary: dict[str, object] = {
        "total_scripts": len(scripts),
        "external_scripts": external_count,
        "inline_scripts": inline_count,
        "integrity_verified": verified_count,
        "integrity_issues": integrity_issue_count,
        "suspicious_scripts": suspicious_count,
        "fetch_failures": fetch_failure_count,
        "csp_grade": csp.grade,
        "csp_score": csp.score,
        "overall_risk": overall_risk,
    }
    if error is not None:
        summary["error"] = error
    return summary


async def audit_url(
    target_url: str,
    baseline_hashes: dict[str, str] | None = None,
    timeout: float = 10.0,
    transport: httpx.AsyncBaseTransport | None = None,
) -> AuditReport:
    """Run the complete ScriptSentinel audit pipeline for ``target_url``.

    ``transport`` accepts an ``httpx.MockTransport`` (or any async transport) so
    callers and tests can exercise the pipeline without network access.
    """
    timestamp = _utc_timestamp()
    baseline = baseline_hashes or {}

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=True,
        transport=transport,
    ) as client:
        try:
            response = await client.get(target_url)
        except Exception as exc:
            error = f"Failed to fetch {target_url}: {type(exc).__name__}: {exc}"
            csp = _coerce_csp(analyze_csp(None))
            summary = _build_summary(csp, (), "ERROR", error)
            return AuditReport(
                target_url=target_url,
                timestamp=timestamp,
                status_code=None,
                headers={},
                csp=csp,
                scripts=(),
                overall_risk="ERROR",
                summary=summary,
                remediation=None,
                error=error,
            )

        headers: dict[str, str] = dict(response.headers)
        csp_header = response.headers.get("content-security-policy")
        csp = _coerce_csp(analyze_csp(csp_header))
        response_url = getattr(response, "url", None)
        base_url = str(response_url) if response_url is not None else target_url

        scripts: list[ScriptAudit] = []
        parse_error: str | None = None
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            script_elements = list(soup.find_all("script"))
        except Exception as exc:
            parse_error = f"Failed to parse HTML from {target_url}: {type(exc).__name__}: {exc}"
            script_elements = []

        for index, element in enumerate(script_elements):
            src = _attribute_text(element, "src")
            nonce = _attribute_text(element, "nonce")
            declared_integrity = _attribute_text(element, "integrity")

            if src is not None:
                script_url = urljoin(base_url, src)
                script = await _audit_external_script(
                    client,
                    index,
                    script_url,
                    nonce,
                    declared_integrity,
                    baseline.get(script_url),
                )
            else:
                script = _audit_inline_script(index, element, nonce)
            scripts.append(script)

        overall_risk = _compute_risk(csp, scripts, parse_error)

        remediation: RemediationPack | None = None
        remediation_error: str | None = None
        try:
            remediation = _coerce_remediation(
                generate_remediation_pack(
                    target_url, csp.to_dict(), [script.to_dict() for script in scripts]
                )
            )
        except Exception as exc:
            remediation_error = (
                f"Failed to generate remediation for {target_url}: "
                f"{type(exc).__name__}: {exc}"
            )

        error_parts: list[str] = [
            part for part in (parse_error, remediation_error) if part is not None
        ]
        audit_error = "; ".join(error_parts) if error_parts else None
        summary = _build_summary(csp, scripts, overall_risk, audit_error)

        return AuditReport(
            target_url=target_url,
            timestamp=timestamp,
            status_code=response.status_code,
            headers=headers,
            csp=csp,
            scripts=tuple(scripts),
            overall_risk=overall_risk,
            summary=summary,
            remediation=remediation,
            error=audit_error,
        )

