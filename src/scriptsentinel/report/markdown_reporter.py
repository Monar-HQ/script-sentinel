"""Markdown reporter for ScriptSentinel audit reports."""

from __future__ import annotations

from pathlib import Path

from ..models import AuditReport, ScriptAudit


def _cell(value: object) -> str:
    """Render a value as a Markdown table cell with pipe escaping."""
    if value is None:
        return "n/a"
    text = " ".join(str(value).split())
    return text.replace("|", "\\|")


def _scan_summary(script: ScriptAudit) -> str:
    """Summarize behavioral scan findings for one script."""
    if script.scan is None:
        return script.error if script.error is not None else "n/a"
    if not script.scan.findings:
        return "clean"
    return ", ".join(f"{finding.rule_id} ({finding.severity})" for finding in script.scan.findings)


def _integrity_status(script: ScriptAudit) -> str:
    """Return the integrity status label for one script."""
    if script.integrity is not None:
        return script.integrity.status
    if script.error is not None:
        return "FETCH_FAILED"
    return "n/a"


def _collect_actions(report: AuditReport) -> list[str]:
    """Build a deduplicated, ordered developer action checklist."""
    actions: list[str] = []
    seen: set[str] = set()

    def add(action: str) -> None:
        if action not in seen:
            seen.add(action)
            actions.append(action)

    for finding in report.csp.findings:
        add(f"**{finding.severity}** `{finding.rule_id}`: {finding.recommendation or finding.title}")

    for script in report.scripts:
        label = script.url if script.url else f"inline script #{script.index}"
        if script.integrity is not None:
            for issue in script.integrity.issues:
                add(f"Resolve `{issue.type}` on `{label}`: {issue.message}")
        if script.error is not None:
            add(f"Re-fetch or remove `{label}`: {script.error}")
        if script.scan is not None and script.scan.is_suspicious:
            rule_ids = ", ".join(finding.rule_id for finding in script.scan.findings)
            add(f"Review behavioral findings on `{label}`: {rule_ids}")

    if report.remediation is not None:
        add("Deploy the hardened CSP header from the remediation pack.")
        if report.remediation.sri_replacement_tags:
            add("Replace external script tags with the generated SRI tags.")

    has_reporting = "report-uri" in report.csp.directives or "report-to" in report.csp.directives
    if not has_reporting:
        add("Configure CSP violation reporting via `report-uri` or `report-to`.")

    if report.error is not None:
        add(f"Resolve audit error: {report.error}")

    add("Re-run the audit after remediation and pin SHA-256 baselines for drift detection.")
    return actions


def render_markdown(report: AuditReport) -> str:
    """Render a human-readable Markdown audit report."""
    external_count = sum(1 for script in report.scripts if script.kind == "external")
    inline_count = len(report.scripts) - external_count
    status_text = str(report.status_code) if report.status_code is not None else "n/a"
    remediation_text = "available" if report.remediation is not None else "not generated"

    lines: list[str] = [
        "# ScriptSentinel Audit Report",
        "",
        f"**Target:** `{report.target_url}`",
        f"**Timestamp:** {report.timestamp}",
        "",
        "## Executive Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Target URL | {_cell(report.target_url)} |",
        f"| Timestamp | {_cell(report.timestamp)} |",
        f"| HTTP Status | {_cell(status_text)} |",
        f"| Overall Risk | **{_cell(report.overall_risk)}** |",
        f"| CSP Grade | {_cell(report.csp.grade)} ({report.csp.score}/100) |",
        f"| Scripts Audited | {len(report.scripts)} ({external_count} external, {inline_count} inline) |",
        f"| Remediation Pack | {remediation_text} |",
    ]
    if report.error is not None:
        lines.append(f"| Audit Error | {_cell(report.error)} |")

    lines.extend(["", "## CSP Findings", ""])
    if report.csp.raw:
        lines.extend(["**Raw CSP header:**", "", "```http", report.csp.raw, "```", ""])
    if report.csp.directives:
        lines.extend(["| Directive | Values |", "| --- | --- |"])
        for name in sorted(report.csp.directives):
            values = " ".join(report.csp.directives[name])
            lines.append(f"| {_cell(name)} | {_cell(values)} |")
        lines.append("")
    if report.csp.findings:
        lines.extend(
            [
                "| Rule ID | Severity | Finding | Description | Recommendation | Evidence |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in report.csp.findings:
            recommendation = finding.recommendation if finding.recommendation else "n/a"
            evidence = finding.evidence if finding.evidence else "n/a"
            lines.append(
                f"| {_cell(finding.rule_id)} | **{_cell(finding.severity)}** | "
                f"{_cell(finding.title)} | {_cell(finding.description)} | "
                f"{_cell(recommendation)} | {_cell(evidence)} |"
            )
    else:
        lines.append("_No CSP misconfigurations detected._")

    lines.extend(["", "## Script Inventory", ""])
    if report.scripts:
        lines.extend(
            [
                "| # | Type | Source | Nonce | SRI Status | SHA-256 | Scan Findings |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for script in report.scripts:
            source = script.url if script.url else "<inline>"
            nonce = script.nonce if script.nonce else "n/a"
            sha256 = (
                script.integrity.calculated.sha256[:12] + "..."
                if script.integrity is not None
                else "n/a"
            )
            lines.append(
                f"| {script.index} | {_cell(script.kind)} | {_cell(source)} | {_cell(nonce)} | "
                f"{_cell(_integrity_status(script))} | {_cell(sha256)} | {_cell(_scan_summary(script))} |"
            )
    else:
        lines.append("_No script elements were discovered._")

    lines.extend(["", "## Integrity Findings", ""])
    integrity_lines: list[str] = []
    for script in report.scripts:
        label = script.url if script.url else f"inline script #{script.index}"
        if script.integrity is not None:
            for issue in script.integrity.issues:
                integrity_lines.append(f"- **{issue.severity}** `{issue.type}` on `{label}`: {issue.message}")
        if script.error is not None:
            integrity_lines.append(f"- **ERROR** `FETCH_FAILED` on `{label}`: {script.error}")
    if integrity_lines:
        lines.extend(integrity_lines)
    else:
        lines.append("_No integrity issues detected._")

    lines.extend(["", "## Developer Action Checklist", ""])
    actions = _collect_actions(report)
    if actions:
        lines.extend(f"- [ ] {action}" for action in actions)
    else:
        lines.append("- [ ] No action required; current CSP and SRI posture is healthy.")

    lines.extend(["", "## Remediation Pack", ""])
    remediation = report.remediation
    if remediation is None:
        lines.append("_No remediation pack was generated._")
    else:
        lines.extend(["### Hardened CSP", "", "```http", remediation.hardened_csp, "```", ""])
        lines.extend(["### SRI Replacement Tags", ""])
        if remediation.sri_replacement_tags:
            for replacement in remediation.sri_replacement_tags:
                lines.extend([f"**Source:** `{replacement.url}`", "", "```html", replacement.tag, "```", ""])
        else:
            lines.append("_No external scripts require SRI replacement tags._")
        lines.extend(["### Nginx Configuration", "", "```nginx", remediation.nginx_config, "```", ""])
        lines.extend(["### Apache Configuration", "", "```apache", remediation.apache_config, "```", ""])
        lines.extend(
            [
                "### Compliance Mapping",
                "",
                "| Standard | Requirement | Status |",
                "| --- | --- | --- |",
            ]
        )
        for item in remediation.compliance:
            lines.append(f"| {_cell(item.standard)} | {_cell(item.requirement)} | {_cell(item.status)} |")

    return "\n".join(lines) + "\n"


def write_markdown(report: AuditReport, path: str | Path) -> None:
    """Write the rendered Markdown audit report to ``path``."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_markdown(report), encoding="utf-8")

