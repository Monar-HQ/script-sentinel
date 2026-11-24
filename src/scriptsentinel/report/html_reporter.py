"""Standalone dark-themed HTML reporter for ScriptSentinel audit reports."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Final

from ..models import AuditReport, CSPAnalysis, Finding, RemediationPack, ScriptAudit

_RISK_PERCENT: Final[dict[str, int]] = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
    "ERROR": 0,
}

_RISK_BADGE_CLASSES: Final[dict[str, str]] = {
    "CRITICAL": "badge-critical",
    "HIGH": "badge-high",
    "MEDIUM": "badge-medium",
    "LOW": "badge-low",
    "ERROR": "badge-error",
}

_RISK_GAUGE_CLASSES: Final[dict[str, str]] = {
    "CRITICAL": "gauge-critical",
    "HIGH": "gauge-high",
    "MEDIUM": "gauge-medium",
    "LOW": "gauge-low",
    "ERROR": "gauge-error",
}

_SEVERITY_CLASSES: Final[dict[str, str]] = {
    "CRITICAL": "badge-critical",
    "HIGH": "badge-high",
    "MEDIUM": "badge-medium",
    "LOW": "badge-low",
    "INFO": "badge-info",
}

_STATUS_CLASSES: Final[dict[str, str]] = {
    "VERIFIED": "status-good",
    "MISSING_SRI": "status-warn",
    "INTEGRITY_MISMATCH": "status-bad",
    "SCRIPT_DRIFT": "status-bad",
    "FETCH_FAILED": "status-bad",
}

_STYLE: Final[str] = """
:root {
  --bg: #04050a;
  --panel: #080a11;
  --panel-alt: #0d1017;
  --border: #232730;
  --text: #fbfaf7;
  --muted: #8892b0;
  --steel: #64748b;
  --accent: #dffc70;
  --badge: #151515;
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif;
  line-height: 1.6;
}
.page-header {
  padding: 2rem clamp(1rem, 4vw, 3rem) 1.25rem;
  border-bottom: 1px solid var(--border);
  border-top: 2px solid var(--accent);
  background: var(--bg);
}
.brand-bar {
  display: flex;
  align-items: center;
  gap: .75rem;
  margin-bottom: 1rem;
}
.brand-mark {
  display: inline-flex;
  width: 28px;
  height: 28px;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--accent);
  color: var(--accent);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: .72rem;
  font-weight: 700;
  letter-spacing: .05em;
}
.brand-meta {
  margin-left: auto;
  color: var(--steel);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: .72rem;
  font-weight: 600;
  letter-spacing: .08em;
}
.eyebrow {
  margin: 0;
  color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: .72rem;
  font-weight: 700;
  letter-spacing: .12em;
  text-transform: uppercase;
}
.page-header h1 {
  margin: 0;
  font-size: clamp(1.4rem, 3vw, 2.1rem);
  font-weight: 700;
  letter-spacing: -.02em;
  word-break: break-word;
}
.meta {
  margin: .6rem 0 0;
  color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: .86rem;
}
.panel {
  max-width: 1200px;
  margin: 1.5rem auto;
  padding: 1.25rem clamp(1rem, 3vw, 2rem);
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 2px;
}
.panel h2 {
  margin: 0 0 .8rem;
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--text);
  border-bottom: 1px solid var(--border);
  padding-bottom: .5rem;
  letter-spacing: -.01em;
}
.panel h3 {
  margin: 1.1rem 0 .5rem;
  font-size: .92rem;
  color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-weight: 700;
  letter-spacing: .08em;
  text-transform: uppercase;
}
.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
  gap: .8rem;
  max-width: 1200px;
  margin: 1.5rem auto;
  padding: 0 clamp(1rem, 3vw, 2rem);
}
.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-top: 2px solid var(--accent);
  border-radius: 2px;
  padding: .9rem 1rem;
}
.card-label {
  margin: 0;
  color: var(--steel);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: .72rem;
  font-weight: 700;
  letter-spacing: .1em;
  text-transform: uppercase;
}
.card-value { margin: .45rem 0 0; font-size: 1.05rem; font-weight: 600; color: var(--text); }
.muted { color: var(--muted); margin: .5rem 0; }
.badge {
  display: inline-flex;
  align-items: center;
  padding: .2rem .55rem;
  border-radius: 2px;
  border: 1px solid var(--border);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: .72rem;
  font-weight: 700;
  letter-spacing: .05em;
  background: var(--badge);
  color: var(--text);
}
.badge-critical { background: var(--accent); color: var(--text); border-color: var(--accent); }
.badge-high { background: var(--badge); color: var(--text); border-color: var(--accent); }
.badge-medium { background: var(--badge); color: var(--text); border-color: var(--steel); }
.badge-low { background: var(--badge); color: var(--text); border-color: var(--border); }
.badge-info { background: var(--badge); color: var(--muted); border-color: var(--border); }
.badge-error { background: var(--badge); color: var(--accent); border-color: var(--accent); }
.status {
  display: inline-flex;
  padding: .18rem .5rem;
  border-radius: 2px;
  border: 1px solid var(--border);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: .72rem;
  font-weight: 600;
  background: var(--badge);
  color: var(--text);
}
.status-good { color: var(--text); border-color: var(--steel); }
.status-warn { color: var(--accent); border-color: var(--accent); }
.status-bad { background: var(--accent); color: var(--text); border-color: var(--accent); }
.status-neutral { color: var(--muted); }
.risk-gauge { display: flex; flex-direction: column; gap: .65rem; }
.gauge-track {
  height: 14px;
  background: var(--badge);
  border: 1px solid var(--border);
  border-radius: 0;
  overflow: hidden;
}
.gauge-fill { height: 100%; }
.gauge-critical { background: var(--accent); }
.gauge-high { background: #9e0a12; }
.gauge-medium { background: #5c0a0e; }
.gauge-low { background: #2f0a0d; }
.gauge-error { background: var(--steel); }
.gauge-scale {
  display: flex;
  justify-content: space-between;
  color: var(--steel);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: .7rem;
  letter-spacing: .06em;
}
.gauge-value { margin: 0; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; min-width: 640px; font-size: .88rem; }
th {
  text-align: left;
  padding: .6rem .7rem;
  background: var(--badge);
  color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: .7rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .07em;
  border-bottom: 1px solid var(--border);
}
td { padding: .6rem .7rem; border-bottom: 1px solid var(--border); vertical-align: top; }
tbody tr:hover { background: var(--panel-alt); }
code { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; font-size: .82rem; color: var(--text); }
.code-block {
  background: #05070d;
  border: 1px solid var(--border);
  border-radius: 2px;
  padding: .8rem 1rem;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-word;
  margin: .4rem 0 .8rem;
}
.code-diff {
  background: #05070d;
  border: 1px solid var(--border);
  border-radius: 2px;
  padding: .85rem;
  margin: .8rem 0;
}
.diff-title { margin: 0 0 .5rem; color: var(--muted); font-size: .82rem; }
.diff-line {
  display: flex;
  gap: .55rem;
  align-items: baseline;
  padding: .25rem .55rem;
  border-radius: 2px;
  margin: .2rem 0;
}
.diff-remove { background: #1a0b0d; color: var(--accent); }
.diff-add { background: var(--panel-alt); color: var(--text); }
.diff-marker { font-weight: 700; }
.error-panel { border-color: var(--accent); }
.error-text { color: var(--accent); margin: .3rem 0; }
.footer {
  max-width: 1200px;
  margin: 0 auto 2rem;
  padding: 0 clamp(1rem, 3vw, 2rem);
  color: var(--steel);
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-size: .78rem;
}
@media (max-width: 720px) {
  .summary-grid { grid-template-columns: 1fr; }
  .page-header { padding: 1.25rem 1rem; }
  .panel { padding: 1rem; margin: 1rem .5rem; }
  th, td { padding: .5rem .45rem; }
  table { min-width: 520px; }
}
"""


def _esc(value: object) -> str:
    """Escape a dynamic value for safe HTML text and attribute insertion."""
    if value is None:
        return "n/a"
    return html.escape(str(value), quote=True)


def _severity_badge(severity: str) -> str:
    """Render a severity badge with the correct CSS class."""
    css_class = _SEVERITY_CLASSES.get(severity, "badge-info")
    return f'<span class="badge {css_class}">{_esc(severity)}</span>'


def _risk_badge(risk: str) -> str:
    """Render an overall risk badge with the correct CSS class."""
    css_class = _RISK_BADGE_CLASSES.get(risk, "badge-error")
    return f'<span class="badge {css_class}">{_esc(risk)}</span>'


def _status_badge(status: str) -> str:
    """Render an integrity status badge with the correct CSS class."""
    css_class = _STATUS_CLASSES.get(status, "status-neutral")
    return f'<span class="status {css_class}">{_esc(status)}</span>'


def _card(label: str, value_html: str) -> str:
    """Render one summary card with escaped label text."""
    return (
        '<div class="card">'
        f'<p class="card-label">{_esc(label)}</p>'
        f'<p class="card-value">{value_html}</p>'
        "</div>"
    )


def _header(report: AuditReport, status_text: str) -> str:
    """Render the page header."""
    return (
        '<header class="page-header">'
        '<div class="brand-bar">'
        '<span class="brand-mark">SS</span>'
        '<span class="eyebrow">ScriptSentinel / client-side supply-chain audit</span>'
        '<span class="brand-meta">MONAR</span>'
        "</div>"
        f"<h1>{_esc(report.target_url)}</h1>"
        f'<p class="meta">Timestamp {_esc(report.timestamp)} &middot; HTTP status {_esc(status_text)}</p>'
        "</header>"
    )


def _summary(report: AuditReport, status_text: str) -> str:
    """Render the executive summary cards."""
    external_count = sum(1 for script in report.scripts if script.kind == "external")
    inline_count = len(report.scripts) - external_count
    cards = [
        _card("Overall Risk", _risk_badge(report.overall_risk)),
        _card("CSP Grade", f"{_esc(report.csp.grade)} ({report.csp.score}/100)"),
        _card("HTTP Status", _esc(status_text)),
        _card(
            "Script Inventory",
            f"{len(report.scripts)} total ({external_count} external, {inline_count} inline)",
        ),
    ]
    return '<section class="summary-grid" aria-label="Audit summary">' + "".join(cards) + "</section>"


def _risk_gauge(report: AuditReport) -> str:
    """Render the overall risk gauge."""
    percent = _RISK_PERCENT.get(report.overall_risk, 0)
    gauge_class = _RISK_GAUGE_CLASSES.get(report.overall_risk, "gauge-error")
    return (
        '<section class="panel">'
        "<h2>Risk Gauge</h2>"
        f'<div class="risk-gauge" role="img" aria-label="Overall risk gauge: {_esc(report.overall_risk)}">'
        f'<div class="gauge-track"><div class="gauge-fill {gauge_class}" style="width:{percent}%"></div></div>'
        "<div class=\"gauge-scale\"><span>LOW</span><span>MEDIUM</span><span>HIGH</span><span>CRITICAL</span></div>"
        f'<p class="gauge-value">{_risk_badge(report.overall_risk)}</p>'
        "</div>"
        "</section>"
    )


def _finding_row(finding: Finding) -> str:
    """Render one CSP finding as an escaped table row."""
    recommendation = finding.recommendation if finding.recommendation else "n/a"
    evidence = finding.evidence if finding.evidence else "n/a"
    return (
        "<tr>"
        f"<td><code>{_esc(finding.rule_id)}</code></td>"
        f"<td>{_severity_badge(finding.severity)}</td>"
        f"<td>{_esc(finding.title)}</td>"
        f"<td>{_esc(finding.description)}</td>"
        f"<td>{_esc(recommendation)}</td>"
        f"<td>{_esc(evidence)}</td>"
        "</tr>"
    )


def _csp_section(csp: CSPAnalysis) -> str:
    """Render CSP directives, findings, and the raw header."""
    parts: list[str] = [
        '<section class="panel">',
        "<h2>CSP Findings</h2>",
        f'<p class="muted">Grade {_esc(csp.grade)} &middot; Score {csp.score}/100</p>',
    ]
    if csp.directives:
        directive_rows = []
        for name in sorted(csp.directives):
            values = " ".join(csp.directives[name])
            directive_rows.append(f"<tr><td><code>{_esc(name)}</code></td><td>{_esc(values)}</td></tr>")
        parts.append("<h3>Directives</h3>")
        parts.append(
            '<div class="table-wrap"><table><thead><tr><th>Directive</th><th>Values</th></tr></thead>'
            "<tbody>" + "".join(directive_rows) + "</tbody></table></div>"
        )
    if csp.findings:
        finding_rows = [_finding_row(finding) for finding in csp.findings]
        parts.append("<h3>Findings</h3>")
        parts.append(
            '<div class="table-wrap"><table><thead><tr><th>Rule</th><th>Severity</th><th>Finding</th>'
            "<th>Description</th><th>Recommendation</th><th>Evidence</th></tr></thead>"
            "<tbody>" + "".join(finding_rows) + "</tbody></table></div>"
        )
    else:
        parts.append('<p class="muted">No CSP misconfigurations detected.</p>')
    if csp.raw:
        parts.append("<h3>Raw Header</h3>")
        parts.append(f'<pre class="code-block"><code>{_esc(csp.raw)}</code></pre>')
    parts.append("</section>")
    return "".join(parts)


def _integrity_status(script: ScriptAudit) -> str:
    """Return the integrity status label for one script."""
    if script.integrity is not None:
        return script.integrity.status
    if script.error is not None:
        return "FETCH_FAILED"
    return "n/a"


def _scan_summary(script: ScriptAudit) -> str:
    """Summarize behavioral scan findings for one script."""
    if script.scan is None:
        return script.error if script.error is not None else "n/a"
    if not script.scan.findings:
        return "clean"
    return ", ".join(f"{finding.rule_id} ({finding.severity})" for finding in script.scan.findings)


def _script_row(script: ScriptAudit) -> str:
    """Render one script inventory row."""
    source = script.url if script.url else "<inline>"
    nonce = script.nonce if script.nonce else "n/a"
    sha256 = (
        script.integrity.calculated.sha256[:12] + "..."
        if script.integrity is not None
        else "n/a"
    )
    return (
        "<tr>"
        f"<td>{script.index}</td>"
        f"<td>{_esc(script.kind)}</td>"
        f"<td><code>{_esc(source)}</code></td>"
        f"<td>{_esc(nonce)}</td>"
        f"<td>{_status_badge(_integrity_status(script))}</td>"
        f"<td><code>{_esc(sha256)}</code></td>"
        f"<td>{_esc(_scan_summary(script))}</td>"
        "</tr>"
    )


def _script_section(scripts: tuple[ScriptAudit, ...]) -> str:
    """Render the script inventory table."""
    parts: list[str] = ['<section class="panel">', "<h2>Script Inventory</h2>"]
    if not scripts:
        parts.append('<p class="muted">No script elements were discovered.</p>')
        parts.append("</section>")
        return "".join(parts)
    rows = [_script_row(script) for script in scripts]
    parts.append(
        '<div class="table-wrap"><table><thead><tr><th>#</th><th>Type</th><th>Source</th><th>Nonce</th>'
        "<th>SRI Status</th><th>SHA-256</th><th>Scan Findings</th></tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody></table></div>"
    )
    parts.append("</section>")
    return "".join(parts)


def _diff_section(scripts: tuple[ScriptAudit, ...]) -> str:
    """Render SRI code diffs and generated replacement tags."""
    diffs: list[str] = []
    for script in scripts:
        integrity = script.integrity
        if integrity is None:
            continue
        declared = integrity.declared_integrity if integrity.declared_integrity else "(missing)"
        tag = script.suggested_tag if script.suggested_tag else integrity.suggested_tag
        diffs.append(
            '<div class="code-diff">'
            f'<p class="diff-title">SRI Code Diff - <code>{_esc(integrity.url)}</code> '
            f"{_status_badge(integrity.status)}</p>"
            '<div class="diff-line diff-remove"><span class="diff-marker">-</span>'
            f'<code>integrity="{_esc(declared)}"</code></div>'
            '<div class="diff-line diff-add"><span class="diff-marker">+</span>'
            f'<code>integrity="{_esc(integrity.calculated.sri_sha256)}"</code></div>'
            "</div>"
            f'<pre class="code-block"><code>{_esc(tag)}</code></pre>'
        )
    if not diffs:
        return (
            '<section class="panel"><h2>SRI Remediation</h2>'
            '<p class="muted">No external scripts with integrity data to remediate.</p></section>'
        )
    return (
        '<section class="panel"><h2>SRI Remediation</h2>'
        '<p class="muted">Replace the declared integrity attribute with the calculated digest, '
        "then paste the generated tag.</p>"
        + "".join(diffs)
        + "</section>"
    )


def _remediation_section(remediation: RemediationPack | None) -> str:
    """Render the remediation pack, server configs, and compliance mapping."""
    parts: list[str] = ['<section class="panel">', "<h2>Remediation Pack</h2>"]
    if remediation is None:
        parts.append('<p class="muted">No remediation pack was generated.</p>')
        parts.append("</section>")
        return "".join(parts)
    parts.append("<h3>Hardened CSP</h3>")
    parts.append(f'<pre class="code-block"><code>{_esc(remediation.hardened_csp)}</code></pre>')
    parts.append("<h3>SRI Replacement Tags</h3>")
    if remediation.sri_replacement_tags:
        for replacement in remediation.sri_replacement_tags:
            parts.append(f'<p class="tag-source"><code>{_esc(replacement.url)}</code></p>')
            parts.append(f'<pre class="code-block"><code>{_esc(replacement.tag)}</code></pre>')
    else:
        parts.append('<p class="muted">No SRI replacement tags were generated.</p>')
    parts.append("<h3>Nginx Configuration</h3>")
    parts.append(f'<pre class="code-block"><code>{_esc(remediation.nginx_config)}</code></pre>')
    parts.append("<h3>Apache Configuration</h3>")
    parts.append(f'<pre class="code-block"><code>{_esc(remediation.apache_config)}</code></pre>')
    if remediation.compliance:
        compliance_rows = []
        for item in remediation.compliance:
            compliance_rows.append(
                f"<tr><td>{_esc(item.standard)}</td><td>{_esc(item.requirement)}</td>"
                f"<td>{_esc(item.status)}</td></tr>"
            )
        parts.append("<h3>Compliance Mapping</h3>")
        parts.append(
            '<div class="table-wrap"><table><thead><tr><th>Standard</th><th>Requirement</th>'
            "<th>Status</th></tr></thead><tbody>" + "".join(compliance_rows) + "</tbody></table></div>"
        )
    parts.append("</section>")
    return "".join(parts)


def _error_section(error: str | None) -> str:
    """Render the audit error panel when an error is present."""
    if error is None:
        return ""
    return (
        '<section class="panel error-panel"><h2>Audit Error</h2>'
        f'<p class="error-text">{_esc(error)}</p></section>'
    )


def render_html(report: AuditReport) -> str:
    """Render a complete, standalone, responsive dark-themed HTML report."""
    status_text = str(report.status_code) if report.status_code is not None else "n/a"
    sections = [
        _header(report, status_text),
        _summary(report, status_text),
        _risk_gauge(report),
        _csp_section(report.csp),
        _script_section(report.scripts),
        _diff_section(report.scripts),
        _remediation_section(report.remediation),
        _error_section(report.error),
    ]
    body = "\n".join(section for section in sections if section)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>ScriptSentinel Audit Report - {_esc(report.target_url)}</title>\n"
        f"<style>\n{_STYLE}\n</style>\n"
        "</head>\n"
        "<body>\n"
        f"{body}\n"
        '<footer class="footer">Generated by ScriptSentinel on '
        f"{_esc(report.timestamp)}.</footer>\n"
        "</body>\n"
        "</html>\n"
    )


def write_html(report: AuditReport, path: str | Path) -> None:
    """Write the rendered HTML audit report to ``path``."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_html(report), encoding="utf-8")

