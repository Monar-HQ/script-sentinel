"""ScriptSentinel CLI entry point.

Rich terminal interface for client-side supply-chain auditing, CSP checks,
script-drift monitoring, remediation generation, and detection-rule export.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .auditor import audit_url
from .csp_analyzer import analyze_csp
from .models import AuditReport, CSPAnalysis, RemediationPack

console = Console()

BANNER = """
[bold cyan]  ____          _      ____             _   _            _ [/bold cyan]
[bold cyan] / ___|___   __| | ___/ ___|  ___ _ __ | |_(_)_ __   ___| |[/bold cyan]
[bold cyan]| |   / _ \\ / _` |/ _ \\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\ |[/bold cyan]
[bold cyan]| |__| (_) | (_| |  __/___) |  __/ | | | |_| | | | |  __/ |[/bold cyan]
[bold cyan] \\____\\___/ \\__,_|\\___|____/ \\___|_| |_|\\__|_|_| |_|\\___|_|[/bold cyan]
[dim] Open-Source Client-Side Supply-Chain Defense & Script Auditor v0.1.0[/dim]
"""

_SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "red",
    "HIGH": "yellow",
    "MEDIUM": "blue",
    "LOW": "green",
    "INFO": "cyan",
}


def _severity_color(severity: str) -> str:
    """Return a Rich colour for a severity label."""
    return _SEVERITY_COLORS.get(severity, "white")


def _load_baseline(path: str | None) -> dict[str, str]:
    """Load a URL-to-SHA-256 baseline map from JSON."""
    if not path:
        return {}
    baseline_path = Path(path)
    if not baseline_path.exists():
        console.print(f"[red]Baseline file not found:[/red] {path}")
        return {}
    try:
        raw = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        console.print(f"[red]Unable to read baseline file:[/red] {exc}")
        return {}
    if not isinstance(raw, dict):
        console.print(f"[red]Baseline must be a JSON object:[/red] {path}")
        return {}
    return {str(key): str(value) for key, value in raw.items()}


def print_audit_summary(report: AuditReport) -> None:
    """Render the terminal audit summary for a typed report."""
    console.print(BANNER)

    risk_color = "red" if report.overall_risk in ("CRITICAL", "HIGH") else "green"
    external_count = sum(1 for script in report.scripts if script.kind == "external")
    inline_count = len(report.scripts) - external_count
    overview_text = (
        f"[bold]Target URL:[/bold] {report.target_url}\n"
        f"[bold]HTTP Status:[/bold] {report.status_code}\n"
        f"[bold]Overall Risk Rating:[/bold] [{risk_color} bold]{report.overall_risk}[/{risk_color} bold]\n"
        f"[bold]CSP Health Grade:[/bold] {report.csp.grade} ({report.csp.score}/100)\n"
        f"[bold]Total Scripts Discovered:[/bold] {len(report.scripts)} "
        f"({external_count} external, {inline_count} inline)"
    )
    console.print(
        Panel(
            overview_text,
            title="[bold white]Audit Executive Summary[/bold white]",
            border_style=risk_color,
        )
    )

    if report.csp.findings:
        table_csp = Table(
            title="[bold yellow]CSP Misconfigurations & Vulnerability Exposure[/bold yellow]"
        )
        table_csp.add_column("Rule ID", style="cyan", no_wrap=True)
        table_csp.add_column("Severity", style="bold")
        table_csp.add_column("Finding", style="white")
        table_csp.add_column("Actionable Remediation", style="green")
        for finding in report.csp.findings:
            color = _severity_color(finding.severity)
            table_csp.add_row(
                finding.rule_id,
                f"[{color}]{finding.severity}[/{color}]",
                finding.title,
                finding.recommendation,
            )
        console.print(table_csp)

    table_scripts = Table(
        title="[bold cyan]JavaScript Inventory, SRI & Behavioral Scan[/bold cyan]"
    )
    table_scripts.add_column("#", style="dim")
    table_scripts.add_column("Origin / Source", style="white")
    table_scripts.add_column("SRI Status", style="bold")
    table_scripts.add_column("SHA-256 (Trunc)", style="dim")
    table_scripts.add_column("Behavioral Threat Findings", style="bold")

    for script in report.scripts:
        if script.kind == "external":
            status = script.integrity.status if script.integrity is not None else "UNKNOWN"
            status_color = "green" if status == "VERIFIED" else "red"
            sha = (
                script.integrity.calculated.sha256[:12] + "..."
                if script.integrity is not None
                else "n/a"
            )
            if script.scan is not None and script.scan.findings:
                scan_text = ", ".join(finding.rule_id for finding in script.scan.findings)
                scan_label = f"[bold red]{scan_text}[/bold red]"
            else:
                scan_label = "[green]Clean / No Suspicious Patterns[/green]"
            table_scripts.add_row(
                str(script.index),
                script.url or "",
                f"[{status_color}]{status}[/{status_color}]",
                sha,
                scan_label,
            )
        else:
            table_scripts.add_row(
                str(script.index),
                "[dim]<inline script>[/dim]",
                "[dim]N/A[/dim]",
                f"[dim]len={script.length}[/dim]",
                "[green]Clean[/green]",
            )
    console.print(table_scripts)

    remediation = report.remediation
    if remediation is not None:
        rem_panel = (
            "[bold green]Hardened CSP Recommendation:[/bold green]\n"
            f"[dim]{remediation.hardened_csp}[/dim]\n\n"
            "[bold cyan]Suggested SRI Replacement Tags:[/bold cyan]\n"
        )
        for tag in remediation.sri_replacement_tags:
            rem_panel += f"[dim]{tag.tag}[/dim]\n"
        console.print(
            Panel(
                rem_panel.strip(),
                title="[bold green]Actionable Remediation Quick-Pack[/bold green]",
                border_style="green",
            )
        )


def _render_csp(csp: CSPAnalysis) -> None:
    """Render CSP analysis as a terminal table."""
    console.print(
        Panel(
            f"Grade: [bold]{csp.grade}[/bold]  Score: [bold]{csp.score}/100[/bold]",
            title="CSP Analysis",
            border_style="cyan",
        )
    )
    if not csp.findings:
        console.print("[green]No CSP misconfigurations detected.[/green]")
        return
    table = Table(title="CSP Findings")
    table.add_column("Rule", style="cyan")
    table.add_column("Severity", style="bold")
    table.add_column("Finding", style="white")
    table.add_column("Recommendation", style="green")
    for finding in csp.findings:
        color = _severity_color(finding.severity)
        table.add_row(
            finding.rule_id,
            f"[{color}]{finding.severity}[/{color}]",
            finding.title,
            finding.recommendation,
        )
    console.print(table)


def _render_remediation(remediation: RemediationPack) -> None:
    """Render a remediation pack for terminal copy/paste."""
    console.print(Panel(remediation.hardened_csp, title="Hardened CSP Header"))
    if remediation.sri_replacement_tags:
        console.print("[bold cyan]SRI Replacement Tags[/bold cyan]")
        for tag in remediation.sri_replacement_tags:
            console.print(f"[dim]{tag.tag}[/dim]")
    console.print("[bold green]PCI-DSS v4.0 Compliance Mapping[/bold green]")
    for item in remediation.compliance:
        console.print(f"[cyan]{item.standard}[/cyan] - {item.status}")


def _write_report(report: AuditReport, output: str, fmt: str) -> None:
    """Write an audit report in the selected format."""
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    selected = fmt
    if selected == "terminal":
        suffix = destination.suffix.lower()
        if suffix in (".md", ".markdown"):
            selected = "markdown"
        elif suffix in (".html", ".htm"):
            selected = "html"
        else:
            selected = "json"

    if selected == "json":
        from .report.json_reporter import write_json

        write_json(report, destination)
    elif selected == "markdown":
        from .report.markdown_reporter import write_markdown

        write_markdown(report, destination)
    elif selected == "html":
        from .report.html_reporter import write_html

        write_html(report, destination)
    else:
        console.print(f"[yellow]Unsupported output format:[/yellow] {selected}")
        return
    console.print(f"[bold green]Report written:[/bold green] {destination}")


def _check_csp(target: str) -> CSPAnalysis:
    """Analyze a raw CSP header or fetch the CSP header from a URL."""
    if target.startswith(("http://", "https://")):
        try:
            response = httpx.get(target, timeout=10.0, follow_redirects=True)
        except httpx.HTTPError as exc:
            console.print(f"[red]CSP fetch failed:[/red] {type(exc).__name__}: {exc}")
            return analyze_csp(None)
        header = response.headers.get("content-security-policy")
        return analyze_csp(header)
    return analyze_csp(target)


def _monitor(url: str, baseline_path: str, webhook: str | None) -> int:
    """Audit a URL and report script drift against a pinned baseline."""
    baseline = _load_baseline(baseline_path)
    if not baseline:
        console.print("[yellow]No baseline hashes loaded; drift comparison is empty.[/yellow]")
    report = asyncio.run(audit_url(url, baseline))
    drifted: list[dict[str, Any]] = []
    for script in report.scripts:
        if script.integrity is None:
            continue
        baseline_hash = baseline.get(script.url or "")
        if baseline_hash is not None and script.integrity.drift_detected:
            drifted.append(
                {
                    "url": script.url,
                    "expected_sha256": baseline_hash,
                    "observed_sha256": script.integrity.calculated.sha256,
                    "status": script.integrity.status,
                }
            )
    if drifted:
        console.print(f"[bold red]{len(drifted)} script drift event(s) detected.[/bold red]")
        for event in drifted:
            console.print(
                f"[red]{event['url']}[/red] expected={event['expected_sha256']} "
                f"observed={event['observed_sha256']}"
            )
        if webhook:
            try:
                response = httpx.post(
                    webhook,
                    json={"target": url, "drift": drifted},
                    timeout=10.0,
                )
                console.print(f"[cyan]Webhook status:[/cyan] {response.status_code}")
            except httpx.HTTPError as exc:
                console.print(f"[red]Webhook delivery failed:[/red] {type(exc).__name__}: {exc}")
    else:
        console.print("[green]No script drift detected against the supplied baseline.[/green]")
    return 0


def _export_rules(fmt: str, output: str, url: str | None) -> int:
    """Export Sigma or Suricata rules from the default feed and optional audit."""
    report: AuditReport | None = None
    if url:
        report = asyncio.run(audit_url(url))
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "sigma":
        from .rules.sigma_exporter import write_sigma

        write_sigma(destination, report=report)
    elif fmt == "suricata":
        from .rules.suricata_exporter import write_suricata

        write_suricata(destination, report=report)
    else:
        console.print(f"[red]Unknown rule format:[/red] {fmt}")
        return 1
    console.print(f"[bold green]{fmt.title()} rules written:[/bold green] {destination}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    """Build the argparse CLI parser."""
    parser = argparse.ArgumentParser(
        description="ScriptSentinel: Client-Side Supply-Chain Defense & Script Auditor"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    audit_parser = subparsers.add_parser(
        "audit", help="Audit a web page URL for third-party JavaScript risks"
    )
    audit_parser.add_argument("url", help="Target URL")
    audit_parser.add_argument("--baseline", default=None, help="Path to baseline hashes JSON")
    audit_parser.add_argument("--output", default=None, help="Write report to this path")
    audit_parser.add_argument(
        "--format",
        choices=("terminal", "json", "markdown", "html"),
        default="terminal",
        help="Output format",
    )
    audit_parser.add_argument("--markdown", default=None, help="Write a Markdown report here")
    audit_parser.add_argument("--html", default=None, help="Write an HTML report here")

    csp_parser = subparsers.add_parser(
        "check-csp", help="Analyze a raw CSP header or fetch CSP from a URL"
    )
    csp_parser.add_argument("target", help="URL or raw Content-Security-Policy header")

    monitor_parser = subparsers.add_parser(
        "monitor", help="Monitor script integrity drift against a pinned baseline"
    )
    monitor_parser.add_argument("url", help="Target URL")
    monitor_parser.add_argument("--baseline", required=True, help="Baseline hashes JSON")
    monitor_parser.add_argument("--alert-webhook", default=None, help="Webhook URL for drift alerts")

    remediate_parser = subparsers.add_parser(
        "remediate", help="Generate hardened CSP and SRI tags for a target"
    )
    remediate_parser.add_argument("url", help="Target URL")

    rules_parser = subparsers.add_parser(
        "export-rules", help="Export Sigma or Suricata detection rules"
    )
    rules_parser.add_argument("--format", choices=("sigma", "suricata"), required=True)
    rules_parser.add_argument("--output", required=True, help="Rule file destination")
    rules_parser.add_argument("--url", default=None, help="Optional URL to audit into rules")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        raise SystemExit(1)

    command = cast(str, args.command)
    baseline_map = _load_baseline(getattr(args, "baseline", None))

    if command == "audit":
        url = cast(str, args.url)
        report = asyncio.run(audit_url(url, baseline_map))
        print_audit_summary(report)

        output = getattr(args, "output", None)
        fmt = cast(str, getattr(args, "format", "terminal"))
        if output:
            _write_report(report, cast(str, output), fmt)
        markdown_path = getattr(args, "markdown", None)
        if markdown_path:
            from .report.markdown_reporter import write_markdown

            write_markdown(report, cast(str, markdown_path))
            console.print(f"[bold green]Markdown report written:[/bold green] {markdown_path}")
        html_path = getattr(args, "html", None)
        if html_path:
            from .report.html_reporter import write_html

            write_html(report, cast(str, html_path))
            console.print(f"[bold green]HTML report written:[/bold green] {html_path}")
        return 0

    if command == "check-csp":
        csp = _check_csp(cast(str, args.target))
        _render_csp(csp)
        return 0

    if command == "monitor":
        return _monitor(
            cast(str, args.url),
            cast(str, args.baseline),
            getattr(args, "alert_webhook", None),
        )

    if command == "remediate":
        url = cast(str, args.url)
        report = asyncio.run(audit_url(url, baseline_map))
        remediation = report.remediation
        if remediation is None:
            console.print("[red]No remediation pack generated.[/red]")
            return 1
        _render_remediation(remediation)
        return 0

    if command == "export-rules":
        return _export_rules(
            cast(str, args.format),
            cast(str, args.output),
            getattr(args, "url", None),
        )

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
