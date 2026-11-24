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

from . import __version__
from .ai.client import AIClient
from .auditor import audit_url
from .auto import AutoResult, run_auto_pipeline
from .csp_analyzer import analyze_csp
from .env_detector import detect_environment
from .models import AuditReport, CSPAnalysis, RemediationPack
from .network import NetworkPolicy, ScopedClient

console = Console()

BANNER = (
    "[bold bright_yellow]SCRIPTSENTINEL[/bold bright_yellow]\n"
    f"[dim]MONAR / CLIENT-SIDE SUPPLY-CHAIN DEFENSE / v{__version__}[/dim]"
)

_SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "bold white",
    "LOW": "white",
    "INFO": "dim",
}

_RISK_ORDER: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
    "ERROR": 5,
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
        raise ValueError(f"Baseline file not found: {path}")
    try:
        raw = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("Unable to read baseline file") from exc
    if not isinstance(raw, dict):
        raise ValueError("Baseline must be a JSON object")
    import re

    if not raw or not all(
        isinstance(k, str) and isinstance(v, str) and re.fullmatch(r"[a-fA-F0-9]{64}", v)
        for k, v in raw.items()
    ):
        raise ValueError("Baseline must contain URL to SHA-256 hex mappings")
    return {key: value.lower() for key, value in raw.items()}


def print_audit_summary(report: AuditReport) -> None:
    """Render the terminal audit summary for a typed report."""
    console.print(BANNER)

    risk_color = "red" if report.overall_risk in ("CRITICAL", "HIGH", "ERROR") else "white"
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
        table_csp = Table(title="[bold red]CSP Misconfigurations[/bold red]")
        table_csp.add_column("Rule ID", style="bold red", no_wrap=True)
        table_csp.add_column("Severity", style="bold")
        table_csp.add_column("Finding", style="white")
        table_csp.add_column("Actionable Remediation", style="dim")
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
        title="[bold white]JavaScript Inventory / SRI / Behavioral Scan[/bold white]"
    )
    table_scripts.add_column("#", style="dim")
    table_scripts.add_column("Origin / Source", style="white")
    table_scripts.add_column("SRI Status", style="bold")
    table_scripts.add_column("SHA-256 (Trunc)", style="dim")
    table_scripts.add_column("Behavioral Threat Findings", style="bold")

    for script in report.scripts:
        if script.kind == "external":
            status = script.integrity.status if script.integrity is not None else "UNKNOWN"
            status_color = "white" if status == "VERIFIED" else "red"
            sha = (
                script.integrity.calculated.sha256[:12] + "..."
                if script.integrity is not None
                else "n/a"
            )
            if script.scan is not None and script.scan.findings:
                scan_text = ", ".join(finding.rule_id for finding in script.scan.findings)
                scan_label = f"[bold red]{scan_text}[/bold red]"
            else:
                scan_label = "[white]CLEAN[/white]"
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
                "[white]CLEAN[/white]",
            )
    console.print(table_scripts)

    remediation = report.remediation
    if remediation is not None:
        rem_panel = (
            "[bold red]Hardened CSP Recommendation[/bold red]\n"
            f"[dim]{remediation.hardened_csp}[/dim]\n\n"
            "[bold white]Suggested SRI Replacement Tags[/bold white]\n"
        )
        for tag in remediation.sri_replacement_tags:
            rem_panel += f"[dim]{tag.tag}[/dim]\n"
        console.print(
            Panel(
                rem_panel.strip(),
                title="[bold red]Actionable Remediation Quick-Pack[/bold red]",
                border_style="red",
            )
        )


def _render_csp(csp: CSPAnalysis) -> None:
    """Render CSP analysis as a terminal table."""
    grade_color = "white" if csp.grade in ("A", "B") else "red"
    console.print(
        Panel(
            f"Grade: [{grade_color} bold]{csp.grade}[/{grade_color} bold]  "
            f"Score: [bold]{csp.score}/100[/bold]",
            title="CSP Analysis",
            border_style="red",
        )
    )
    if not csp.findings:
        console.print("[white]No CSP misconfigurations detected.[/white]")
        return
    table = Table(title="[bold white]CSP Findings[/bold white]")
    table.add_column("Rule", style="bold red")
    table.add_column("Severity", style="bold")
    table.add_column("Finding", style="white")
    table.add_column("Recommendation", style="dim")
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
    console.print(Panel(remediation.hardened_csp, title="Hardened CSP Header", border_style="red"))
    if remediation.sri_replacement_tags:
        console.print("[bold white]SRI Replacement Tags[/bold white]")
        for tag in remediation.sri_replacement_tags:
            console.print(f"[dim]{tag.tag}[/dim]")
    console.print("[bold red]PCI-DSS v4.0 Compliance Mapping[/bold red]")
    for item in remediation.compliance:
        console.print(f"[red]{item.standard}[/red] - {item.status}")


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
        console.print(f"[red]Unsupported output format:[/red] {selected}")
        return
    console.print(f"[bold white]Report written:[/bold white] {destination}")


def _check_csp(target: str) -> CSPAnalysis:
    """Analyze a raw CSP header or fetch the CSP header from a URL."""
    if target.startswith(("http://", "https://")):

        async def fetch() -> httpx.Response:
            async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
                response = await ScopedClient(client, NetworkPolicy.create([target])).get(target)
                response.raise_for_status()
                return response

        response = asyncio.run(fetch())
        header = response.headers.get("content-security-policy")
        return analyze_csp(header)
    return analyze_csp(target)


def _monitor(url: str, baseline_path: str, webhook: str | None) -> int:
    """Audit a URL and report script drift against a pinned baseline."""
    baseline = _load_baseline(baseline_path)
    if not baseline:
        console.print("[red]No baseline hashes loaded; drift comparison is empty.[/red]")
    report = asyncio.run(audit_url(url, baseline, network_policy=NetworkPolicy.create([url])))
    if report.error or report.overall_risk == "ERROR" or any(s.error for s in report.scripts):
        console.print("[red]Monitoring incomplete: fetch or analysis failed.[/red]")
        return 2
    observed = {s.url for s in report.scripts if s.kind == "external"}
    if observed != set(baseline):
        console.print("[red]Script inventory changed against the baseline.[/red]")
        return 1
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
                console.print(f"[white]Webhook status:[/white] {response.status_code}")
            except httpx.HTTPError as exc:
                console.print(f"[red]Webhook delivery failed:[/red] {type(exc).__name__}: {exc}")
        return 1
    console.print("[white]No script drift detected against the supplied baseline.[/white]")
    return 0


def _export_rules(fmt: str, output: str, url: str | None) -> int:
    """Export Sigma or Suricata rules from the default feed and optional audit."""
    report: AuditReport | None = None
    if url:
        report = asyncio.run(audit_url(url, network_policy=NetworkPolicy.create([url])))
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
    console.print(f"[bold white]{fmt.title()} rules written:[/bold white] {destination}")
    return 0


def _audit_exit_code(report: AuditReport, fail_on: str, baseline: dict[str, str]) -> int:
    """Return a CI-friendly exit code for audit thresholds."""
    if report.error or report.overall_risk == "ERROR" or any(s.error for s in report.scripts):
        return 2
    if fail_on == "none":
        return 0
    if fail_on == "drift":
        for script in report.scripts:
            if script.integrity is None:
                continue
            if baseline.get(script.url or "") is not None and script.integrity.drift_detected:
                return 1
        return 0
    threshold = _RISK_ORDER.get(fail_on.upper())
    if threshold is None:
        return 0
    return 1 if _RISK_ORDER.get(report.overall_risk, 0) >= threshold else 0


def _render_auto(result: AutoResult) -> None:
    """Render high-impact terminal presentation for autonomous execution."""
    console.print(BANNER)
    if result.summary.get("ai_error"):
        console.print(str(result.summary["ai_error"]), markup=False)

    risk_color = "red" if result.overall_risk in ("CRITICAL", "HIGH", "ERROR") else "white"
    env = result.env_profile

    # 1. Environment & Architecture Recon
    env_info = (
        f"[bold]Target:[/bold] {result.target} "
        f"({'[dim]Remote[/dim]' if env.is_remote else '[dim]Local Workspace[/dim]'})\n"
        f"[bold]Web Server / Reverse Proxy:[/bold] [bold red]{env.primary_server}[/bold red]\n"
        f"[bold]Application Framework:[/bold] {env.framework or 'Static / Generic'}\n"
        f"[bold]Discovered HTML Files:[/bold] {len(env.html_files)}\n"
        f"[bold]Total Scripts Discovered:[/bold] {env.total_scripts} "
        f"([bold red]{len(env.scripts_needing_sri)}[/bold red] needing Subresource Integrity)"
    )
    console.print(
        Panel(
            env_info,
            title="[bold white]Environment & Architecture Recon[/bold white]",
            border_style="white",
        )
    )

    # 2. Audit & Vulnerability Assessment
    audit = result.audit_report
    audit_info = (
        f"[bold]Overall Risk Rating:[/bold] [{risk_color} bold]{result.overall_risk}[/{risk_color} bold]\n"
        f"[bold]CSP Health Grade:[/bold] {audit.csp.grade} ({audit.csp.score}/100)\n"
        f"[bold]CSP Violations Flagged:[/bold] {len(audit.csp.findings)}"
    )
    console.print(
        Panel(
            audit_info,
            title="[bold white]Client-Side Security Audit[/bold white]",
            border_style=risk_color,
        )
    )

    # 3. Frontier Multi-Provider AI Intelligence
    if result.ai_analysis:
        ai = result.ai_analysis
        ai_summary = (
            f"[bold white]Executive Summary:[/bold white]\n{ai.executive_summary}\n\n"
            f"[bold white]Threat Vector Analysis:[/bold white]\n{ai.threat_narrative}\n\n"
            f"[bold white]Synthesized Smart CSP:[/bold white]\n[dim]{ai.smart_csp}[/dim]"
        )
        console.print(
            Panel(
                ai_summary,
                title="[bold bright_yellow]Optional AI Advisory[/bold bright_yellow]",
                border_style="bold red",
            )
        )

    # 4. Patch Execution
    if result.patches:
        table_patches = Table(title="[bold red]Surgical Automated Patch Log[/bold red]")
        table_patches.add_column("File Target", style="bold white")
        table_patches.add_column("SRI Patched", justify="right", style="bold red")
        table_patches.add_column("CSP Injected", style="bold")
        table_patches.add_column("Diff Summary", style="dim")

        for patch in result.patches:
            table_patches.add_row(
                Path(patch.file_path).name,
                str(patch.scripts_patched),
                "[green]Yes[/green]" if patch.csp_injected else "[dim]No[/dim]",
                patch.diff_summary,
            )
        console.print(table_patches)
        console.print(
            f"[bold red]Hardened:[/bold red] Applied [bold]{result.total_patches_applied}[/bold] surgical modifications with rollback safety.\n"
        )
    elif not env.is_remote and len(env.scripts_needing_sri) > 0:
        console.print(
            "[dim]Review artifact provenance, then use [bold white]scriptsentinel propose[/bold white] to prepare an inspectable SRI diff. Application and deployment approval stay explicit.[/dim]\n"
        )


def _render_setup(target: str) -> None:
    """Run diagnostic environment inspection."""
    console.print(BANNER)
    env = detect_environment(target)
    with AIClient() as ai_client:
        diag = (
            f"[bold]Target:[/bold] {env.target}\n"
            f"[bold]Mode:[/bold] {'Remote HTTP' if env.is_remote else 'Local Workspace'}\n"
            f"[bold]Detected Web Server:[/bold] [bold red]{env.primary_server}[/bold red]\n"
            f"[bold]Detected Framework:[/bold] {env.framework or 'Static / None'}\n"
            f"[bold]Discovered Configuration Files:[/bold] {len(env.config_files)}\n"
            f"[bold]Discovered HTML Files:[/bold] {len(env.html_files)}\n"
            f"[bold]Total Script Elements:[/bold] {env.total_scripts}\n"
            f"[bold]Scripts Missing SRI:[/bold] [bold red]{len(env.scripts_needing_sri)}[/bold red]\n"
            f"[bold]Existing CSP:[/bold] {'Found' if env.existing_csp else 'None (Exposed)'}\n\n"
            f"[bold white]AI Reasoning Engine:[/bold white] "
            f"{'[bold white]Configured (authentication untested)[/bold white] (' + ai_client.config.provider + ': ' + ai_client.config.model + ')' if ai_client.is_available else '[dim]Unconfigured (Deterministic Only)[/dim]'}"
        )
        console.print(
            Panel(
                diag,
                title="[bold white]ScriptSentinel Environment & Diagnostics Wizard[/bold white]",
                border_style="red" if not ai_client.is_available else "white",
            )
        )


def _build_parser() -> argparse.ArgumentParser:
    """Build the argparse CLI parser."""
    parser = argparse.ArgumentParser(
        description="ScriptSentinel: Client-Side Supply-Chain Defense & Script Auditor"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    from .cli_v1 import register

    register(subparsers)

    # auto
    auto_parser = subparsers.add_parser(
        "auto", help="Autonomous environment recon, security audit, AI triage, and patching"
    )
    auto_parser.add_argument(
        "target", nargs="?", default=".", help="Target URL or local directory (default: .)"
    )
    auto_parser.add_argument(
        "--ai",
        action="store_true",
        help="Opt in to sending minimized evidence to the configured AI provider",
    )
    auto_parser.add_argument(
        "--fix", action="store_true", help="Apply surgical automated patches to local files"
    )
    auto_parser.add_argument(
        "--no-backup", action="store_true", help="Disable .bak backup generation"
    )
    auto_parser.add_argument(
        "--api-key", default=None, help="Custom API key for Anthropic/OpenAI/OpenRouter"
    )
    auto_parser.add_argument(
        "--api-base", default=None, help="Custom base URL for OpenAI-compatible endpoint"
    )
    auto_parser.add_argument(
        "--provider",
        default=None,
        choices=("anthropic", "openai", "openrouter", "gemini", "custom"),
        help="AI provider",
    )
    auto_parser.add_argument("--model", default=None, help="AI model name")
    auto_parser.add_argument("--json", action="store_true", help="Output raw JSON format")

    # fix
    fix_parser = subparsers.add_parser(
        "fix", help="Surgically patch local workspace: inject SRI tags and harden CSP headers"
    )
    fix_parser.add_argument(
        "target", nargs="?", default=".", help="Target local directory or file (default: .)"
    )
    fix_parser.add_argument(
        "--no-backup", action="store_true", help="Disable .bak backup generation"
    )
    fix_parser.add_argument("--api-key", default=None, help="Custom API key")
    fix_parser.add_argument("--api-base", default=None, help="Custom base URL")
    fix_parser.add_argument(
        "--provider", default=None, choices=("anthropic", "openai", "openrouter", "custom")
    )
    fix_parser.add_argument("--model", default=None, help="AI model name")

    # setup
    setup_parser = subparsers.add_parser(
        "setup", help="Inspect local environment and configured provider metadata"
    )
    setup_parser.add_argument(
        "target", nargs="?", default=".", help="Target workspace directory (default: .)"
    )

    audit_parser = subparsers.add_parser(
        "audit", help="Audit a web page URL for third-party JavaScript risks"
    )
    audit_parser.add_argument("url", help="Target URL")
    audit_parser.add_argument(
        "--allow-origin",
        action="append",
        default=[],
        help="Additional exact authorized resource origin",
    )
    audit_parser.add_argument(
        "--allow-private", action="store_true", help="Authorize private/local destination addresses"
    )
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
    audit_parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical", "drift"),
        default="none",
        help="Exit non-zero when risk meets this threshold or script drift is detected",
    )

    csp_parser = subparsers.add_parser(
        "check-csp", help="Analyze a raw CSP header or fetch CSP from a URL"
    )
    csp_parser.add_argument("target", help="URL or raw Content-Security-Policy header")

    monitor_parser = subparsers.add_parser(
        "monitor", help="Monitor script integrity drift against a pinned baseline"
    )
    monitor_parser.add_argument("url", help="Target URL")
    monitor_parser.add_argument("--baseline", required=True, help="Baseline hashes JSON")
    monitor_parser.add_argument(
        "--alert-webhook", default=None, help="Webhook URL for drift alerts"
    )

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
    observe_parser = subparsers.add_parser(
        "observe-har", help="Import an authorized single-page browser HAR offline"
    )
    observe_parser.add_argument("file")
    observe_parser.add_argument("--page-origin", required=True)
    for name in ("propose", "validate-proposal", "apply-proposal"):
        p = subparsers.add_parser(name, help="Reviewed local SRI proposal workflow")
        p.add_argument("root", help="Approved local workspace")
        p.add_argument("--trusted-baseline", required=True)
        p.add_argument("--proposal", required=True, help="Proposal JSON path")
        if name == "propose":
            p.add_argument("--file", required=True, help="Workspace-relative HTML file")
        if name == "apply-proposal":
            p.add_argument(
                "--approve",
                action="store_true",
                help="Confirm diff and application compatibility reviewed",
            )
    return parser


def _main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        raise SystemExit(1)

    command = cast(str, args.command)
    from .cli_v1 import execute

    handled = execute(args)
    if handled is not None:
        return handled
    if command == "observe-har":
        from .observation import inventory_har

        try:
            result = inventory_har(Path(args.file), args.page_origin)
            print(json.dumps(result, indent=2))
            return 0
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            console.print(str(exc), markup=False)
            return 2
    if command in ("propose", "validate-proposal", "apply-proposal"):
        from . import proposals

        try:
            root = Path(args.root)
            trusted = Path(args.trusted_baseline)
            destination = Path(args.proposal)
            if command == "propose":
                proposal = proposals.propose(root, args.file, trusted)
                with destination.open("x", encoding="utf-8") as stream:
                    json.dump(proposal, stream, indent=2)
                console.print(proposal["diff"], markup=False)
            else:
                proposal = json.loads(destination.read_text(encoding="utf-8"))
                if command == "validate-proposal":
                    from .validation import isolated

                    console.print_json(data=isolated(root, proposal, trusted))
                else:
                    from .validation import apply_reviewed

                    recovery_copy = apply_reviewed(
                        root,
                        proposal,
                        trusted,
                        Path(str(destination) + ".receipt.json"),
                        args.approve,
                    )
                    console.print(
                        f"Applied reviewed proposal. Recovery copy: {recovery_copy}", markup=False
                    )
            return 0
        except (OSError, ValueError, KeyError, TypeError) as exc:
            console.print(str(exc), markup=False)
            return 2
    try:
        baseline_map = _load_baseline(getattr(args, "baseline", None))
    except ValueError as exc:
        console.print(str(exc), markup=False)
        return 2
    if command == "fix" or (command == "auto" and getattr(args, "fix", False)):
        console.print(
            "Use propose, validate-proposal and apply-proposal --approve with a trusted baseline."
        )
        return 2

    if command == "auto":
        target = cast(str, getattr(args, "target", "."))
        apply_fix = bool(getattr(args, "fix", False))
        backup = not bool(getattr(args, "no_backup", False))
        ai_cfg = AIClient.auto_detect(
            api_key=getattr(args, "api_key", None),
            api_base=getattr(args, "api_base", None),
            provider=getattr(args, "provider", None),
            model=getattr(args, "model", None),
        )
        res = run_auto_pipeline(
            target=target, apply_fix=apply_fix, backup=backup, ai_config=ai_cfg if args.ai else None
        )
        if getattr(args, "json", False):
            console.print_json(data=res.to_dict())
        else:
            _render_auto(res)
        return 1 if res.overall_risk in ("CRITICAL", "ERROR") else 0

    if command == "fix":
        target = cast(str, getattr(args, "target", "."))
        backup = not bool(getattr(args, "no_backup", False))
        ai_cfg = AIClient.auto_detect(
            api_key=getattr(args, "api_key", None),
            api_base=getattr(args, "api_base", None),
            provider=getattr(args, "provider", None),
            model=getattr(args, "model", None),
        )
        res = run_auto_pipeline(target=target, apply_fix=True, backup=backup, ai_config=ai_cfg)
        _render_auto(res)
        return (
            0
            if any(p.success for p in res.patches) or len(res.env_profile.scripts_needing_sri) == 0
            else 1
        )

    if command == "setup":
        target = cast(str, getattr(args, "target", "."))
        if target.startswith(("https://", "http://")):
            console.print("Use audit URL with explicit authorized origin scope for remote targets.")
            return 2
        _render_setup(target)
        return 0

    if command == "audit":
        url = cast(str, args.url)
        report = asyncio.run(
            audit_url(
                url,
                baseline_map,
                network_policy=NetworkPolicy.create([url, *args.allow_origin], args.allow_private),
            )
        )
        output = getattr(args, "output", None)
        fmt = cast(str, getattr(args, "format", "terminal"))
        if fmt == "json" and not output:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print_audit_summary(report)
        if output:
            _write_report(report, cast(str, output), fmt)
        markdown_path = getattr(args, "markdown", None)
        if markdown_path:
            from .report.markdown_reporter import write_markdown

            write_markdown(report, cast(str, markdown_path))
            console.print(f"[bold white]Markdown report written:[/bold white] {markdown_path}")
        html_path = getattr(args, "html", None)
        if html_path:
            from .report.html_reporter import write_html

            write_html(report, cast(str, html_path))
            console.print(f"[bold white]HTML report written:[/bold white] {html_path}")
        fail_on = cast(str, getattr(args, "fail_on", "none"))
        return _audit_exit_code(report, fail_on, baseline_map)

    if command == "check-csp":
        try:
            csp = _check_csp(cast(str, args.target))
        except (OSError, ValueError, httpx.HTTPError):
            console.print(
                "CSP retrieval failed or was outside destination scope. No policy conclusion was made."
            )
            return 2
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
        report = asyncio.run(
            audit_url(url, baseline_map, network_policy=NetworkPolicy.create([url]))
        )
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


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return _main(argv)
    except (OSError, ValueError, httpx.HTTPError, ImportError) as exc:
        console.print(f"Unable to complete: {exc}", markup=False)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
