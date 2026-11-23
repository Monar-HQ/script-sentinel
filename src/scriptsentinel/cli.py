"""
CodeSentinel CLI Entry Point
Rich terminal interface for client-side supply-chain auditing.
"""

import sys
import os
import asyncio
import json
import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .auditor import audit_url

console = Console()

BANNER = """
[bold cyan]  ____          _      ____             _   _            _ [/bold cyan]
[bold cyan] / ___|___   __| | ___/ ___|  ___ _ __ | |_(_)_ __   ___| |[/bold cyan]
[bold cyan]| |   / _ \\ / _` |/ _ \\___ \\ / _ \\ '_ \\| __| | '_ \\ / _ \\ |[/bold cyan]
[bold cyan]| |__| (_) | (_| |  __/___) |  __/ | | | |_| | | | |  __/ |[/bold cyan]
[bold cyan] \\____\\___/ \\__,_|\\___|____/ \\___|_| |_|\\__|_|_| |_|\\___|_|[/bold cyan]
[dim] Open-Source Client-Side Supply-Chain Defense & Script Auditor v0.1.0[/dim]
"""

def print_audit_summary(report):
    console.print(BANNER)
    
    # 1. Target Overview Panel
    risk_color = "red" if report.overall_risk in ("CRITICAL", "HIGH") else "green"
    overview_text = f"""
[bold]Target URL:[/bold] {report.target_url}
[bold]HTTP Status:[/bold] {report.status_code}
[bold]Overall Risk Rating:[/bold] [{risk_color} bold]{report.overall_risk}[/{risk_color} bold]
[bold]CSP Health Grade:[/bold] {report.summary.get('csp_grade')} ({report.summary.get('csp_score')}/100)
[bold]Total Scripts Discovered:[/bold] {report.summary.get('total_scripts')} ({report.summary.get('external_scripts')} external, {report.summary.get('inline_scripts')} inline)
    """.strip()
    console.print(Panel(overview_text, title="[bold white]Audit Executive Summary[/bold white]", border_style=risk_color))

    # 2. CSP Findings Table
    csp_findings = report.csp_report.get("findings", [])
    if csp_findings:
        table_csp = Table(title="[bold yellow]CSP Misconfigurations & Vulnerability Exposure[/bold yellow]")
        table_csp.add_column("Rule ID", style="cyan", no_wrap=True)
        table_csp.add_column("Severity", style="bold")
        table_csp.add_column("Finding", style="white")
        table_csp.add_column("Actionable Remediation", style="green")

        for f in csp_findings:
            sev = f["severity"]
            s_color = "red" if sev == "CRITICAL" else ("yellow" if sev == "HIGH" else "blue")
            table_csp.add_row(
                f["rule_id"],
                f"[{s_color}]{sev}[/{s_color}]",
                f["title"],
                f["recommendation"]
            )
        console.print(table_csp)

    # 3. Scripts Inventory & Integrity Table
    table_scripts = Table(title="[bold cyan]JavaScript Inventory, SRI & Behavioral Scan[/bold cyan]")
    table_scripts.add_column("#", style="dim")
    table_scripts.add_column("Origin / Source", style="white")
    table_scripts.add_column("SRI Status", style="bold")
    table_scripts.add_column("SHA-256 (Trunc)", style="dim")
    table_scripts.add_column("Behavioral Threat Findings", style="bold")

    for s in report.scripts:
        idx = str(s.get("index"))
        if s.get("type") == "external":
            src = s.get("url")
            integ = s.get("integrity_audit", {})
            status = integ.get("status", "UNKNOWN")
            st_color = "green" if status == "VERIFIED" else "red"
            sha = integ.get("calculated", {}).get("sha256", "")[:12] + "..."
            
            scanner = s.get("scanner_audit", {})
            findings = scanner.get("findings", [])
            if findings:
                f_desc = ", ".join([f"{f['rule_id']}" for f in findings])
                f_str = f"[bold red]{f_desc}[/bold red]"
            else:
                f_str = "[green]Clean / No Suspicious Patterns[/green]"

            table_scripts.add_row(
                idx,
                src,
                f"[{st_color}]{status}[/{st_color}]",
                sha,
                f_str
            )
        else:
            table_scripts.add_row(
                idx,
                "[dim]<inline script>[/dim]",
                "[dim]N/A[/dim]",
                f"[dim]len={s.get('length')}[/dim]",
                "[green]Clean[/green]"
            )
    console.print(table_scripts)

    # 4. Remediation Quick-Copy
    rem = report.remediation
    if rem:
        rem_panel = f"""
[bold green]Hardened CSP Recommendation:[/bold green]
[dim]{rem.get('hardened_csp')}[/dim]

[bold cyan]Suggested SRI Replacement Tags:[/bold cyan]
"""
        for tag in rem.get("sri_replacement_tags", []):
            rem_panel += f"[dim]{tag['tag']}[/dim]\n"

        console.print(Panel(rem_panel.strip(), title="[bold green]Actionable Remediation Quick-Pack[/bold green]", border_style="green"))

def main():
    parser = argparse.ArgumentParser(description="CodeSentinel: Client-Side Supply-Chain Defense & Script Auditor")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # audit command
    audit_parser = subparsers.add_parser("audit", help="Audit a web page URL for third-party JS risks")
    audit_parser.add_argument("url", help="Target URL (e.g. http://localhost:8100/strict/checkout)")
    audit_parser.add_argument("--baseline", help="Path to baseline hashes JSON file", default=None)
    audit_parser.add_argument("--output", help="Save full report to JSON file", default=None)

    # remediate command
    rem_parser = subparsers.add_parser("remediate", help="Output hardened CSP and SRI tags for a target")
    rem_parser.add_argument("url", help="Target URL")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    baseline_map = {}
    if getattr(args, "baseline", None) and os.path.exists(args.baseline):
        try:
            with open(args.baseline, "r") as f:
                baseline_map = json.load(f)
        except Exception as e:
            console.print(f"[red]Error loading baseline hashes:[/red] {e}")

    if args.command == "audit":
        with console.status(f"[cyan]Auditing target {args.url}...[/cyan]"):
            report = asyncio.run(audit_url(args.url, baseline_map))
        print_audit_summary(report)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2)
            console.print(f"\n[bold green]Full JSON report stashed at:[/bold green] {args.output}")

    elif args.command == "remediate":
        report = asyncio.run(audit_url(args.url, baseline_map))
        rem = report.remediation
        console.print(Panel(rem.get("hardened_csp", ""), title="Hardened CSP Header"))
        for tag in rem.get("sri_replacement_tags", []):
            console.print(tag["tag"])

if __name__ == "__main__":
    main()
