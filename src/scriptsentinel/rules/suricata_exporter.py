"""Suricata rule export for ScriptSentinel C2 IOC domains.

The exporter emits one HTTP host alert and one DNS query alert for every C2
domain in the feed.  Audit reports can contribute additional flagged domains
discovered by the behavioral scanner.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

from ..iocs.loader import IOCFeed, load_default_feed
from ..models import AuditReport

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _resolve_feed(feed: IOCFeed | None) -> IOCFeed:
    """Return the supplied feed or the packaged default feed."""
    return load_default_feed() if feed is None else feed


def _metadata_date(report: AuditReport | None, feed: IOCFeed) -> str:
    """Choose a Suricata metadata date token (``YYYY_MM_DD``)."""
    if report is not None:
        candidate = report.timestamp.strip()[:10]
        if _DATE_RE.match(candidate):
            return candidate.replace("-", "_")
    feed_date = feed.as_of.strip()
    if _DATE_RE.match(feed_date):
        return feed_date.replace("-", "_")
    return date.today().isoformat().replace("-", "_")


def _report_domains(report: AuditReport) -> set[str]:
    """Collect C2 domains surfaced by scanner findings in the report."""
    domains: set[str] = set()
    for script in report.scripts:
        if script.scan is None:
            continue
        for finding in script.scan.findings:
            domains.update(domain.strip().lower() for domain in finding.domains if domain.strip())
    return domains


def _flagged_domains(report: AuditReport | None, feed: IOCFeed) -> list[str]:
    """Return sorted feed domains plus any scanner-flagged report domains."""
    domains = set(feed.domains())
    if report is not None:
        domains.update(_report_domains(report))
    return sorted(domains)


def _http_rule(domain: str, sid: int, date_token: str, feed_id: str) -> str:
    """Build one Suricata HTTP host alert rule."""
    return (
        f'alert http any any -> any any (msg:"ScriptSentinel C2 HTTP host {domain}"; '
        f'flow:established,to_server; http.host; content:"{domain}"; nocase; endswith; '
        f"sid:{sid}; rev:1; classtype:trojan-activity; "
        f"metadata: created_at {date_token}, updated_at {date_token}, "
        f"source ScriptSentinel, feed {feed_id};)"
    )


def _dns_rule(domain: str, sid: int, date_token: str, feed_id: str) -> str:
    """Build one Suricata DNS query alert rule."""
    return (
        f'alert dns any any -> any any (msg:"ScriptSentinel C2 DNS query {domain}"; '
        f'dns.query; content:"{domain}"; nocase; '
        f"sid:{sid}; rev:1; classtype:trojan-activity; "
        f"metadata: created_at {date_token}, updated_at {date_token}, "
        f"source ScriptSentinel, feed {feed_id};)"
    )


def export_suricata(
    report: AuditReport | None = None,
    feed: IOCFeed | None = None,
    sid_base: int = 100000,
) -> str:
    """Return Suricata HTTP and DNS alert rules for flagged C2 domains."""
    if sid_base < 1:
        raise ValueError("sid_base must be a positive integer")

    resolved = _resolve_feed(feed)
    domains = _flagged_domains(report, resolved)
    date_token = _metadata_date(report, resolved)

    lines: list[str] = []
    for index, domain in enumerate(domains):
        lines.append(_http_rule(domain, sid_base + index, date_token, resolved.feed_id))

    dns_start = sid_base + len(domains)
    for index, domain in enumerate(domains):
        lines.append(_dns_rule(domain, dns_start + index, date_token, resolved.feed_id))

    return "\n".join(lines) + "\n"


def write_suricata(
    path: str | Path,
    report: AuditReport | None = None,
    feed: IOCFeed | None = None,
    sid_base: int = 100000,
) -> Path:
    """Write Suricata rules to ``path`` and return the written path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        export_suricata(report=report, feed=feed, sid_base=sid_base),
        encoding="utf-8",
    )
    return target
