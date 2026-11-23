"""Sigma rule export for ScriptSentinel IOC feeds and audit reports.

The exporter emits one standard Sigma rule that covers every IOC domain and
SHA-256 hash in the feed.  When an audit report is supplied, its CSP, scanner,
and integrity findings are folded into the rule description and tags so the
Sigma rule carries the full audit context.
"""

from __future__ import annotations

import re
import uuid
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from ..iocs.loader import IOCFeed, load_default_feed
from ..models import AuditReport

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RISK_TO_LEVEL: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "ERROR": "medium",
}
_FEED_LEVEL_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low")


def _resolve_feed(feed: IOCFeed | None) -> IOCFeed:
    """Return the supplied feed or the packaged default feed."""
    return load_default_feed() if feed is None else feed


def _sigma_date(report: AuditReport | None, feed: IOCFeed) -> str:
    """Choose a Sigma-compatible ``YYYY-MM-DD`` date."""
    if report is not None:
        candidate = report.timestamp.strip()[:10]
        if _DATE_RE.match(candidate):
            return candidate
    feed_date = feed.as_of.strip()
    if _DATE_RE.match(feed_date):
        return feed_date
    return date.today().isoformat()


def _sigma_id(report: AuditReport | None, feed: IOCFeed) -> str:
    """Build a deterministic UUID for the exported rule."""
    seed = f"scriptsentinel:sigma:{feed.feed_id}:{feed.version}:{feed.digest()}"
    if report is not None:
        seed = f"{seed}:{report.target_url}:{report.overall_risk}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


def _sigma_level(report: AuditReport | None, feed: IOCFeed) -> str:
    """Map feed severity or audit risk to a Sigma level."""
    if report is not None:
        return _RISK_TO_LEVEL.get(report.overall_risk, "medium")
    present = {record.severity.strip().lower() for record in feed.records}
    for level in _FEED_LEVEL_ORDER:
        if level in present:
            return level
    return "medium"


def _audit_finding_ids(report: AuditReport) -> list[str]:
    """Collect CSP, scanner, and integrity rule identifiers from a report."""
    identifiers: set[str] = set()
    for finding in report.csp.findings:
        identifiers.add(finding.rule_id)
    for script in report.scripts:
        if script.scan is not None:
            for scan_finding in script.scan.findings:
                identifiers.add(scan_finding.rule_id)
        if script.integrity is not None:
            for issue in script.integrity.issues:
                identifiers.add(issue.type)
    return sorted(identifiers)


def _audit_script_paths(report: AuditReport) -> list[str]:
    """Collect URL paths of external scripts that produced scan findings."""
    paths: set[str] = set()
    for script in report.scripts:
        if script.url is None or script.scan is None or not script.scan.findings:
            continue
        path = urlparse(script.url).path
        if path:
            paths.add(path)
    return sorted(paths)


def _sigma_detection(report: AuditReport | None, feed: IOCFeed) -> dict[str, Any]:
    """Build a Sigma detection block covering domains, hashes, and findings."""
    domains = sorted(feed.domains())
    hashes = sorted(feed.hashes())

    detection: dict[str, Any] = {}
    selections: list[str] = []

    if domains:
        detection["selection_domains"] = {"cs-host": domains}
        selections.append("selection_domains")
    if hashes:
        detection["selection_hashes"] = {"file_hash": hashes}
        selections.append("selection_hashes")
    if report is not None:
        paths = _audit_script_paths(report)
        if paths:
            detection["selection_audit_urls"] = {"cs-uri|contains": paths}
            selections.append("selection_audit_urls")

    if not selections:
        detection["selection_feed"] = {"cs-host": ["*"]}
        selections.append("selection_feed")

    detection["condition"] = " or ".join(selections)
    return detection


def _sigma_description(report: AuditReport | None, feed: IOCFeed) -> str:
    """Describe the feed contents and, when present, the audit findings."""
    description = (
        f"IOC feed {feed.feed_id} version {feed.version} (as of {feed.as_of}) "
        f"contains {len(feed.domains())} C2 domains and {len(feed.hashes())} SHA-256 hashes."
    )
    if report is not None:
        identifiers = _audit_finding_ids(report)
        findings_text = ", ".join(identifiers) if identifiers else "none"
        description += (
            f" Audit target {report.target_url} rated {report.overall_risk} "
            f"with findings: {findings_text}."
        )
    return description


def export_sigma(report: AuditReport | None = None, feed: IOCFeed | None = None) -> str:
    """Return a standard Sigma YAML rule for the IOC feed and optional audit."""
    resolved = _resolve_feed(feed)
    detection = _sigma_detection(report, resolved)
    finding_ids = _audit_finding_ids(report) if report is not None else []

    tags = [
        "attack.command_and_control",
        "attack.t1071.001",
        "scriptsentinel.ioc.feed",
    ]
    if resolved.domains():
        tags.append("scriptsentinel.ioc.domain")
    if resolved.hashes():
        tags.append("scriptsentinel.ioc.sha256")
    for rule_id in finding_ids:
        tags.append(f"scriptsentinel.finding.{rule_id.lower()}")

    title = (
        f"ScriptSentinel Audit Detection - {report.target_url}"
        if report is not None
        else f"ScriptSentinel IOC Detection - {resolved.feed_id}"
    )

    rule: dict[str, Any] = {
        "title": title,
        "id": _sigma_id(report, resolved),
        "status": "stable",
        "description": _sigma_description(report, resolved),
        "author": "ScriptSentinel Contributors",
        "date": _sigma_date(report, resolved),
        "logsource": {"category": "webserver"},
        "detection": detection,
        "fields": ["cs-host", "cs-uri", "file_hash"],
        "level": _sigma_level(report, resolved),
        "falsepositives": [
            "Benign requests to a listed domain (vendor or CDN reuse).",
            "A SHA-256 match on an unrelated file with identical bytes.",
        ],
        "tags": tags,
    }
    return str(yaml.safe_dump(rule, sort_keys=False, allow_unicode=True))


def write_sigma(
    path: str | Path,
    report: AuditReport | None = None,
    feed: IOCFeed | None = None,
) -> Path:
    """Write the Sigma YAML rule to ``path`` and return the written path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(export_sigma(report=report, feed=feed), encoding="utf-8")
    return target
