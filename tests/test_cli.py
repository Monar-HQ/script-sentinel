"""Unit tests for ScriptSentinel CLI entry point."""

from __future__ import annotations

import json
from pathlib import Path

from scriptsentinel.cli import main
from scriptsentinel.models import (
    AuditReport,
    CSPAnalysis,
    Finding,
    RemediationPack,
    ScriptTagReplacement,
)


def test_cli_help(capsys):
    import sys
    sys.argv = ["scriptsentinel"]
    try:
        main()
    except SystemExit as e:
        assert e.code == 1

    captured = capsys.readouterr()
    assert "usage:" in captured.out or "usage:" in captured.err


def test_cli_remediate(monkeypatch, capsys):
    import sys

    dummy_report = AuditReport.create(
        target_url="https://checkout.test.com",
        status_code=200,
        csp=CSPAnalysis(score=0, grade="F", directives={}, findings=()),
        scripts=(),
        overall_risk="LOW",
        remediation=RemediationPack(
            site_url="https://checkout.test.com",
            hardened_csp="default-src 'self'; script-src 'self' 'nonce-{NONCE}'",
            sri_replacement_tags=(
                ScriptTagReplacement(
                    url="https://checkout.test.com/app.js",
                    tag='<script src="https://checkout.test.com/app.js" integrity="sha256-123"></script>',
                ),
            ),
            nginx_config="...",
            apache_config="...",
            compliance=(),
        ),
    )

    async def mock_audit(*args, **kwargs):
        return dummy_report

    import scriptsentinel.cli as cli_mod
    monkeypatch.setattr(cli_mod, "audit_url", mock_audit)

    sys.argv = ["scriptsentinel", "remediate", "https://checkout.test.com"]
    main()

    captured = capsys.readouterr()
    assert "Hardened CSP Header" in captured.out
    assert "default-src 'self'" in captured.out
    assert "integrity=\"sha256-123\"" in captured.out


def test_cli_audit_with_outputs(monkeypatch, tmp_path: Path, capsys):
    import sys

    dummy_report = AuditReport.create(
        target_url="https://checkout.test.com",
        status_code=200,
        csp=CSPAnalysis(
            score=30,
            grade="D",
            directives={"default-src": ("'self'",)},
            findings=(
                Finding("CSP-MISSING", "CRITICAL", "Missing header", "Description", "Fix it"),
            ),
        ),
        scripts=(),
        overall_risk="HIGH",
        remediation=RemediationPack(
            site_url="https://checkout.test.com",
            hardened_csp="default-src 'self'",
            sri_replacement_tags=(),
            nginx_config="",
            apache_config="",
            compliance=(),
        ),
    )

    async def mock_audit(*args, **kwargs):
        return dummy_report

    import scriptsentinel.cli as cli_mod
    monkeypatch.setattr(cli_mod, "audit_url", mock_audit)

    json_path = tmp_path / "report.json"
    md_path = tmp_path / "report.md"

    sys.argv = [
        "scriptsentinel",
        "audit",
        "https://checkout.test.com",
        "--output",
        str(json_path),
        "--markdown",
        str(md_path),
    ]
    main()

    assert json_path.exists()
    saved_json = json.loads(json_path.read_text(encoding="utf-8"))
    assert saved_json["target_url"] == "https://checkout.test.com"
    assert saved_json["overall_risk"] == "HIGH"

    assert md_path.exists()
    saved_md = md_path.read_text(encoding="utf-8")
    assert "# ScriptSentinel Audit Report" in saved_md
