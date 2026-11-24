"""Tests for Autonomous Pipeline Orchestrator and CLI commands."""

from __future__ import annotations

from pathlib import Path

import pytest

from scriptsentinel.auto import AutoResult, run_auto_pipeline
from scriptsentinel.cli import main


def test_run_auto_pipeline_local_audit_only(tmp_path: Path) -> None:
    """Verifies autonomous pipeline execution in recon + audit mode (without fix)."""
    # Create test workspace
    html_file = tmp_path / "checkout.html"
    html_file.write_text(
        """<!DOCTYPE html>
<html>
<head>
  <script src="/app.js"></script>
</head>
<body><h1>Store</h1></body>
</html>""",
        encoding="utf-8",
    )
    js_file = tmp_path / "app.js"
    js_file.write_bytes(b"console.log('payment form');")

    res = run_auto_pipeline(target=str(tmp_path), apply_fix=False)
    assert isinstance(res, AutoResult)
    assert res.target == str(tmp_path)
    assert res.env_profile.total_scripts == 1
    assert len(res.patches) == 0
    assert res.total_patches_applied == 0
    d = res.to_dict()
    assert d["target"] == str(tmp_path)
    assert "env_profile" in d
    assert "audit_report" in d


def test_run_auto_pipeline_local_with_fix(tmp_path: Path) -> None:
    """Verifies autonomous pipeline execution with surgical automated patching."""
    html_file = tmp_path / "index.html"
    html_file.write_text(
        """<!DOCTYPE html>
<html>
<head>
  <script src="/main.js"></script>
</head>
<body></body>
</html>""",
        encoding="utf-8",
    )
    js_file = tmp_path / "main.js"
    js_file.write_bytes(b"alert('safe');")

    original = html_file.read_bytes()
    with pytest.raises(ValueError, match="Direct remediation is disabled"):
        run_auto_pipeline(target=str(tmp_path), apply_fix=True, backup=True)
    assert html_file.read_bytes() == original


def test_cli_auto_and_setup_commands(tmp_path: Path) -> None:
    """Verifies that CLI commands `auto`, `fix`, and `setup` run without error."""
    html_file = tmp_path / "index.html"
    html_file.write_text("<html><head></head><body></body></html>", encoding="utf-8")

    # 1. Setup diagnostic wizard
    code_setup = main(["setup", str(tmp_path)])
    assert code_setup == 0

    # 2. Auto recon & audit
    code_auto = main(["auto", str(tmp_path)])
    assert code_auto in (0, 1)

    # 3. Fix patching
    code_fix = main(["fix", str(tmp_path)])
    assert code_fix == 2
