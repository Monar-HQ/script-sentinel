"""Tests for Autonomous Surgical Patcher & Rollback Engine."""

from __future__ import annotations

from pathlib import Path

from scriptsentinel.patcher import Patcher, PatchResult


def test_patch_html_file_with_sri_and_csp(tmp_path: Path) -> None:
    """Verifies that patcher injects SRI hashes and CSP meta tags."""
    # Create local script file
    js_file = tmp_path / "bundle.js"
    js_content = b"console.log('production bundle');"
    js_file.write_bytes(js_content)

    html_file = tmp_path / "index.html"
    html_file.write_text(
        """<!DOCTYPE html>
<html>
<head>
  <title>App</title>
  <script src="/bundle.js"></script>
</head>
<body></body>
</html>""",
        encoding="utf-8",
    )

    with Patcher() as patcher:
        res = patcher.patch_html_file(
            html_file,
            hardened_csp="default-src 'self'",
            create_backup=True,
        )

    assert isinstance(res, PatchResult)
    assert res.success is True
    assert res.scripts_patched == 1
    assert res.csp_injected is True
    assert res.backup_path is not None
    assert Path(res.backup_path).is_file()

    # Check updated content
    updated = html_file.read_text(encoding="utf-8")
    assert 'integrity="sha256-' in updated
    assert 'crossorigin="anonymous"' in updated
    assert 'http-equiv="Content-Security-Policy"' in updated

    # Test rollback
    rollback_ok = patcher.rollback(res.backup_path)
    assert rollback_ok is True
    restored = html_file.read_text(encoding="utf-8")
    assert "integrity=" not in restored
    assert not Path(res.backup_path).exists()


def test_patch_nginx_config(tmp_path: Path) -> None:
    """Verifies CSP injection into Nginx configuration."""
    conf_file = tmp_path / "nginx.conf"
    conf_file.write_text(
        """server {
    listen 80;
    server_name example.com;
}""",
        encoding="utf-8",
    )

    with Patcher() as patcher:
        res = patcher.patch_nginx_config(
            conf_file,
            hardened_csp="default-src 'self'; script-src 'self'",
            create_backup=True,
        )

    assert res.success is True
    assert res.csp_injected is True
    updated = conf_file.read_text(encoding="utf-8")
    assert 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'" always;' in updated


def test_patch_nonexistent_file() -> None:
    """Verifies graceful failure when file is missing."""
    with Patcher() as patcher:
        res = patcher.patch_html_file("nonexistent.html")
        assert res.success is False
        assert "File not found" in str(res.error)
