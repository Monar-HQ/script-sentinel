"""Tests for Environment & Architecture Reconnaissance Engine."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from scriptsentinel.env_detector import (
    DiscoveredScript,
    EnvironmentProfile,
    detect_environment,
)


def test_discovered_script_model() -> None:
    """Verifies DiscoveredScript dataclass and serialization."""
    s = DiscoveredScript(
        source_file="index.html",
        src="https://cdn.example.com/app.js",
        is_inline=False,
        has_sri=False,
        declared_sri=None,
        line_number=12,
    )
    d = s.to_dict()
    assert d["src"] == "https://cdn.example.com/app.js"
    assert d["has_sri"] is False
    assert d["line_number"] == 12


def test_detect_environment_local_workspace(tmp_path: Path) -> None:
    """Verifies local directory inspection for HTML files, scripts, and Nginx config."""
    # Setup test workspace
    html_file = tmp_path / "index.html"
    html_file.write_text(
        """<!DOCTYPE html>
<html>
<head>
  <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
  <script src="https://cdn.example.com/checkout.js"></script>
  <script src="/local.js" integrity="sha256-abc"></script>
  <script>console.log("inline");</script>
</head>
<body></body>
</html>""",
        encoding="utf-8",
    )

    nginx_conf = tmp_path / "nginx.conf"
    nginx_conf.write_text("server { listen 80; }", encoding="utf-8")

    env = detect_environment(str(tmp_path))
    assert isinstance(env, EnvironmentProfile)
    assert env.is_remote is False
    assert env.primary_server == "nginx"
    assert len(env.html_files) == 1
    assert env.total_scripts == 3
    # 1 external script has no SRI
    assert len(env.scripts_needing_sri) == 1
    assert env.scripts_needing_sri[0].src == "https://cdn.example.com/checkout.js"
    assert env.existing_csp == "default-src 'self'"


def test_detect_environment_remote_mock() -> None:
    """Verifies remote URL inspection with mock httpx responses."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            headers={
                "server": "cloudflare",
                "content-type": "text/html; charset=utf-8",
                "content-security-policy": "default-src 'self'; script-src 'self'",
            },
            text="""<html><head>
                <script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"></script>
            </head></html>""",
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        env = detect_environment("https://test.monar.io", http_client=client)
    assert env.is_remote is True
    assert env.primary_server == "cloudflare"
    assert env.existing_csp == "default-src 'self'; script-src 'self'"
    assert env.total_scripts == 1
    assert len(env.scripts_needing_sri) == 1


def test_detect_environment_nonexistent_raises() -> None:
    """Verifies FileNotFoundError on invalid local path."""
    with pytest.raises(FileNotFoundError):
        detect_environment("nonexistent_path_xyz_12345")
