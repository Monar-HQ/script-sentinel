"""Environment & Reconnaissance Engine for ScriptSentinel.

Automatically inspects local directories or remote targets to detect:
- Web servers & reverse proxies (Nginx, Apache, Caddy, Cloudflare, Vercel)
- Application frameworks (Next.js, Node/Express, Django, FastAPI, Flask, static HTML)
- HTML files and embedded script tags requiring SRI attributes
- Existing Content-Security-Policy configurations (headers or <meta> tags)
- Prime remediation targets for automated patching
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup


@dataclass(frozen=True, slots=True)
class DiscoveredScript:
    """Represents a discovered script in local files or remote DOM."""
    source_file: str
    src: str | None
    is_inline: bool
    has_sri: bool
    declared_sri: str | None
    line_number: int | None = None
    raw_tag: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_file": self.source_file,
            "src": self.src,
            "is_inline": self.is_inline,
            "has_sri": self.has_sri,
            "declared_sri": self.declared_sri,
            "line_number": self.line_number,
        }


@dataclass(frozen=True, slots=True)
class EnvironmentProfile:
    """Represents the discovered runtime, architecture, and remediation targets."""
    target: str
    is_remote: bool
    primary_server: str
    framework: str | None
    config_files: tuple[str, ...]
    html_files: tuple[str, ...]
    discovered_scripts: tuple[DiscoveredScript, ...]
    existing_csp: str | None
    remediation_targets: tuple[str, ...]
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_scripts(self) -> int:
        return len(self.discovered_scripts)

    @property
    def scripts_needing_sri(self) -> list[DiscoveredScript]:
        return [s for s in self.discovered_scripts if s.src and not s.has_sri]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "is_remote": self.is_remote,
            "primary_server": self.primary_server,
            "framework": self.framework,
            "config_files": list(self.config_files),
            "html_files": list(self.html_files),
            "total_scripts": self.total_scripts,
            "scripts_needing_sri_count": len(self.scripts_needing_sri),
            "discovered_scripts": [s.to_dict() for s in self.discovered_scripts],
            "existing_csp": self.existing_csp,
            "remediation_targets": list(self.remediation_targets),
            "metadata": self.metadata,
        }


def detect_environment(
    target: str,
    http_client: httpx.Client | None = None,
) -> EnvironmentProfile:
    """Inspects target URL or local filesystem path and builds an EnvironmentProfile."""
    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        return _inspect_remote_target(target, http_client=http_client)

    path = Path(target).resolve()
    if not path.exists():
        # Treat as relative or check current working directory
        cwd_path = Path.cwd() / target
        if cwd_path.exists():
            path = cwd_path.resolve()
        else:
            raise FileNotFoundError(f"Target path does not exist: {target}")

    return _inspect_local_target(path)


def _inspect_remote_target(
    url: str,
    http_client: httpx.Client | None = None,
) -> EnvironmentProfile:
    """Recons a remote web application endpoint via HTTP probing."""
    server = "unknown"
    framework = None
    existing_csp = None
    scripts: list[DiscoveredScript] = []
    metadata: dict[str, Any] = {}

    try:
        def _execute_get(cli: httpx.Client) -> httpx.Response:
            return cli.get(url)

        if http_client:
            resp = _execute_get(http_client)
        else:
            with httpx.Client(timeout=10.0, follow_redirects=True) as client:
                resp = _execute_get(client)

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Detect server banner
        server_hdr = headers.get("server", "").lower()
        powered_by = headers.get("x-powered-by", "").lower()

        if "cloudflare" in server_hdr:
            server = "cloudflare"
        elif "nginx" in server_hdr:
            server = "nginx"
        elif "apache" in server_hdr:
            server = "apache"
        elif "caddy" in server_hdr:
            server = "caddy"
        elif "cloudfront" in headers.get("via", "").lower():
            server = "aws-cloudfront"
        elif server_hdr:
            server = server_hdr

        # Detect framework
        if "next.js" in powered_by or "x-nextjs" in headers:
            framework = "nextjs"
        elif "express" in powered_by:
            framework = "express"
        elif "django" in powered_by:
            framework = "django"

        existing_csp = headers.get("content-security-policy")
        metadata["status_code"] = resp.status_code
        metadata["headers"] = dict(resp.headers)

        # Parse DOM scripts
        content_type = headers.get("content-type", "")
        if "text/html" in content_type:
            soup = BeautifulSoup(resp.text, "html.parser")

            # Check for meta tag CSP if header missing
            if not existing_csp:
                meta_csp = soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "content-security-policy"})
                if meta_csp and meta_csp.get("content"):
                    existing_csp = str(meta_csp["content"])
                    metadata["csp_source"] = "meta_tag"

            for idx, tag in enumerate(soup.find_all("script")):
                src = tag.get("src")
                integrity = tag.get("integrity")
                is_inline = not bool(src)
                scripts.append(DiscoveredScript(
                    source_file=url,
                    src=str(src) if src else None,
                    is_inline=is_inline,
                    has_sri=bool(integrity),
                    declared_sri=str(integrity) if integrity else None,
                    line_number=idx + 1,
                    raw_tag=str(tag),
                ))

    except Exception as exc:
        metadata["error"] = str(exc)

    return EnvironmentProfile(
        target=url,
        is_remote=True,
        primary_server=server,
        framework=framework,
        config_files=(),
        html_files=(),
        discovered_scripts=tuple(scripts),
        existing_csp=existing_csp,
        remediation_targets=(url,),
        metadata=metadata,
    )


def _inspect_local_target(root: Path) -> EnvironmentProfile:
    """Deep-scans a local codebase, web root, or project directory."""
    server = "static"
    framework = None
    config_files: list[str] = []
    html_files: list[str] = []
    scripts: list[DiscoveredScript] = []
    existing_csp = None
    remediation_targets: list[str] = []
    metadata: dict[str, Any] = {}

    # Define ignore directories
    ignore_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".ruff_cache", "dist", "build"}

    # 1. Walk directory and collect candidate files
    if root.is_file():
        candidates = [root]
        search_root = root.parent
    else:
        candidates = []
        search_root = root
        for cur_root, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for f in files:
                candidates.append(Path(cur_root) / f)

    for p in candidates:
        name_lower = p.name.lower()
        abs_str = str(p.resolve())
        rel_str = str(p.relative_to(search_root)) if p.is_relative_to(search_root) else abs_str

        # Detect Web Server Configs
        if name_lower in ("nginx.conf", "default.conf") or p.suffix == ".conf":
            config_files.append(abs_str)
            server = "nginx"
            remediation_targets.append(abs_str)
        elif name_lower in (".htaccess", "httpd.conf", "apache2.conf"):
            config_files.append(abs_str)
            server = "apache"
            remediation_targets.append(abs_str)
        elif name_lower in ("caddyfile", "caddy.json"):
            config_files.append(abs_str)
            server = "caddy"
            remediation_targets.append(abs_str)

        # Detect Frameworks
        if name_lower in ("next.config.js", "next.config.mjs", "next.config.ts"):
            framework = "nextjs"
            config_files.append(abs_str)
            remediation_targets.append(abs_str)
        elif name_lower == "package.json":
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                if '"next"' in content:
                    framework = "nextjs"
                elif '"express"' in content:
                    framework = "express"
                elif '"react"' in content:
                    framework = framework or "react"
            except Exception:
                pass
        elif name_lower in ("pyproject.toml", "requirements.txt"):
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                if "fastapi" in content:
                    framework = "fastapi"
                elif "django" in content:
                    framework = "django"
                elif "flask" in content:
                    framework = "flask"
            except Exception:
                pass

        # Detect HTML files
        if p.suffix.lower() in (".html", ".htm", ".xhtml"):
            html_files.append(abs_str)
            remediation_targets.append(abs_str)

            # Inspect scripts inside HTML
            try:
                html_text = p.read_text(encoding="utf-8", errors="ignore")
                soup = BeautifulSoup(html_text, "html.parser")

                # Check for meta CSP
                if not existing_csp:
                    meta = soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "content-security-policy"})
                    if meta and meta.get("content"):
                        existing_csp = str(meta["content"])

                for idx, tag in enumerate(soup.find_all("script")):
                    src = tag.get("src")
                    integrity = tag.get("integrity")
                    is_inline = not bool(src)
                    scripts.append(DiscoveredScript(
                        source_file=abs_str,
                        src=str(src) if src else None,
                        is_inline=is_inline,
                        has_sri=bool(integrity),
                        declared_sri=str(integrity) if integrity else None,
                        line_number=idx + 1,
                        raw_tag=str(tag),
                    ))
            except Exception as e:
                metadata[f"parse_error_{rel_str}"] = str(e)

    return EnvironmentProfile(
        target=str(root),
        is_remote=False,
        primary_server=server,
        framework=framework,
        config_files=tuple(sorted(config_files)),
        html_files=tuple(sorted(html_files)),
        discovered_scripts=tuple(scripts),
        existing_csp=existing_csp,
        remediation_targets=tuple(sorted(set(remediation_targets))),
        metadata=metadata,
    )
