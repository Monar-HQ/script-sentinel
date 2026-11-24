"""Offline, scoped analysis. Never executes project JavaScript or fetches vendors."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote, urlsplit

from bs4 import BeautifulSoup

from .auditor import _compute_risk
from .csp_analyzer import analyze_csp
from .env_detector import EnvironmentProfile
from .integrity import audit_script_integrity
from .models import AuditReport, ScriptAudit
from .scanner import scan_script_content
from .script_types import executable_script_type


def resolve_local_script(root: Path, html: Path, src: str) -> Path:
    """Resolve URL paths inside an approved root, including symlink checks."""
    parsed = urlsplit(src)
    if parsed.scheme or parsed.netloc:
        raise ValueError("Remote resource unavailable in offline mode")
    path = unquote(parsed.path)
    if "\\" in path or "\x00" in path:
        raise ValueError("Invalid script path")
    candidate = ((root if path.startswith("/") else html.parent) / path.lstrip("/")).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError("Script path escapes approved workspace")
    return candidate


def audit_local(env: EnvironmentProfile) -> AuditReport:
    root = Path(env.target).resolve()
    if root.is_file():
        root = root.parent
    csp = analyze_csp(env.existing_csp)
    scripts: list[ScriptAudit] = []
    errors: list[str] = []
    for filename in env.html_files:
        html = Path(filename).resolve()
        try:
            if not html.is_relative_to(root):
                raise ValueError("HTML path escapes approved workspace")
            if html.stat().st_size > 5_000_000:
                raise ValueError("HTML exceeds 5 MB analysis limit")
            soup = BeautifulSoup(html.read_text(encoding="utf-8"), "html.parser")
            has_base_href = soup.find("base", href=True) is not None
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append(f"{html.name}: {type(exc).__name__}: {exc}")
            continue
        for tag in soup.find_all("script"):
            if len(scripts) >= 1000:
                errors.append("Workspace exceeds 1000-script analysis limit")
                break
            src = str(tag.get("src")) if tag.has_attr("src") else None
            script_type = str(tag.get("type", "")).lower().split(";")[0].strip()
            if not executable_script_type(script_type):
                scripts.append(
                    ScriptAudit(
                        index=len(scripts),
                        kind="external" if src else "inline",
                        url=src,
                        analysis_note=f"Non-executable data script ({script_type}); source not fetched or scanned",
                    )
                )
                continue
            nonce = str(tag["nonce"]) if tag.has_attr("nonce") else None
            declared = str(tag["integrity"]) if tag.has_attr("integrity") else None
            integrity = None
            scan = None
            error = None
            length = None
            try:
                if src is not None and has_base_href:
                    raise ValueError(
                        "HTML base href requires browser URL resolution; external script unavailable offline"
                    )
                if (
                    src is not None
                    and resolve_local_script(root, html, src).stat().st_size > 5_000_000
                ):
                    raise ValueError("Script exceeds 5 MB analysis limit")
                content = (
                    resolve_local_script(root, html, src).read_bytes()
                    if src is not None
                    else tag.get_text().encode("utf-8")
                )
                length = len(content)
                scan = scan_script_content(
                    content.decode("utf-8", errors="replace"), src or f"{html.name}:inline"
                )
                if src is not None:
                    integrity = audit_script_integrity(src, content, declared)
            except (OSError, ValueError) as exc:
                error = f"{type(exc).__name__}: {exc}"
            scripts.append(
                ScriptAudit(
                    index=len(scripts),
                    kind="external" if src is not None else "inline",
                    url=src,
                    nonce=nonce,
                    declared_integrity=declared,
                    integrity=integrity,
                    scan=scan,
                    error=error,
                    length=length,
                    suggested_tag=integrity.suggested_tag if integrity else None,
                )
            )
    error_text = "; ".join(errors) or None
    risk = _compute_risk(csp, scripts, error_text)
    return AuditReport.create(
        target_url=env.target,
        status_code=None,
        csp=csp,
        scripts=tuple(scripts),
        overall_risk=risk,
        error=error_text,
        summary={
            "total_scripts": len(scripts),
            "fetch_failures": sum(s.error is not None for s in scripts),
            "analysis": "offline AST capability signals and heuristic patterns; not execution or full dataflow proof",
        },
    )
