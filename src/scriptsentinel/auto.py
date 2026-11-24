"""Autonomous Security Pipeline & Orchestration Engine for ScriptSentinel.

Executes the complete, hands-off client-side supply-chain remediation workflow:
1. Environment & Architecture Recon: Auto-detects reverse proxies, frameworks, HTML files, and script elements.
2. Deterministic Security Audit: Deep AST skimmer scan, Subresource Integrity verification, and CSP evaluation.
3. Multi-Provider AI Intelligence: Synthesizes threat narratives, surgical CSPs, and PCI-DSS v4.0 executive briefs.
4. Surgical Automated Patching: Injects SRI hashes into HTML <script> tags and hardens Nginx/server headers with rollback safety.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from bs4 import BeautifulSoup

from .ai.agent import AIAgent, AIAuditAnalysis
from .ai.client import AIClient, AIConfig
from .auditor import audit_url
from .csp_analyzer import analyze_csp
from .env_detector import EnvironmentProfile, detect_environment
from .integrity import audit_script_integrity
from .models import (
    AuditReport,
    CSPAnalysis,
    HashDigests,
    IntegrityIssue,
    RemediationPack,
    RiskRating,
    ScanResult,
    ScriptAudit,
    ScriptIntegrityResult,
)
from .patcher import Patcher, PatchResult
from .remediate import generate_remediation_pack
from .scanner import scan_script_content


@dataclass(frozen=True, slots=True)
class AutoResult:
    """Consolidated outcome of the autonomous recon, audit, AI triage, and patching pipeline."""
    target: str
    env_profile: EnvironmentProfile
    audit_report: AuditReport
    ai_analysis: AIAuditAnalysis | None
    patches: tuple[PatchResult, ...]
    overall_risk: str
    summary: dict[str, Any] = field(default_factory=dict)

    @property
    def total_patches_applied(self) -> int:
        return sum(p.scripts_patched for p in self.patches) + sum(1 for p in self.patches if p.csp_injected)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "overall_risk": self.overall_risk,
            "env_profile": self.env_profile.to_dict(),
            "audit_report": self.audit_report.to_dict(),
            "ai_analysis": self.ai_analysis.to_dict() if self.ai_analysis else None,
            "patches": [p.to_dict() for p in self.patches],
            "total_patches_applied": self.total_patches_applied,
            "summary": self.summary,
        }


def _audit_local_environment(env: EnvironmentProfile) -> AuditReport:
    """Builds a comprehensive AuditReport for local projects and directories."""
    # 1. Evaluate CSP if present
    csp_analysis = analyze_csp(env.existing_csp)
    if not isinstance(csp_analysis, CSPAnalysis):
        # Convert dict to CSPAnalysis
        csp_analysis = CSPAnalysis(
            score=int(csp_analysis.get("score", 0)),
            grade=csp_analysis.get("grade", "F"),  # type: ignore[arg-type]
            directives=csp_analysis.get("directives", {}),
            findings=(),
            raw=env.existing_csp,
        )

    # 2. Audit scripts across discovered HTML files
    scripts: list[ScriptAudit] = []
    script_idx = 0

    for html_file_str in env.html_files:
        html_path = Path(html_file_str)
        if not html_path.is_file():
            continue

        try:
            content = html_path.read_text(encoding="utf-8", errors="ignore")
            soup = BeautifulSoup(content, "html.parser")
            for tag in soup.find_all("script"):
                src = tag.get("src")
                nonce = tag.get("nonce")
                declared_integrity = tag.get("integrity")

                if src:
                    # External script reference
                    src_str = str(src)
                    local_candidate = (html_path.parent / src_str.lstrip("/")).resolve()
                    if local_candidate.is_file():
                        raw_bytes = local_candidate.read_bytes()
                        integ_raw = audit_script_integrity(
                            url=src_str,
                            content=raw_bytes,
                            declared_integrity=str(declared_integrity) if declared_integrity else None,
                        )
                    else:
                        integ_raw = audit_script_integrity(
                            url=src_str,
                            content=b"",
                            declared_integrity=str(declared_integrity) if declared_integrity else None,
                        )

                    # Coerce integrity result to model
                    integ_model = ScriptIntegrityResult(
                        url=str(integ_raw.get("url", src_str)),
                        status=str(integ_raw.get("status", "UNKNOWN")),
                        drift_detected=bool(integ_raw.get("drift_detected", False)),
                        declared_integrity=integ_raw.get("declared_integrity"),
                        calculated=HashDigests(
                            sha256=str(integ_raw.get("calculated", {}).get("sha256", "")),
                            sha384=str(integ_raw.get("calculated", {}).get("sha384", "")),
                            sri_sha256=str(integ_raw.get("calculated", {}).get("sri_sha256", "")),
                            sri_sha384=str(integ_raw.get("calculated", {}).get("sri_sha384", "")),
                            byte_count=int(integ_raw.get("calculated", {}).get("byte_count", 0)),
                        ),
                        issues=tuple(
                            IntegrityIssue(
                                type=str(i.get("type", "")),
                                severity=str(i.get("severity", "INFO")),  # type: ignore[arg-type]
                                message=str(i.get("message", "")),
                            )
                            for i in integ_raw.get("issues", ())
                        ),
                        suggested_tag=str(integ_raw.get("suggested_tag", "")),
                    )

                    scripts.append(
                        ScriptAudit(
                            index=script_idx,
                            kind="external",
                            url=src_str,
                            nonce=str(nonce) if nonce else None,
                            declared_integrity=str(declared_integrity) if declared_integrity else None,
                            integrity=integ_model,
                            scan=None,
                            error=None,
                            suggested_tag=integ_model.suggested_tag,
                            length=integ_model.calculated.byte_count or None,
                        )
                    )
                else:
                    # Inline script block
                    inline_code = tag.get_text()
                    scan_raw = scan_script_content(inline_code, target=f"{html_path.name}:inline_{script_idx}")
                    scan_model = ScanResult(
                        target=str(scan_raw.get("target", "")),
                        is_suspicious=bool(scan_raw.get("is_suspicious", False)),
                        findings_count=int(scan_raw.get("findings_count", 0)),
                        findings=(),
                    )
                    scripts.append(
                        ScriptAudit(
                            index=script_idx,
                            kind="inline",
                            url=None,
                            nonce=str(nonce) if nonce else None,
                            declared_integrity=None,
                            integrity=None,
                            scan=scan_model,
                            error=None,
                            suggested_tag=None,
                            length=len(inline_code),
                        )
                    )
                script_idx += 1
        except Exception:
            pass

    # 3. Derive overall risk
    risk: RiskRating = "LOW"
    if csp_analysis.grade in ("D", "F"):
        risk = "HIGH"
    for s in scripts:
        if s.integrity and s.integrity.drift_detected:
            risk = "CRITICAL"
            break
        if s.scan and s.scan.is_suspicious:
            risk = "CRITICAL"
            break

    # 4. Generate deterministic remediation pack
    remediation: RemediationPack | None = None
    try:
        remediation = generate_remediation_pack(env.target, csp_analysis, scripts)
    except Exception:
        remediation = None

    summary = {
        "target": env.target,
        "primary_server": env.primary_server,
        "framework": env.framework,
        "total_scripts": len(scripts),
        "scripts_needing_sri": len(env.scripts_needing_sri),
        "csp_grade": csp_analysis.grade,
        "csp_score": csp_analysis.score,
        "overall_risk": risk,
    }

    return AuditReport(
        target_url=env.target,
        timestamp=datetime.now(timezone.utc).isoformat(),
        status_code=200,
        headers={"server": env.primary_server},
        csp=csp_analysis,
        scripts=tuple(scripts),
        overall_risk=risk,
        summary=summary,
        remediation=remediation,
        error=None,
    )


async def _run_pipeline_async(
    target: str,
    apply_fix: bool = False,
    backup: bool = True,
    ai_client: AIClient | None = None,
    ai_config: AIConfig | None = None,
    http_transport: httpx.AsyncBaseTransport | None = None,
) -> AutoResult:
    """Core async execution of the autonomous pipeline."""
    # Step 1: Environment & Architecture Recon
    env = detect_environment(target)

    # Step 2: Deterministic Security Audit
    if env.is_remote:
        report = await audit_url(target, transport=http_transport)
    else:
        report = _audit_local_environment(env)

    # Step 3: Frontier Multi-Provider AI Reasoning
    active_client = ai_client or AIClient(config=ai_config)
    ai_agent = AIAgent(client=active_client)
    ai_analysis: AIAuditAnalysis | None = None

    try:
        if ai_agent.is_available:
            try:
                ai_analysis = ai_agent.analyze_audit(report, env)
            except Exception:
                ai_analysis = None
    finally:
        if ai_client is None:
            active_client.close()

    # Step 4: Determine Remediation Policy
    if ai_analysis and ai_analysis.smart_csp:
        hardened_csp = ai_analysis.smart_csp
    elif report.remediation and report.remediation.hardened_csp:
        hardened_csp = report.remediation.hardened_csp
    else:
        hardened_csp = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';"

    # Step 5: Surgical Automated Patching (if requested)
    patch_results: list[PatchResult] = []
    if apply_fix and not env.is_remote:
        with Patcher(base_url=target if env.is_remote else None) as patcher:
            # 1. Patch Nginx configuration if present
            server_config_patched = False
            for cfg in env.config_files:
                if cfg.endswith(".conf") or "nginx" in cfg:
                    res = patcher.patch_nginx_config(cfg, hardened_csp=hardened_csp, create_backup=backup)
                    patch_results.append(res)
                    if res.success:
                        server_config_patched = True

            # 2. Patch HTML files: inject SRI and inject CSP meta-tag if no reverse proxy was patched
            for html_file in env.html_files:
                inject_meta = hardened_csp if not server_config_patched else None
                res = patcher.patch_html_file(
                    html_file,
                    hardened_csp=inject_meta,
                    create_backup=backup,
                )
                patch_results.append(res)

    summary = {
        "target": target,
        "is_remote": env.is_remote,
        "primary_server": env.primary_server,
        "framework": env.framework,
        "scripts_discovered": env.total_scripts,
        "scripts_needing_sri": len(env.scripts_needing_sri),
        "csp_grade": report.csp.grade,
        "overall_risk": report.overall_risk,
        "ai_active": ai_analysis is not None,
        "patches_applied": len(patch_results),
    }

    return AutoResult(
        target=target,
        env_profile=env,
        audit_report=report,
        ai_analysis=ai_analysis,
        patches=tuple(patch_results),
        overall_risk=report.overall_risk,
        summary=summary,
    )


def run_auto_pipeline(
    target: str,
    apply_fix: bool = False,
    backup: bool = True,
    ai_client: AIClient | None = None,
    ai_config: AIConfig | None = None,
    http_transport: httpx.AsyncBaseTransport | None = None,
) -> AutoResult:
    """Synchronous interface for executing the autonomous ScriptSentinel pipeline."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Running inside an active event loop (e.g. pytest or jupyter)
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                asyncio.run,
                _run_pipeline_async(
                    target=target,
                    apply_fix=apply_fix,
                    backup=backup,
                    ai_client=ai_client,
                    ai_config=ai_config,
                    http_transport=http_transport,
                ),
            )
            return future.result()

    return asyncio.run(
        _run_pipeline_async(
            target=target,
            apply_fix=apply_fix,
            backup=backup,
            ai_client=ai_client,
            ai_config=ai_config,
            http_transport=http_transport,
        )
    )
