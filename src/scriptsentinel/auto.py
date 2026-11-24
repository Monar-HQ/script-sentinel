"""Read-only discovery and deterministic audit with optional AI advice.

Local analysis uses heuristic source patterns, not an AST. Applying a patch is
a separate reviewed-baseline proposal workflow in :mod:`proposals`.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx

from .ai.agent import AIAgent, AIAuditAnalysis
from .ai.client import AIClient, AIConfig
from .auditor import audit_url
from .env_detector import EnvironmentProfile, detect_environment
from .models import (
    AuditReport,
)
from .network import NetworkPolicy
from .patcher import PatchResult


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
        return sum(p.scripts_patched for p in self.patches) + sum(
            1 for p in self.patches if p.csp_injected
        )

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
    if target.startswith(("https://", "http://")):
        # Do not run unscoped discovery before the authorized HTTP audit.
        env = EnvironmentProfile(
            target=target,
            is_remote=True,
            primary_server="unknown",
            framework=None,
            config_files=(),
            html_files=(),
            discovered_scripts=(),
            existing_csp=None,
            remediation_targets=(),
        )
    else:
        env = detect_environment(target)

    # Step 2: Deterministic Security Audit
    if env.is_remote:
        report = await audit_url(
            target,
            transport=http_transport,
            network_policy=None if http_transport else NetworkPolicy.create([target]),
        )
    else:
        from .local_audit import audit_local

        report = audit_local(env)

    # Step 3: Frontier Multi-Provider AI Reasoning
    # Ambient credentials do not authorize sending project evidence externally.
    active_client = ai_client or AIClient(
        config=ai_config
        or AIConfig(provider="custom", api_key=None, api_base=None, model="unconfigured")
    )
    ai_agent = AIAgent(client=active_client)
    ai_analysis: AIAuditAnalysis | None = None
    ai_error: str | None = None

    try:
        if ai_agent.is_available:
            try:
                ai_analysis = ai_agent.analyze_audit(report, env)
            except Exception as exc:
                ai_error = (
                    f"AI advisory unavailable ({type(exc).__name__}); deterministic report retained"
                )
                ai_analysis = None
        elif ai_config is not None or ai_client is not None:
            ai_error = "AI advisory is unconfigured; deterministic report retained"
    except Exception as exc:
        ai_error = f"AI advisory unavailable ({type(exc).__name__}); deterministic report retained"
    finally:
        if ai_client is None:
            active_client.close()

    # Step 5: Surgical Automated Patching (if requested)
    patch_results: list[PatchResult] = []
    if apply_fix and not env.is_remote:
        raise ValueError(
            "Direct remediation is disabled. Use propose, validate-proposal and apply-proposal "
            "with a reviewed trusted baseline and explicit approval."
        )

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
        "ai_error": ai_error,
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
