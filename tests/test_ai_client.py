"""Tests for Multi-Provider AI Client and Security Agent."""

from __future__ import annotations

import json

import pytest

from scriptsentinel.ai.agent import AIAgent, AIAuditAnalysis
from scriptsentinel.ai.client import AIClient, AIConfig
from scriptsentinel.models import AuditReport, CSPAnalysis


def test_ai_config_properties() -> None:
    """Verifies AIConfig properties and readiness checks."""
    cfg = AIConfig(provider="anthropic", api_key="sk-ant-test", api_base=None, model="claude-3-5-sonnet")
    assert cfg.is_configured is True
    assert cfg.provider == "anthropic"

    empty_cfg = AIConfig(provider="none", api_key=None, api_base=None, model="none")
    assert empty_cfg.is_configured is False


def test_ai_client_auto_detect_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies auto-detection of environment credentials."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-12345")
    cfg = AIClient.auto_detect()
    assert cfg.provider == "anthropic"
    assert cfg.api_key == "sk-ant-12345"
    assert "claude" in cfg.model


def test_ai_agent_analyze_audit_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies AI agent JSON extraction and structured analysis synthesis."""
    fake_payload = {
        "threat_narrative": "Attackers leverage unpinned CDN script to inject DOM harvester.",
        "smart_csp": "default-src 'self'; script-src 'self' https://trusted.cdn.com;",
        "remediation_recommendations": ["Pin SHA-256 SRI hash", "Deploy hardened CSP"],
        "compliance_assessment": "Violates PCI-DSS v4.0 Requirement 6.4.3.",
        "executive_summary": "Critical supply-chain vulnerability detected in checkout workflow.",
    }

    class MockClient:
        is_available = True

        def generate(self, system: str, prompt: str) -> str:
            return f"```json\n{json.dumps(fake_payload)}\n```"

    agent = AIAgent(client=MockClient())  # type: ignore[arg-type]
    report = AuditReport.create(
        target_url="https://checkout.example.com",
        csp=CSPAnalysis(score=20, grade="F", directives={}, findings=()),
    )

    analysis = agent.analyze_audit(report)
    assert isinstance(analysis, AIAuditAnalysis)
    assert "DOM harvester" in analysis.threat_narrative
    assert "https://trusted.cdn.com" in analysis.smart_csp
    assert len(analysis.remediation_recommendations) == 2
    assert "PCI-DSS" in analysis.compliance_assessment


def test_ai_agent_explain_threat_mock() -> None:
    """Verifies single rule explanation generation."""
    class MockClient:
        is_available = True

        def generate(self, system: str, prompt: str) -> str:
            return "Adversaries abuse this vector to exfiltrate credit card data via fetch."

    agent = AIAgent(client=MockClient())  # type: ignore[arg-type]
    explanation = agent.explain_threat("CSP-001", {"score": 0})
    assert "exfiltrate credit card data" in explanation
