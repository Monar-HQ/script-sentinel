from __future__ import annotations

from scriptsentinel.models import (
    ComplianceItem,
    CSPAnalysis,
    Finding,
    HashDigests,
    RemediationPack,
    ScriptAudit,
    ScriptIntegrityResult,
    ScriptTagReplacement,
)
from scriptsentinel.remediate import generate_remediation_pack

_SITE_URL = "https://example.com/checkout"
_SUGGESTED_TAG = (
    '<script src="https://cdn.optimized-edge.com/geo.js" '
    'integrity="sha256-AbCdEf=" crossorigin="anonymous"></script>'
)


def _sample_csp() -> CSPAnalysis:
    return CSPAnalysis(
        score=25,
        grade="F",
        directives={
            "default-src": ("'self'",),
            "script-src": (
                "'self'",
                "'unsafe-eval'",
                "'unsafe-inline'",
                "https://cdn.example.com",
            ),
            "connect-src": ("*",),
        },
        findings=(
            Finding(
                rule_id="CSP-UNSAFE-EVAL",
                severity="CRITICAL",
                title="'unsafe-eval' permitted",
                description="Injected scripts can execute dynamic strings.",
                recommendation="Remove 'unsafe-eval' from script-src.",
            ),
        ),
        raw=(
            "default-src 'self'; "
            "script-src 'self' 'unsafe-eval' 'unsafe-inline' https://cdn.example.com; "
            "connect-src *"
        ),
    )


def _sample_scripts() -> tuple[ScriptAudit, ...]:
    return (
        ScriptAudit(
            index=0,
            kind="external",
            url="https://cdn.optimized-edge.com/geo.js",
            suggested_tag=_SUGGESTED_TAG,
            length=1024,
        ),
        ScriptAudit(index=1, kind="inline", length=42),
    )


def _directive_values(policy: str, directive: str) -> tuple[str, ...]:
    for segment in policy.split(";"):
        parts = segment.strip().split()
        if parts and parts[0] == directive:
            return tuple(parts[1:])
    return ()


def test_generate_remediation_pack_returns_typed_contract() -> None:
    pack = generate_remediation_pack(_SITE_URL, _sample_csp(), _sample_scripts())

    assert isinstance(pack, RemediationPack)
    assert pack.site_url == _SITE_URL
    assert isinstance(pack.sri_replacement_tags, tuple)
    assert isinstance(pack.compliance, tuple)
    payload = pack.to_dict()
    assert payload["site_url"] == _SITE_URL
    assert payload["hardened_csp"] == pack.hardened_csp
    assert payload["sri_replacement_tags"] == [
        {"url": "https://cdn.optimized-edge.com/geo.js", "tag": _SUGGESTED_TAG}
    ]
    assert len(payload["compliance"]) == 2


def test_hardened_csp_strips_unsafe_keywords_and_adds_strict_directives() -> None:
    pack = generate_remediation_pack(_SITE_URL, _sample_csp(), _sample_scripts())

    assert "default-src 'self'" in pack.hardened_csp
    assert "script-src-elem" in pack.hardened_csp
    assert "'nonce-{NONCE}'" in pack.hardened_csp
    assert "connect-src 'self'" in pack.hardened_csp
    assert "report-uri /api/csp-report" in pack.hardened_csp
    assert "https://cdn.optimized-edge.com" in pack.hardened_csp
    assert "https://cdn.example.com" in pack.hardened_csp
    assert "'unsafe-eval'" not in pack.hardened_csp
    assert "'unsafe-inline'" not in pack.hardened_csp

    script_src = _directive_values(pack.hardened_csp, "script-src")
    assert "'unsafe-eval'" not in script_src
    assert "'unsafe-inline'" not in script_src
    assert "'self'" in script_src
    assert "'nonce-{NONCE}'" in script_src
    assert "https://cdn.optimized-edge.com" in script_src
    assert "https://cdn.example.com" in script_src

    script_src_elem = _directive_values(pack.hardened_csp, "script-src-elem")
    assert "'unsafe-eval'" not in script_src_elem
    assert "'unsafe-inline'" not in script_src_elem
    assert "'self'" in script_src_elem
    assert "'nonce-{NONCE}'" in script_src_elem
    assert "https://cdn.optimized-edge.com" in script_src_elem

    assert _directive_values(pack.hardened_csp, "connect-src") == ("'self'",)
    assert _directive_values(pack.hardened_csp, "report-uri") == ("/api/csp-report",)


def test_server_snippets_are_ready_to_paste() -> None:
    pack = generate_remediation_pack(_SITE_URL, _sample_csp(), _sample_scripts())

    assert (
        f'add_header Content-Security-Policy "{pack.hardened_csp}" always;'
        in pack.nginx_config
    )
    assert 'add_header X-Content-Type-Options "nosniff" always;' in pack.nginx_config
    assert (
        f'Header set Content-Security-Policy "{pack.hardened_csp}"'
        in pack.apache_config
    )
    assert 'Header set X-Content-Type-Options "nosniff"' in pack.apache_config


def test_sri_replacement_tags_use_audit_suggested_tag() -> None:
    pack = generate_remediation_pack(_SITE_URL, _sample_csp(), _sample_scripts())

    assert len(pack.sri_replacement_tags) == 1
    replacement = pack.sri_replacement_tags[0]
    assert isinstance(replacement, ScriptTagReplacement)
    assert replacement.url == "https://cdn.optimized-edge.com/geo.js"
    assert replacement.tag == _SUGGESTED_TAG


def test_sri_tags_fall_back_to_integrity_suggested_tag() -> None:
    digests = HashDigests(
        sha256="0123456789abcdef",
        sha384="fedcba9876543210",
        sri_sha256="sha256-AbCdEf=",
        sri_sha384="sha384-GhIjKl=",
        byte_count=1024,
    )
    integrity = ScriptIntegrityResult(
        url="https://cdn.optimized-edge.com/geo.js",
        status="VERIFIED",
        drift_detected=False,
        declared_integrity="sha256-AbCdEf=",
        calculated=digests,
        issues=(),
        suggested_tag=_SUGGESTED_TAG,
    )
    audit = ScriptAudit(
        index=0,
        kind="external",
        url="https://cdn.optimized-edge.com/geo.js",
        integrity=integrity,
    )

    pack = generate_remediation_pack(_SITE_URL, _sample_csp(), (audit,))

    assert len(pack.sri_replacement_tags) == 1
    assert pack.sri_replacement_tags[0].url == "https://cdn.optimized-edge.com/geo.js"
    assert pack.sri_replacement_tags[0].tag == _SUGGESTED_TAG


def test_approved_origins_include_relative_and_protocol_relative_audits() -> None:
    scripts = (
        ScriptAudit(
            index=0,
            kind="external",
            url="//cdn.optimized-edge.com/geo.js",
            suggested_tag=_SUGGESTED_TAG,
        ),
        ScriptAudit(
            index=1,
            kind="external",
            url="https://cdn.optimized-edge.com/other.js",
            suggested_tag="<script src=\"https://cdn.optimized-edge.com/other.js\"></script>",
        ),
        ScriptAudit(
            index=2,
            kind="external",
            url="/assets/app.js",
            suggested_tag="<script src=\"/assets/app.js\"></script>",
        ),
    )

    pack = generate_remediation_pack(_SITE_URL, _sample_csp(), scripts)
    script_src = _directive_values(pack.hardened_csp, "script-src")

    assert "https://cdn.optimized-edge.com" in script_src
    assert script_src.count("https://cdn.optimized-edge.com") == 1
    assert "'self'" in script_src


def test_compliance_checklist_covers_pci_dss_requirements() -> None:
    pack = generate_remediation_pack(_SITE_URL, _sample_csp(), _sample_scripts())

    assert len(pack.compliance) == 2
    assert all(isinstance(item, ComplianceItem) for item in pack.compliance)
    first = pack.compliance[0]
    second = pack.compliance[1]
    assert "PCI-DSS v4.0" in first.standard
    assert "6.4.3" in first.standard
    assert "PCI-DSS v4.0" in second.standard
    assert "11.6.1" in second.standard
    assert first.status.startswith("PASS")
    assert second.status.startswith("PASS")
    assert first.requirement
    assert second.requirement


def test_empty_script_inventory_still_produces_valid_csp() -> None:
    pack = generate_remediation_pack(_SITE_URL, _sample_csp(), ())

    assert "script-src 'self' 'nonce-{NONCE}'" in pack.hardened_csp
    assert pack.sri_replacement_tags == ()
    assert len(pack.compliance) == 2

