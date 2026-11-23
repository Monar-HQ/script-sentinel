"""Actionable remediation generator for ScriptSentinel.

Builds a typed :class:`RemediationPack` from CSP analysis and script inventory.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final
from urllib.parse import urljoin, urlparse

from .models import (
    ComplianceItem,
    CSPAnalysis,
    RemediationPack,
    ScriptAudit,
    ScriptTagReplacement,
)

_NONCE_PLACEHOLDER: Final[str] = "'nonce-{NONCE}'"
_REPORT_URI: Final[str] = "/api/csp-report"
_UNSAFE_SCRIPT_KEYWORDS: Final[frozenset[str]] = frozenset({"'unsafe-eval'", "'unsafe-inline'"})
_NONCE_OR_HASH_PREFIXES: Final[tuple[str, ...]] = ("'nonce-", "'sha256-", "'sha384-")


def _origin_from_url(site_url: str, raw_url: str) -> str | None:
    """Return the HTTP(S) origin of a URL, resolving relative URLs against the site."""

    absolute_url = urljoin(site_url, raw_url.strip())
    parsed = urlparse(absolute_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _collect_approved_origins(
    site_url: str,
    csp_analysis: CSPAnalysis | dict[str, Any],
    scripts_audit: Sequence[ScriptAudit | dict[str, Any]],
) -> tuple[str, ...]:
    """Collect explicit script origins from the existing CSP and audited scripts."""

    origins: set[str] = {"'self'"}
    directives = (
        csp_analysis.get("directives", {})
        if isinstance(csp_analysis, dict)
        else csp_analysis.directives
    )
    source_values = directives.get("script-src", directives.get("default-src", ()))

    for value in source_values:
        normalized = value.strip()
        lowered = normalized.lower()
        if lowered in _UNSAFE_SCRIPT_KEYWORDS:
            continue
        if lowered.startswith(_NONCE_OR_HASH_PREFIXES):
            continue
        if lowered == "'self'":
            origins.add("'self'")
            continue
        if normalized.startswith(("http://", "https://", "//")):
            origin = _origin_from_url(site_url, normalized)
            if origin is not None:
                origins.add(origin)
            continue
        if normalized and not normalized.startswith("'") and "." in normalized:
            origin = _origin_from_url(site_url, f"https://{normalized}")
            if origin is not None:
                origins.add(origin)

    for audit in scripts_audit:
        url = audit.get("url") if isinstance(audit, dict) else audit.url
        if url:
            origin = _origin_from_url(site_url, url)
            if origin is not None:
                origins.add(origin)

    return tuple(sorted(origins, key=lambda item: (item != "'self'", item)))


def _build_hardened_csp(origins: tuple[str, ...]) -> str:
    """Build a strict CSP with a nonce placeholder and explicit approved origins."""

    url_origins = tuple(origin for origin in origins if origin != "'self'")
    script_values: tuple[str, ...] = ("'self'", _NONCE_PLACEHOLDER, *url_origins)
    script_source = " ".join(script_values)

    directives = (
        "default-src 'self'",
        f"script-src {script_source}",
        f"script-src-elem {script_source}",
        "connect-src 'self'",
        "style-src 'self'",
        "img-src 'self' data: https:",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        f"report-uri {_REPORT_URI}",
    )
    return "; ".join(directives)


def _sri_replacements(
    scripts_audit: Sequence[ScriptAudit | dict[str, Any]],
) -> tuple[ScriptTagReplacement, ...]:
    """Build drop-in SRI tags from audit suggested tags, preserving inventory order."""

    replacements: list[ScriptTagReplacement] = []
    for audit in scripts_audit:
        if isinstance(audit, dict):
            tag = audit.get("suggested_tag")
            url = audit.get("url")
        else:
            tag = audit.suggested_tag
            url = audit.url
            if audit.integrity is not None:
                if tag is None:
                    tag = audit.integrity.suggested_tag
                if url is None:
                    url = audit.integrity.url
        if tag is not None and url is not None:
            replacements.append(ScriptTagReplacement(url=url, tag=tag))
    return tuple(replacements)


def _nginx_config(hardened_csp: str) -> str:
    """Return a ready-to-paste Nginx header snippet."""

    return (
        "# Nginx security configuration (ScriptSentinel hardened)\n"
        f'add_header Content-Security-Policy "{hardened_csp}" always;\n'
        'add_header X-Content-Type-Options "nosniff" always;\n'
        'add_header X-Frame-Options "DENY" always;\n'
        'add_header Referrer-Policy "strict-origin-when-cross-origin" always;\n'
    )


def _apache_config(hardened_csp: str) -> str:
    """Return a ready-to-paste Apache header snippet."""

    return (
        "# Apache security configuration (ScriptSentinel hardened)\n"
        f'Header set Content-Security-Policy "{hardened_csp}"\n'
        'Header set X-Content-Type-Options "nosniff"\n'
        'Header set X-Frame-Options "DENY"\n'
        'Header set Referrer-Policy "strict-origin-when-cross-origin"\n'
    )


def _compliance_checklist() -> tuple[ComplianceItem, ...]:
    """Return PCI-DSS v4.0 compliance entries for payment-page script controls."""

    return (
        ComplianceItem(
            standard="PCI-DSS v4.0 Requirement 6.4.3",
            requirement=(
                "All payment page scripts must be authorized, justified, and integrity-verified."
            ),
            status="PASS with generated SRI tags and explicit script inventory.",
        ),
        ComplianceItem(
            standard="PCI-DSS v4.0 Requirement 11.6.1",
            requirement=(
                "Change- and tamper-detection mechanism for payment page HTTP headers and contents."
            ),
            status="PASS when script hash drift monitoring and CSP reporting are active.",
        ),
    )


def generate_remediation_pack(
    site_url: str,
    csp_analysis: CSPAnalysis | dict[str, Any],
    scripts_audit: Sequence[ScriptAudit | dict[str, Any]],
) -> RemediationPack:
    """Generate a typed remediation pack for a site's CSP and script inventory."""

    origins = _collect_approved_origins(site_url, csp_analysis, scripts_audit)
    hardened_csp = _build_hardened_csp(origins)
    return RemediationPack(
        site_url=site_url,
        hardened_csp=hardened_csp,
        sri_replacement_tags=_sri_replacements(scripts_audit),
        nginx_config=_nginx_config(hardened_csp),
        apache_config=_apache_config(hardened_csp),
        compliance=_compliance_checklist(),
    )

