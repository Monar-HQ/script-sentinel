"""
Actionable Remediation Generator
Synthesizes hardened CSP policies, Subresource Integrity tags, and server configurations.
"""

from typing import Any
from urllib.parse import urlparse


def generate_remediation_pack(
    site_url: str, csp_analysis: dict[str, Any], scripts_audit: list[dict[str, Any]]
) -> dict[str, Any]:
    # Collect approved script origins
    approved_script_origins = {"'self'"}
    sri_tags = []

    for s in scripts_audit:
        src = s.get("url")
        if src and src.startswith("http"):
            parsed = urlparse(src)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            approved_script_origins.add(origin)

        # Include suggested SRI tag
        if "suggested_tag" in s:
            sri_tags.append({"url": src, "tag": s["suggested_tag"]})

    script_src_list = " ".join(sorted(approved_script_origins))

    # Synthesize hardened CSP
    hardened_csp = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{{NONCE}}' {script_src_list}; "
        f"script-src-elem 'self' 'nonce-{{NONCE}}' {script_src_list}; "
        f"connect-src 'self'; "
        f"style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data: https:; "
        f"frame-ancestors 'none'; "
        f"form-action 'self'; "
        f"base-uri 'self'; "
        f"report-uri /api/csp-report"
    )

    # Server configurations
    nginx_conf = f"""# Nginx Security Configuration (CodeSentinel Hardened)
add_header Content-Security-Policy "{hardened_csp}" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
"""

    apache_conf = f"""# Apache Security Configuration (CodeSentinel Hardened)
Header set Content-Security-Policy "{hardened_csp}"
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "DENY"
Header set Referrer-Policy "strict-origin-when-cross-origin"
"""

    compliance_checklist = [
        {
            "standard": "PCI-DSS v4.0 Requirement 6.4.3",
            "requirement": "All payment page scripts must be authorized, justified, and integrity-verified.",
            "status": "PASS with generated SRI tags and explicit script inventory.",
        },
        {
            "standard": "PCI-DSS v4.0 Requirement 11.6.1",
            "requirement": "Change- and tamper-detection mechanism for payment page HTTP headers and contents.",
            "status": "PASS when script hash drift monitoring and CSP reporting are active.",
        },
    ]

    return {
        "site_url": site_url,
        "hardened_csp": hardened_csp,
        "sri_replacement_tags": sri_tags,
        "nginx_config": nginx_conf,
        "apache_config": apache_conf,
        "compliance": compliance_checklist,
    }
