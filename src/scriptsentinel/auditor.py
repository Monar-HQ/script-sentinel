"""
Core Auditor & Pipeline Orchestrator
Fetches targets, inspects HTTP response headers, parses HTML scripts, fetches dependencies,
computes integrity, and coordinates full security audit.
"""

from typing import Any
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from .csp_analyzer import analyze_csp
from .integrity import audit_script_integrity
from .remediate import generate_remediation_pack
from .scanner import scan_script_content


class AuditReport:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.timestamp = None
        self.status_code = None
        self.headers = {}
        self.csp_report = {}
        self.scripts = []
        self.overall_risk = "LOW"
        self.summary = {}
        self.remediation = {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "status_code": self.status_code,
            "overall_risk": self.overall_risk,
            "summary": self.summary,
            "csp": self.csp_report,
            "scripts": self.scripts,
            "remediation": self.remediation,
        }


async def audit_url(
    target_url: str, baseline_hashes: dict[str, str] | None = None, timeout: float = 10.0
) -> AuditReport:
    report = AuditReport(target_url)
    baseline_hashes = baseline_hashes or {}

    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        try:
            resp = await client.get(target_url)
        except Exception as e:
            report.overall_risk = "ERROR"
            report.summary = {"error": f"Failed to fetch {target_url}: {e!s}"}
            return report

        report.status_code = resp.status_code
        report.headers = dict(resp.headers)

        # 1. Analyze CSP header
        csp_header = resp.headers.get("content-security-policy")
        report.csp_report = analyze_csp(csp_header)

        # 2. Parse HTML and inventory scripts
        html = resp.text
        soup = BeautifulSoup(html, "html.parser")
        script_elements = soup.find_all("script")

        for idx, s in enumerate(script_elements):
            src = s.get("src")
            declared_integrity = s.get("integrity")
            nonce = s.get("nonce")

            if src:
                full_url = urljoin(target_url, src)
                # Fetch external script
                try:
                    s_resp = await client.get(full_url)
                    s_bytes = s_resp.content
                    s_text = s_resp.text
                except Exception as ex:
                    report.scripts.append(
                        {
                            "index": idx,
                            "type": "external",
                            "url": full_url,
                            "error": f"Failed to retrieve script: {ex!s}",
                            "status": "FETCH_FAILED",
                        }
                    )
                    continue

                # Run integrity & drift check
                base_sha = baseline_hashes.get(full_url)
                integ_res = audit_script_integrity(full_url, s_bytes, declared_integrity, base_sha)

                # Run behavioral skimmer scan
                scan_res = scan_script_content(s_text, full_url)

                report.scripts.append(
                    {
                        "index": idx,
                        "type": "external",
                        "url": full_url,
                        "nonce": nonce,
                        "declared_integrity": declared_integrity,
                        "integrity_audit": integ_res,
                        "scanner_audit": scan_res,
                        "suggested_tag": integ_res["suggested_tag"],
                    }
                )
            else:
                # Inline script
                inline_content = s.string or s.text or ""
                scan_res = scan_script_content(inline_content, f"inline_script_{idx}")
                report.scripts.append(
                    {
                        "index": idx,
                        "type": "inline",
                        "length": len(inline_content),
                        "nonce": nonce,
                        "scanner_audit": scan_res,
                    }
                )

        # 3. Synthesize overall risk
        has_critical = False
        has_high = False

        if report.csp_report.get("grade") in ("D", "F"):
            has_high = True

        for s in report.scripts:
            # Check integrity issues
            integ = s.get("integrity_audit", {})
            for issue in integ.get("issues", []):
                if issue.get("severity") == "CRITICAL":
                    has_critical = True
                elif issue.get("severity") == "HIGH":
                    has_high = True

            # Check scanner issues
            scanner = s.get("scanner_audit", {})
            for f in scanner.get("findings", []):
                if f.get("severity") == "CRITICAL":
                    has_critical = True
                elif f.get("severity") == "HIGH":
                    has_high = True

        if has_critical:
            report.overall_risk = "CRITICAL"
        elif has_high:
            report.overall_risk = "HIGH"
        else:
            report.overall_risk = "LOW"

        # 4. Generate Remediation Pack
        report.remediation = generate_remediation_pack(
            target_url, report.csp_report, report.scripts
        )

        # 5. Populate summary
        report.summary = {
            "total_scripts": len(report.scripts),
            "external_scripts": len([s for s in report.scripts if s.get("type") == "external"]),
            "inline_scripts": len([s for s in report.scripts if s.get("type") == "inline"]),
            "csp_grade": report.csp_report.get("grade"),
            "csp_score": report.csp_report.get("score"),
            "overall_risk": report.overall_risk,
        }

        return report
