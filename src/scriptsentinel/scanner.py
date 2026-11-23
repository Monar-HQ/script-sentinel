"""
Behavioral Script Scanner
Statically analyzes JavaScript content for skimmer behaviors, credential harvesting,
dynamic eval patterns, clipboard tampering, and known C2 IOCs.
"""

import re
import json
import os
from typing import Dict, List, Any

# Load C2 feeds
IOC_FEED_PATH = os.path.join(os.path.dirname(__file__), "iocs", "feeds", "malicious_c2.json")
KNOWN_IOC_DOMAINS = []
if os.path.exists(IOC_FEED_PATH):
    try:
        with open(IOC_FEED_PATH, "r", encoding="utf-8") as f:
            feed_data = json.load(f)
            KNOWN_IOC_DOMAINS = feed_data.get("domains", [])
    except Exception:
        pass

SUSPICIOUS_PATTERNS = [
    {
        "id": "SKIM-INPUT-HARVEST",
        "name": "Payment & Credential Field Scraping",
        "severity": "CRITICAL",
        "regex": r"(?:card(?:number|_no)?|cvv|cvc|expir(?:y|ation)|password|passwd|ssn)\b[\'\"]?\s*(?:,|:|=|\.value|\.getAttribute)",
        "description": "Script inspects or extracts values from payment card, CVV, or credential form fields."
    },
    {
        "id": "SKIM-DOM-LISTENER",
        "name": "Global Input / Keystroke Interceptor",
        "severity": "HIGH",
        "regex": r"addEventListener\s*\(\s*[\'\"](?:input|change|keydown|keyup|keypress|submit)[\'\"]",
        "description": "Attaches global listeners to harvest keystrokes or form submissions."
    },
    {
        "id": "SKIM-CLIPBOARD-TAMPER",
        "name": "Clipboard Read / Write Access",
        "severity": "HIGH",
        "regex": r"navigator\.(?:clipboard\.(?:readText|writeText)|clipboard)\b",
        "description": "Interacts directly with the system clipboard (crypto address clippers / credential theft)."
    },
    {
        "id": "SKIM-EVAL-EXEC",
        "name": "Dynamic Code Evaluation",
        "severity": "CRITICAL",
        "regex": r"\b(?:eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*[\'\"][^,]|\bFunction\s*\()",
        "description": "Executes dynamic strings or functions, often used to unpack obfuscated second-stage payloads."
    },
    {
        "id": "SKIM-BASE64-UNPACK",
        "name": "Base64 Decoding / Obfuscation Unpacker",
        "severity": "MEDIUM",
        "regex": r"\b(?:window\.)?(?:atob|btoa)\s*\(",
        "description": "Decodes base64 strings dynamically at runtime."
    },
    {
        "id": "SKIM-EXFIL-BEACON",
        "name": "Network Exfiltration Beacon",
        "severity": "HIGH",
        "regex": r"navigator\.sendBeacon\s*\(",
        "description": "Uses asynchronous sendBeacon to exfiltrate telemetry or harvested data during page unload."
    }
]

def scan_script_content(content_str: str, script_name: str = "inline") -> Dict[str, Any]:
    findings = []

    # 1. Check for behavioral regex patterns
    for p in SUSPICIOUS_PATTERNS:
        matches = re.findall(p["regex"], content_str, re.IGNORECASE)
        if matches:
            findings.append({
                "rule_id": p["id"],
                "name": p["name"],
                "severity": p["severity"],
                "matches_count": len(matches),
                "description": p["description"]
            })

    # 2. Check for known C2 IOC domains
    matched_iocs = []
    for domain in KNOWN_IOC_DOMAINS:
        if domain.lower() in content_str.lower():
            matched_iocs.append(domain)

    if matched_iocs:
        findings.append({
            "rule_id": "IOC-MATCH-C2-DOMAIN",
            "name": "Known Malicious C2 Domain IOC Matched",
            "severity": "CRITICAL",
            "matches_count": len(matched_iocs),
            "domains": matched_iocs,
            "description": f"Script contains hardcoded reference(s) to known adversary C2 host(s): {', '.join(matched_iocs)}"
        })

    is_suspicious = any(f["severity"] in ("CRITICAL", "HIGH") for f in findings)

    return {
        "target": script_name,
        "is_suspicious": is_suspicious,
        "findings_count": len(findings),
        "findings": findings
    }
