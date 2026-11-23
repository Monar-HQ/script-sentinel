# PCI-DSS v4.0 Compliance Mapping Guide

PCI-DSS version 4.0 introduced mandatory requirements targeting client-side payment security to combat browser-based digital skimming (Magecart, formjacking, and upstream CDN tampering). 

This document details how **ScriptSentinel** (`scriptsentinel`) provides the technical enforcement, inventory tracking, and cryptographic proofs required to satisfy **Requirement 6.4.3** and **Requirement 11.6.1**.

---

## 1. Regulatory Background: Why Client-Side Requirements Were Mandated

Prior to PCI-DSS v4.0, compliance assessments focused almost exclusively on server-side architecture (firewalls, encryption at rest, segmentation, and access controls). Attackers adapted by bypassing the server entirely: compromising upstream JavaScript files hosted on third-party CDNs and harvesting cardholder data directly out of the browser's Document Object Model (DOM).

To close this attack surface, the PCI Security Standards Council (SSC) introduced two binding mandates:
1. **Requirement 6.4.3**: Management and verification of all scripts running in consumer browsers on payment pages.
2. **Requirement 11.6.1**: Change- and tamper-detection mechanisms for payment page HTTP headers and content.

---

## 2. Requirement 6.4.3: Script Authorization & Integrity Verification

> *"All payment page scripts that are loaded and executed in the consumer’s browser are managed as follows:*
> *• A method is implemented to confirm that each script is authorized.*
> *• A method is implemented to ensure the integrity of each script.*
> *• An inventory of all scripts is maintained with written justification for why each is necessary."*
> — **PCI-DSS v4.0 Requirement 6.4.3**

### How ScriptSentinel Enforces Requirement 6.4.3:

| Sub-Requirement | ScriptSentinel Technical Implementation | Audit Evidence Generated |
| :--- | :--- | :--- |
| **Script Authorization** | Audits DOM to extract complete inventory of inline and external `<script>` elements. Validates origins against approved whitelist in `--baseline` configuration. | `audit_report.json` containing `scripts_audit` inventory with origin domain validation. |
| **Script Integrity** | Computes SHA-256 and SHA-384 cryptographic digests for every discovered script. Detects missing `integrity` attributes (`MISSING_SRI`) and flags hash drift (`SCRIPT_DRIFT`). Generates valid W3C Subresource Integrity (SRI) hashes (`sri_sha256`, `sri_sha384`). | `integrity_status` field for every script: `VERIFIED`, `MISSING_SRI`, or `SCRIPT_DRIFT`. |
| **Maintained Inventory & Justification** | Outputs structured inventory files (`audit_report.json`) suitable for integration into internal compliance GRC tooling and version control. | Machine-readable JSON script manifest recording byte count, cryptographic hash, script URL, and timestamp. |

### Operational Workflow for Req 6.4.3:
```bash
# 1. Establish an approved cryptographic baseline for your payment page
scriptsentinel audit https://checkout.merchant.com/pay --output payment_baseline.json

# 2. In CI/CD or staging, generate drop-in SRI tags with computed hashes
scriptsentinel remediate https://checkout.merchant.com/pay
```

---

## 3. Requirement 11.6.1: Tamper- and Drift-Detection Mechanisms

> *"A change- and tamper-detection mechanism is deployed as follows:*
> *• To alert personnel to unauthorized modification (including changes to the content of the script or the headers) of the payment pages as received by the consumer browser.*
> *• The mechanism is configured to evaluate the received page at least once every seven days or periodically at the frequency defined in the entity's targeted risk analysis."*
> — **PCI-DSS v4.0 Requirement 11.6.1**

### How ScriptSentinel Enforces Requirement 11.6.1:

| Mandate Element | ScriptSentinel Enforcement Mechanism | Output Verification |
| :--- | :--- | :--- |
| **HTTP Header Tampering** | Parses response headers and alerts on Content-Security-Policy modifications, missing security headers, or open `connect-src` directives that permit data exfiltration. | CSP health score and detailed finding logs (`CSP-MISSING`, `CSP-UNSAFE-EVAL`, `CSP-CONNECT-WILDCARD`). |
| **Script Content Tampering** | Re-computes live script SHA-256 hashes and compares against the pinned baseline (`--baseline`). Triggers an immediate `SCRIPT_DRIFT` critical alert upon single-byte code divergence. | `drift_detected: true` flag and terminal alert identifying the exact altered script URL. |
| **Automated Periodic Evaluation** | ScriptSentinel CLI is lightweight and deterministic, enabling execution via GitHub Actions, GitLab CI, Kubernetes cronjobs, or synthetic monitoring every hour or day (exceeding the 7-day minimum). | Non-zero exit code on failure, enabling automated Slack/PagerDuty/SIEM alerting. |

### Operational Workflow for Req 11.6.1:
```bash
# Periodic automated monitor (run every 24 hours via cron or CI runner)
scriptsentinel audit https://checkout.merchant.com/pay \
  --baseline payment_baseline.json \
  --output daily_audit.json

# Exit code 1 indicates drift or critical finding; trigger incident response
if [ $? -ne 0 ]; then
  echo "CRITICAL: Script drift or CSP violation detected on payment page!"
  # Dispatch alert to SOC / SIEM
fi
```

---

## 4. Evidence Package for Qualified Security Assessors (QSAs)

When undergoing your annual PCI-DSS v4.0 assessment, provide your QSA with:
1. **Baseline Configuration File (`baselines.json`)**: Demonstrates active script inventory management and authorized cryptographic hash pinning.
2. **Automated Audit Logs (`audit_report.json`)**: Demonstrates continuous execution of tamper-detection mechanisms (Req 11.6.1).
3. **Hardened CSP Directives**: Demonstrates technical controls restricting unauthorized script injection and exfiltration channels.
4. **Subresource Integrity Deployment**: Demonstrates browser-level cryptographic enforcement on all third-party CDN scripts.

ScriptSentinel provides the complete technical foundation to achieve and maintain compliance without third-party vendor lock-in.
