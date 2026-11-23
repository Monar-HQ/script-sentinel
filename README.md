# CodeSentinel (ScriptSentinel)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![Security: PCI-DSS v4.0](https://img.shields.io/badge/PCI--DSS_v4.0-Req_6.4.3_%26_11.6.1-red.svg)](https://www.pcisecuritystandards.org/)

**CodeSentinel** is a CLI-first open-source security tool designed to audit third-party JavaScript, detect client-side supply-chain compromises (such as Magecart, OPTIJACK / CVE-2026-132224), monitor script integrity drift, identify dangerous Content-Security-Policy (CSP) misconfigurations, and generate verifiable, drop-in remediations.

---

## The Problem: Client-Side Blind Spots
Modern web applications pull dozens of external scripts directly into the document root (analytics, A/B testing, tag managers, support widgets). When an upstream vendor control plane or CDN is compromised, malicious code executes directly within your end-users' browser sessions—harvesting credit cards, credentials, and session tokens before encryption.

Traditional perimeter defenses (WAFs, network firewalls, and server SIEMs) are completely blind to client-side DOM execution.

CodeSentinel solves this by providing:
1. **Automated Inventory & Script Harvester**: Extracts and audits all inline and external `<script>` elements.
2. **Cryptographic Integrity & Drift Tracking**: Computes Subresource Integrity (SRI) hashes and detects unauthorized upstream vendor code alterations in real time.
3. **Deep CSP Vulnerability Analysis**: Grades your CSP policy (A to F) and pinpoints fatal keywords (`'unsafe-eval'`, `'unsafe-inline'`, loose `'strict-dynamic'`, wildcard `connect-src`).
4. **Behavioral AST & Threat Scanning**: Statically inspects JavaScript payloads for payment field scraping, DOM keystroke listeners, clipboard hijacking, dynamic evaluations, and known C2 IOC domains.
5. **Actionable Remediation Quick-Pack**: Auto-generates production-ready hardened CSP headers, Nginx/Apache configurations, and exact drop-in SRI script tags.

---

## Installation

```bash
git clone https://github.com/your-username/codesentinel.git
cd codesentinel
pip install -e .
```

Requires Python 3.10+.

---

## Quick Start

### 1. Audit a Target Page
Scan any web application endpoint (e.g. checkout or login form):

```bash
scriptsentinel audit https://example.com/checkout
```

### 2. Audit with Hash Baseline Drift Detection
Pin your known-good baseline script hashes and flag when a vendor pushes unexpected changes:

```bash
scriptsentinel audit https://example.com/checkout --baseline baselines.json --output audit_report.json
```

### 3. Generate Remediation Drop-Ins
Output hardened CSP and copy-pasteable SRI tags:

```bash
scriptsentinel remediate https://example.com/checkout
```

---

## Example Audit Output

```text
  ____          _      ____             _   _            _ 
 / ___|___   __| | ___/ ___|  ___ _ __ | |_(_)_ __   ___| |
| |   / _ \ / _` |/ _ \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
| |__| (_) | (_| |  __/___) |  __/ | | | |_| | | | |  __/ |
 \____\___/ \__,_|\___|____/ \___|_| |_|\__|_|_| |_|\___|_|
 Open-Source Client-Side Supply-Chain Defense & Script Auditor v0.1.0

┌────────────────────────── Audit Executive Summary ──────────────────────────┐
│ Target URL: http://localhost:8100/no-csp/checkout                           │
│ HTTP Status: 200                                                            │
│ Overall Risk Rating: CRITICAL                                               │
│ CSP Health Grade: F (0/100)                                                 │
│ Total Scripts Discovered: 1 (1 external, 0 inline)                          │
└─────────────────────────────────────────────────────────────────────────────┘
                CSP Misconfigurations & Vulnerability Exposure                 
┌─────────────┬──────────┬──────────────────────────┬─────────────────────────┐
│ Rule ID     │ Severity │ Finding                  │ Actionable Remediation  │
├─────────────┼──────────┼──────────────────────────┼─────────────────────────┤
│ CSP-MISSING │ CRITICAL │ Content-Security-Policy  │ Deploy a strict CSP     │
│             │          │ Header Missing           │ enforcing nonces &      │
│             │          │                          │ restricted connect-src. │
└─────────────┴──────────┴──────────────────────────┴─────────────────────────┘
                  JavaScript Inventory, SRI & Behavioral Scan                  
┌───┬────────────────────┬─────────────┬─────────────────┬────────────────────┐
│ # │ Origin / Source    │ SRI Status  │ SHA-256 (Trunc) │ Threat Findings    │
├───┼────────────────────┼─────────────┼─────────────────┼────────────────────┤
│ 0 │ https://cdn.vendor │ MISSING_SRI │ 1ddc1b32fb1e... │ SKIM-EVAL-EXEC     │
└───┴────────────────────┴─────────────┴─────────────────┴────────────────────┘
```

---

## Compliance Mapping

* **PCI-DSS v4.0 Requirement 6.4.3**: Confirms third-party scripts on payment pages are justified, inventoried, and integrity-verified.
* **PCI-DSS v4.0 Requirement 11.6.1**: Verifies HTTP tamper-detection headers and script drift monitoring mechanisms.

---

## License
MIT License.
