# ScriptSentinel Audit Report

**Target:** `http://localhost:8100/no-csp/checkout`
**Timestamp:** 2026-11-23T23:18:29+00:00

## Executive Summary

| Metric | Value |
| --- | --- |
| Target URL | http://localhost:8100/no-csp/checkout |
| Timestamp | 2026-11-23T23:18:29+00:00 |
| HTTP Status | 200 |
| Overall Risk | **CRITICAL** |
| CSP Grade | F (0/100) |
| Scripts Audited | 1 (1 external, 0 inline) |
| Remediation Pack | available |

## CSP Findings

| Rule ID | Severity | Finding | Description | Recommendation | Evidence |
| --- | --- | --- | --- | --- | --- |
| CSP-MISSING | **CRITICAL** | Content-Security-Policy Header Missing | The application returns no Content-Security-Policy header. Injected third-party JavaScript executes with full origin authority and can exfiltrate DOM inputs, cookies, and tokens without restriction. | Deploy a strict CSP enforcing default-src 'self', script-src with cryptographic nonces, and a restricted connect-src. | n/a |

## Script Inventory

| # | Type | Source | Nonce | SRI Status | SHA-256 | Scan Findings |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | external | http://localhost:8001/js/acme.js | n/a | MISSING_SRI | 1ddc1b32fb1e... | clean |

## Integrity Findings

- **HIGH** `MISSING_SRI` on `http://localhost:8001/js/acme.js`: Script 'http://localhost:8001/js/acme.js' is loaded without a Subresource Integrity attribute. Any upstream vendor compromise executes without cryptographic verification.

## Developer Action Checklist

- [ ] **CRITICAL** `CSP-MISSING`: Deploy a strict CSP enforcing default-src 'self', script-src with cryptographic nonces, and a restricted connect-src.
- [ ] Resolve `MISSING_SRI` on `http://localhost:8001/js/acme.js`: Script 'http://localhost:8001/js/acme.js' is loaded without a Subresource Integrity attribute. Any upstream vendor compromise executes without cryptographic verification.
- [ ] Deploy the hardened CSP header from the remediation pack.
- [ ] Replace external script tags with the generated SRI tags.
- [ ] Configure CSP violation reporting via `report-uri` or `report-to`.
- [ ] Re-run the audit after remediation and pin SHA-256 baselines for drift detection.

## Remediation Pack

### Hardened CSP

```http
default-src 'self'; script-src 'self' 'nonce-{NONCE}' http://localhost:8001; script-src-elem 'self' 'nonce-{NONCE}' http://localhost:8001; connect-src 'self'; style-src 'self'; img-src 'self' data: https:; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'; report-uri /api/csp-report
```

### SRI Replacement Tags

**Source:** `http://localhost:8001/js/acme.js`

```html
<script src="http://localhost:8001/js/acme.js" integrity="sha256-HdwbMvseS8acAXHY00VRiX4AG9aivqn38TbzRUKFiwE=" crossorigin="anonymous"></script>
```

### Nginx Configuration

```nginx
# Nginx security configuration (ScriptSentinel hardened)
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-{NONCE}' http://localhost:8001; script-src-elem 'self' 'nonce-{NONCE}' http://localhost:8001; connect-src 'self'; style-src 'self'; img-src 'self' data: https:; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'; report-uri /api/csp-report" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

```

### Apache Configuration

```apache
# Apache security configuration (ScriptSentinel hardened)
Header set Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-{NONCE}' http://localhost:8001; script-src-elem 'self' 'nonce-{NONCE}' http://localhost:8001; connect-src 'self'; style-src 'self'; img-src 'self' data: https:; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'; report-uri /api/csp-report"
Header set X-Content-Type-Options "nosniff"
Header set X-Frame-Options "DENY"
Header set Referrer-Policy "strict-origin-when-cross-origin"

```

### Compliance Mapping

| Standard | Requirement | Status |
| --- | --- | --- |
| PCI-DSS v4.0 Requirement 6.4.3 | All payment page scripts must be authorized, justified, and integrity-verified. | PASS with generated SRI tags and explicit script inventory. |
| PCI-DSS v4.0 Requirement 11.6.1 | Change- and tamper-detection mechanism for payment page HTTP headers and contents. | PASS when script hash drift monitoring and CSP reporting are active. |
