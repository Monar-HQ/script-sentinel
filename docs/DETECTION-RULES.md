# CodeSentinel Detection Rule Reference

This document provides the definitive specification of all security detection rules, behavioral heuristics, integrity checks, and CSP evaluation criteria enforced by **CodeSentinel** (`scriptsentinel`).

---

## 1. Content-Security-Policy (CSP) Rules

Evaluated by `scriptsentinel.csp_analyzer` against the target endpoint's response headers.

### `CSP-MISSING`
- **Severity**: `CRITICAL` (Penalty: 35 points)
- **Title**: Content-Security-Policy Header Missing
- **Description**: The endpoint returned no `Content-Security-Policy` header. Any injected or modified script executes with complete origin authority, allowing unconstrained DOM read/write, cookie access, and outbound exfiltration.
- **Remediation**: Deploy a strict CSP header enforcing `default-src 'self'`, `script-src` with per-request cryptographic nonces, and locked-down `connect-src`.

### `CSP-UNSAFE-EVAL`
- **Severity**: `CRITICAL` (Penalty: 35 points)
- **Title**: `'unsafe-eval'` Keyword Permitted in `script-src`
- **Description**: The policy allows dynamic string evaluation via `eval()`, `new Function()`, and `setTimeout(string)`. Digital skimmers (including OPTIJACK Variant C) rely on `eval()` to unpack encrypted, obfuscated second-stage payloads in memory.
- **Remediation**: Remove `'unsafe-eval'` from `script-src` and `default-src`. Refactor dynamic evaluation logic to use static functions and typed JSON deserialization.

### `CSP-UNSAFE-INLINE`
- **Severity**: `CRITICAL` (Penalty: 35 points)
- **Title**: `'unsafe-inline'` Allowed Without Cryptographic Nonces or Hashes
- **Description**: Permits arbitrary inline `<script>` tags and inline event handlers (`onload`, `onerror`, `onclick`). Enables stored and reflected XSS payloads to execute freely.
- **Remediation**: Remove `'unsafe-inline'`. Replace with unique, cryptographically random per-response nonces (`'nonce-<random>'`) or SHA-256 hashes for static inline blocks.

### `CSP-CONNECT-WILDCARD`
- **Severity**: `CRITICAL` (Penalty: 35 points)
- **Title**: Wildcard or Unrestricted `connect-src` Exfiltration Vector
- **Description**: `connect-src` contains wildcard `*` or open schemes (`http:`, `https:`). Governs `fetch()`, `XMLHttpRequest`, `navigator.sendBeacon()`, and `WebSocket`. An open `connect-src` allows compromised scripts to exfiltrate harvested cardholder data to arbitrary adversary C2 servers.
- **Remediation**: Restrict `connect-src` strictly to `'self'` and explicitly named, authenticated backend API origins.

### `CSP-STRICT-DYNAMIC-EXFIL-RISK`
- **Severity**: `HIGH` (Penalty: 20 points)
- **Title**: `'strict-dynamic'` Enabled Without Restricted `connect-src`
- **Description**: While `'strict-dynamic'` eases nonce deployment by trusting scripts dynamically injected by a nonced root script, any compromised vendor script carrying a valid nonce can dynamically inject child skimmers. Without a locked `connect-src`, data exfiltration cannot be stopped.
- **Remediation**: Maintain strict `connect-src 'self'` whenever `'strict-dynamic'` is deployed.

### `CSP-REPORTING-ABSENT`
- **Severity**: `MEDIUM` (Penalty: 10 points)
- **Title**: CSP Violation Reporting Not Configured
- **Description**: The policy lacks `report-uri` or `report-to` directives. Browser-side policy violations, injection attempts, and blocked exfiltrations are silenced and never reach the security operations team.
- **Remediation**: Configure `report-uri /api/csp-report` or the Reporting API `report-to` directive to stream real-time violation logs into your SIEM.

---

## 2. Subresource Integrity (SRI) & Drift Rules

Evaluated by `scriptsentinel.integrity` against external script bytes and baseline ledgers.

### `SCRIPT_DRIFT`
- **Severity**: `CRITICAL`
- **Description**: The SHA-256 digest of the downloaded script does not match the pinned hash recorded in `--baseline <file>`. Indicates that an upstream third-party vendor, CDN, or AWS S3 bucket was modified or compromised.
- **Action**: Alert security operations immediately. Block script loading or freeze deployment until the vendor code diff has been verified.

### `INTEGRITY_MISMATCH`
- **Severity**: `CRITICAL`
- **Description**: The script tag declared an `integrity` attribute (e.g., `integrity="sha256-..."`), but the actual downloaded bytes compute to a different digest.
- **Behavior**: The browser will actively block script execution with an integrity error. Verify whether the vendor updated their asset without coordinating SRI updates.

### `MISSING_SRI`
- **Severity**: `HIGH`
- **Description**: An external JavaScript resource is loaded via `<script src="...">` without an `integrity` attribute. The browser will execute whatever content the remote server serves without cryptographic verification.
- **Action**: Add `integrity="sha256-<hash>"` and `crossorigin="anonymous"` to the script element using CodeSentinel's remediation generator.

### `VERIFIED`
- **Severity**: `INFO`
- **Description**: The external script possesses a valid SRI attribute that matches calculated cryptographic digests, and matches any pinned baseline.

---

## 3. Behavioral AST & Threat Scanner Rules

Evaluated by `scriptsentinel.scanner` inspecting raw and reconstructed JavaScript source code.

| Rule ID | Severity | Threat Pattern | Description |
| :--- | :---: | :--- | :--- |
| `SKIM-INPUT-HARVEST` | `CRITICAL` | `(?:card(?:number|_no)?\|cvv\|cvc\|expir(?:y\|ation)\|password\|passwd\|ssn)\b` | Script inspects, accesses, or scrapes values from sensitive payment card, CVV, password, or SSN DOM form fields. |
| `SKIM-DOM-LISTENER` | `HIGH` | `addEventListener\s*\(\s*['"](?:input\|change\|keydown\|keyup\|keypress\|submit)` | Script attaches global event listeners to intercept keystrokes or watch form submissions in real time. |
| `SKIM-CLIPBOARD-TAMPER`| `HIGH` | `navigator\.(?:clipboard\.(?:readText\|writeText)\|clipboard)\b` | Script interacts directly with the clipboard API (crypto clippers, credential scrapers). |
| `SKIM-EVAL-EXEC` | `CRITICAL` | `\b(?:eval\s*\( \| new\s+Function\s*\( \| setTimeout\s*\(\s*['"][^,])` | Script compiles dynamic strings into executable code to bypass static scanner signatures. |
| `SKIM-BASE64-UNPACK` | `MEDIUM` | `\b(?:window\.)?(?:atob\|btoa)\s*\(` | Dynamic runtime decoding of base64 payloads, frequently used in multi-stage skimmer loaders. |
| `SKIM-EXFIL-BEACON` | `HIGH` | `navigator\.sendBeacon\s*\(` | Asynchronous exfiltration dispatching harvested data during page transitions or unload events. |
| `IOC-MATCH-C2-DOMAIN` | `CRITICAL` | Hardcoded C2 domain matching threat intelligence feed | Script references known adversary C2 infrastructure (e.g., OPTIJACK, Magecart, or rogue drop domains). |

---

## 4. CSP Health Grading Matrix

The CSP Health Score starts at **100** points. Penalties are deducted based on findings:
- **CRITICAL**: −35 points
- **HIGH**: −20 points
- **MEDIUM**: −10 points
- **LOW**: −5 points

The final score determines the grade:

| Score Range | Grade | Security Posture |
| :---: | :---: | :--- |
| **90 – 100** | **A** | Excellent. Nonced scripts, locked `connect-src 'self'`, reporting enabled, no `unsafe-inline`/`eval`. |
| **75 – 89** | **B** | Strong. Minor omissions (e.g. reporting absent or minor non-critical directive gaps). |
| **50 – 74** | **C** | Moderate. One high-severity finding present (e.g. unconstrained `connect-src`). |
| **30 – 49** | **D** | Poor. Multiple severe weaknesses (e.g. `unsafe-eval` and open exfiltration channels). |
| **0 – 29** | **F** | Failing. CSP missing entirely, or multiple critical vulnerabilities present. |

---

## 5. Contributing New Rules

To contribute new skimmer patterns or adversary C2 domains:
1. Behavioral patterns: Add rule dictionaries to `SUSPICIOUS_PATTERNS` in `src/scriptsentinel/scanner.py`.
2. IOC domains: Submit additions to `src/scriptsentinel/iocs/feeds/malicious_c2.json` or create a new feed under `src/scriptsentinel/iocs/feeds/`.
3. Verify test coverage: Run `pytest` and ensure `ruff check .` passes without warnings.
