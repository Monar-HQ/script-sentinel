# Detection Rules

ScriptSentinel exposes deterministic rule IDs for CSP posture, Subresource Integrity, behavioral skimming, and IOC exposure. The engine emits typed findings; reporters render them without rewriting rule logic.

## CSP Rules

| Rule ID | Severity | Penalty | Trigger | Evidence |
| --- | --- | --- | --- | --- |
| `CSP-MISSING` | CRITICAL | 35 | No `Content-Security-Policy` header. | Header absent. |
| `CSP-UNSAFE-EVAL` | CRITICAL | 35 | `'unsafe-eval'` appears in `script-src` or fallback `default-src`. | `'unsafe-eval'`. |
| `CSP-UNSAFE-INLINE` | CRITICAL | 35 | `'unsafe-inline'` appears without a nonce or hash source. | `'unsafe-inline'`. |
| `CSP-STRICT-DYNAMIC-RISK` | HIGH | 20 | `'strict-dynamic'` appears with a missing or wildcard `connect-src`. | `'strict-dynamic'`. |
| `CSP-CONNECT-WILDCARD` | CRITICAL | 35 | `connect-src` is missing, contains `*`, or contains bare `http:` / `https:`. | `*` or `connect-src absent`. |
| `CSP-REPORTING-ABSENT` | MEDIUM | 10 | Neither `report-uri` nor `report-to` is present. | `no report-uri/report-to`. |

Score is `max(0, 100 - sum(penalties))`. Grades: A ≥ 90, B ≥ 75, C ≥ 50, D ≥ 30, F < 30.

## SRI Statuses

| Status | Severity | Meaning |
| --- | --- | --- |
| `VERIFIED` | None | Declared integrity matches the calculated `sha256-...` or `sha384-...` SRI digest. |
| `MISSING_SRI` | HIGH | External script has no `integrity` attribute. |
| `INTEGRITY_MISMATCH` | CRITICAL | Declared integrity does not match the calculated digest; the browser blocks the resource. |
| `SCRIPT_DRIFT` | CRITICAL | Current SHA-256 differs from the pinned baseline; upstream content changed. |

`SCRIPT_DRIFT` overrides `VERIFIED` or `MISSING_SRI` when a baseline hash is supplied and differs.

## Behavioral Rules

| Rule ID | Severity | Logic | Description |
| --- | --- | --- | --- |
| `SKIM-INPUT-HARVEST` | CRITICAL | Matches payment/credential field names (`card`, `card_number`, `cvv`, `cvc`, `expiry`, `password`, `passwd`, `ssn`) followed by value access (`:`, `=`, `.value`, `.getAttribute`). | Script inspects or extracts payment card, CVV, or credential values. |
| `SKIM-DOM-LISTENER` | HIGH | Matches `addEventListener('input'|'change'|'keydown'|'keyup'|'keypress'|'submit')`. | Attaches global listeners to harvest keystrokes or submissions. |
| `SKIM-CLIPBOARD-TAMPER` | HIGH | Matches `navigator.clipboard.readText`, `writeText`, or `navigator.clipboard`. | Reads or writes clipboard data. |
| `SKIM-EVAL-EXEC` | CRITICAL | Matches `eval(`, `new Function(`, or `setTimeout("...")`. | Executes dynamic strings, often unpacking obfuscated payloads. |
| `SKIM-BASE64-UNPACK` | MEDIUM | Matches `atob(` or `btoa(`. | Decodes or encodes base64 at runtime. |
| `SKIM-EXFIL-BEACON` | HIGH | Matches `navigator.sendBeacon(`. | Uses asynchronous beacon exfiltration. |

## IOC Rules

| Rule ID | Severity | Logic |
| --- | --- | --- |
| `IOC-MATCH-C2-DOMAIN` | CRITICAL | Exact hostname boundary match against the packaged OPTIJACK domains and legacy C2 domains. |
| `IOC-MATCH-C2-HASH` | CRITICAL | Exact 64-hex SHA-256 boundary match against packaged IOC hashes or the script's computed SHA-256. |

IOC matching is case-insensitive and rejects substring matches.

## Packaged IOC Set

The default feed `optimjack_2026-11-23.json` contains eight domains and two SHA-256 indicators. Legacy `malicious_c2.json` adds two domains:

| Indicator | Value |
| --- | --- |
| Domain | `1688360.cc` |
| Domain | `webshell.lol` |
| Domain | `linkforge.cc` |
| Domain | `pay-cloud.online` |
| Domain | `pay.pay-cloud.online` |
| Domain | `pay-relay.wordpressadmin001.workers.dev` |
| Domain | `5vobauua3ojpklx.icu` |
| Domain | `eil786npto9u5bq.icu` |
| SHA-256 | `f7b84b9a94f749f8ced3f0112d0a66894e8bbc3b4aa5592021d1b8976a9bad40` |
| SHA-256 | `814a963c0da480e2449d9b6664480156e1cd6d731014117401bf635badec3a0f` |

## OPTIJACK Validation

The rules were validated against the local OPTIJACK telemetry slices. Counts are true positives in the attack-only slice; false positives were zero in the clean slice.

| Rule | TP | FP |
| --- | --- | --- |
| IOC-1 | 108 | 0 |
| IOC-2 | 0 | 0 |
| IOC-3 | 111 | 0 |
| BEH-1 | 24 | 0 |
| BEH-2 | 9 | 0 |
| BEH-3 | 18 | 0 |
| BEH-4 | 54 | 0 |
| BEH-5 | 12 | 0 |
| BEH-6 | 54 | 0 |

IOC-2 is the `track.js` hash indicator. `track.js` was not served in the lab, so TP is zero and the rule remains retained as a real-world indicator.

Scale note: the lab covers 144 visits across four CSP profiles and three replicas. It demonstrates the detection mechanism; it does not generalize to the 178 organizations in the source incident.

## Rule Export

- Sigma: 8 domain indicators, one rule per host, tags include `attack.c2`, `attack.exfiltration`, and `attack.javascript`.
- Suricata: 16 alerts, 8 HTTP host rules and 8 DNS query rules.

Exports are generated from the packaged feed and an optional live audit:

```bash
scriptsentinel export-rules --format sigma --output rules/sigma.yml
scriptsentinel export-rules --format suricata --output rules/suricata.rules
```
