# PCI-DSS v4.0 Mapping

ScriptSentinel produces audit evidence for payment-page script control and change detection. The mapping covers Requirement 6.4.3 and Requirement 11.6.1. Incident context and control analysis are in [docs/CASE-STUDY.md](CASE-STUDY.md).

## Requirement 6.4.3 — Payment Page Scripts

Requirement 6.4.3 requires that all payment page scripts loaded into the consumer browser are authorized, justified, and integrity-verified.

| Evidence | Source | Field |
| --- | --- | --- |
| Full script inventory | `AuditReport.scripts` | `index`, `kind`, `url`, `nonce`, `length` |
| Declared integrity | `ScriptIntegrityResult.declared_integrity` | Declared `integrity` attribute |
| Calculated SRI digests | `HashDigests.sri_sha256`, `HashDigests.sri_sha384` | Base64 SRI strings |
| Canonical SHA-256/SHA-384 | `HashDigests.sha256`, `HashDigests.sha384` | Hex digests |
| CSP authorization | `CSPAnalysis.directives` | `script-src`, `script-src-elem`, `default-src` |
| Hardened CSP | `RemediationPack.hardened_csp` | Nonced `default-src 'self'` policy |
| Replacement tags | `RemediationPack.sri_replacement_tags` | Drop-in `<script>` tags with SRI and `crossorigin` |

`remediate.py` emits a compliance item:

> PCI-DSS v4.0 Requirement 6.4.3 — PASS with generated SRI tags and explicit script inventory.

## Requirement 11.6.1 — Change and Tamper Detection

Requirement 11.6.1 requires a change- and tamper-detection mechanism for payment page HTTP headers and contents.

| Evidence | Source | Field |
| --- | --- | --- |
| Pinned baseline | Operator-supplied JSON | URL → SHA-256 hex |
| Observed SHA-256 | `ScriptIntegrityResult.calculated.sha256` | Current fetched bytes |
| Drift status | `ScriptIntegrityResult.status` | `SCRIPT_DRIFT` |
| Drift flag | `ScriptIntegrityResult.drift_detected` | Boolean |
| Drift evidence | `IntegrityIssue` | Expected and observed SHA-256 |
| CSP reporting | `CSPAnalysis.directives` | `report-uri` / `report-to` |
| Deterministic report | `report/*.json` | Full audit record |

`remediate.py` emits a compliance item:

> PCI-DSS v4.0 Requirement 11.6.1 — PASS when script hash drift monitoring and CSP reporting are active.

## Baseline Format

```json
{
  "https://cdn.vendor.example/js/tag.js": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

Keys are exact script URLs. Values are lowercase 64-character SHA-256 hex digests. `monitor` compares the fetched bytes against this map and exits `1` on drift.

## Audit Commands

```bash
# Full audit with baseline and JSON evidence
scriptsentinel audit https://checkout.example.com \
  --baseline baselines/checkout.json \
  --format json \
  --output report/checkout.json \
  --fail-on drift

# Drift-only gate with webhook alert
scriptsentinel monitor https://checkout.example.com \
  --baseline baselines/checkout.json \
  --alert-webhook https://hooks.example.com/security

# Hardened CSP and SRI pack
scriptsentinel remediate https://checkout.example.com
```

## Evidence Artifacts

| Artifact | Purpose |
| --- | --- |
| `report/*.json` | Machine-readable audit evidence for SIEM, CI, and change records. |
| `report/*.md` | Human-readable audit with developer action checklist. |
| `report/*.html` | Standalone MONAR-styled audit report. |
| `rules/sigma.yml` | Sigma rule export for C2 domains. |
| `rules/suricata.rules` | Suricata HTTP and DNS alert rules. |

## Scope Note

This mapping is evidence support for PCI-DSS v4.0 Requirements 6.4.3 and 11.6.1. It is not a certification claim; assessors evaluate the deployed controls and the operator's baseline maintenance process.
