# CI Gate

ScriptSentinel ships a composite action at the repository root and a reusable workflow at `.github/workflows/scriptsentinel-gate.yml`. Both run the same audit and fail the job at the requested threshold.

## Composite Action Inputs

| Input | Required | Default | Purpose |
| --- | --- | --- | --- |
| `url` | Yes | — | Target page URL to audit. |
| `baseline` | No | `""` | Path to a baseline SHA-256 JSON file. Leave empty to skip drift comparison. |
| `fail-on` | No | `high` | Exit threshold: `none`, `low`, `medium`, `high`, `critical`, or `drift`. |
| `report-path` | No | `scriptsentinel-report.json` | Path for the JSON audit report. |
| `python-version` | No | `3.12` | Python version used to install and run ScriptSentinel. |

## Outputs

| Output | Source | Purpose |
| --- | --- | --- |
| `report-path` | Input echo | Written JSON report path. |
| `risk` | Audit report | Overall risk rating (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `ERROR`). |

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Audit completed and did not meet the `fail-on` threshold; no drift when `fail-on: drift`. |
| `1` | Risk met or exceeded the threshold, or script drift was detected. |
| `2` | CLI argument error (argparse). |

`monitor` always exits `1` when a pinned baseline hash changes, regardless of `--fail-on`.

## Baseline Schema

```json
{
  "https://cdn.vendor.example/js/tag.js": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

Keys are exact script URLs. Values are lowercase 64-character SHA-256 hex digests.

## Composite Action Usage

```yaml
name: Script integrity gate

on: [pull_request]

jobs:
  scriptsentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Ally-Released/scriptsentinel@main
        with:
          url: https://checkout.example.com
          baseline: baselines/checkout.json
          fail-on: drift
          report-path: scriptsentinel-report.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: scriptsentinel-report
          path: scriptsentinel-report.json
```

The action installs the package from its own action path, so the caller repository can keep its baseline and report files in its own workspace.

## Reusable Workflow Usage

```yaml
jobs:
  gate:
    uses: Ally-Released/scriptsentinel/.github/workflows/scriptsentinel-gate.yml@main
    with:
      url: https://checkout.example.com
      baseline: baselines/checkout.json
      fail-on: high
      report-path: scriptsentinel-report.json
```

The reusable workflow checks out the caller repository, runs the remote action, uploads the JSON report, and exposes the `risk` output.

## Pinning

Pin the action or workflow to a commit SHA in production:

```yaml
uses: Ally-Released/scriptsentinel@<commit-sha>
```

This prevents unreviewed changes from altering the gate.

## Evidence

The JSON report includes `target_url`, `timestamp`, `status_code`, `overall_risk`, `summary`, `csp`, `scripts`, and `remediation`. Upload it as a CI artifact or forward it to a SIEM.
