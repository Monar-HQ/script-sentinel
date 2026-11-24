# CI gate

Use an installed checkout or wheel and run a scoped audit against an authorized
staging page. Additional exact origins must be explicitly authorized.

```text
scriptsentinel audit https://owned-staging.example/checkout --allow-origin https://approved-cdn.example --baseline approved-url-hashes.json --output audit.json --format json --fail-on high
```

The HTTP baseline is a URL-to-SHA-256 map. It is different from the reviewed
local baseline schema used by local proposals. Establish it from independently
reviewed artifacts; do not blindly approve the current network response.

Exit 0 means the command completed within the selected threshold. Exit 1 means
the risk/drift threshold was met. Exit 2 means invalid configuration, failed
fetches or incomplete analysis. `--fail-on none` never turns a failed audit into
success. An unrun or skipped workflow must remain visible.

The composite action accepts URL, baseline, threshold, report path and additional
origins. Input values travel through environment variables and quoted argument
arrays, not direct shell interpolation. Pin your chosen action revision after
review; using a mutable main branch is not a release-integrity guarantee.

The supplied CI matrix covers Windows/Linux/macOS and Python 3.12/3.14. A separate
job installs Chromium and exercises the harmless browser workflows. Package
builds include wheel/source smoke checks and a software inventory. The locked
runtime dependency audit is an explicit gate. Configuration alone is not
evidence that these remote jobs have run.
