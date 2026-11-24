# v1 release candidate gates

Local development version: **1.0.0rc1**. This is not a public release or a claim
that every production acceptance criterion has passed.

## Automated local gates

Run Ruff, strict Mypy, Pytest, the optional real Chromium suite, the disclosed
AST benchmark, wheel/sdist build and a fresh-wheel installation. Verify bundled
UI, demo, research and IOC data. Build standalone executables natively per OS.
Review dependency locks and an SBOM before distribution.

## Deployment and external gates

The owner authorized a push to the existing repository's main branch. That
does not authorize a package publication, deployment, tag or public release.
A release operator must still obtain an independent
security review, run the OS matrix and container/cluster workflows in actual
environments, validate production compatibility, and supply platform signing
identities/provenance. No test configuration stands in for a passing run.

The current local Docker daemon was unavailable. Container and Kubernetes
configuration are supplied but are not recorded as tested deployments.
Paid provider adapters use mock transport contract tests; no live subscription
or model capability is claimed on the strength of those tests.

## Release acceptance decisions

- Local Core, dashboard, staged SRI workflow, local monitoring, read-only host
  tools, provider advisory and synthetic browser workflows have executable tests.
- AST analysis is capability analysis, not full interprocedural dataflow.
- CSP uses supported posture semantics and independent policy handling; it is
  not a complete browser policy or compatibility oracle.
- Browser observation is anonymous and read-only at the HTTP method boundary;
  it is not an OS or network sandbox.
- Application compatibility, production recovery drills and deployment must be
  validated by the owner of the real application before approval.
- Windows local results and any additional runtime checks are recorded in
  docs/VALIDATION.md. Unrun platforms remain explicitly unverified.

Historical 0.1.0 release statements are retained in the repository's Git history
and earlier development record; they are not verification of the new candidate.
