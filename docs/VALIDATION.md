# Validation record — 2026-11-24

Candidate version: **1.0.0rc1**. Repository delivery is authorized; production
release gates remain open.

Latest Windows checks: Python 3.12.14 ran 129 tests successfully with three
historical lab tests skipped. Python 3.14.7 ran 127 tests successfully with
five skipped (the same lab tests plus the optional browser tests). The real
Chromium workflows ran under 3.12. Unclosed SQLite connections found during
3.14 validation were corrected with explicit transaction/connection lifetimes.

## Executed checks

### Remote CI

[GitHub Actions run 45435739490](https://github.com/Monar-HQ/scriptsentinel/actions/runs/45435739490)
passed for commit `6e782bd`: Python 3.12 and 3.14 on Windows, Linux and macOS,
lint and strict typing, real Chromium workflows, the locked dependency audit,
and a wheel/source build with installed-package smoke checks. All ten jobs
completed successfully. Subsequent commits have their own Actions records;
this result applies to the named commit.

### Local checks

- Windows / CPython 3.12.14 with the locked Core, browser, credentials and dev
  dependencies; fixed Soup Sieve 4.0 is installed.
- Ruff and strict Mypy across 39 source modules.
- Full Pytest suite, including two real Chromium end-to-end workflows. The three
  historical OPTIJACK integration tests are skipped while those services are
  stopped. They have not been substituted with invented incident results.
- Desktop and 390px phone layout, console navigation, demo evidence, real inventory
  cells, research and activity views; no page script errors or horizontal overflow.
- Authorized localhost observation captures a dynamically loaded harmless script
  and blocks a POST. No third-party exploit or attack harness is run.
- Baseline drift, persistence across restart, scoped redirects, compressed response
  handling, proposal tampering, isolated validation, approval, recovery and
  rollback after an injected receipt-write failure.
- Provider endpoint contracts, key separation, prompt minimization, retry/request
  budgets, invalid responses and outage fallback using mock transports.
- The disclosed AST corpus: five capability fixtures and five benign fixtures.
  It tests syntax signals, not real-world malware detection accuracy.
- Gitleaks directory scan with redaction. A clean scan is a bounded check, not
  proof that a secret has never existed in history or third-party artifacts.
- Locked dependency audit. Initial Soup Sieve findings were addressed by raising
  the supported Python minimum to 3.11.5 and pinning fixed 4.x dependencies.
  The updated Python 3.12 dependency audit reports no known vulnerabilities.

## Distribution checks

Wheel and source archive builds, clean installation smoke tests, packaged demo
and research data, local standalone build and software inventory are exercised
in the development workflow. Artifact checksums are not digital signatures.
The final local command results and artifacts are retained under `dist/v1/`.

Reproduce with the locked environment:

```text
uv sync --frozen --extra dev --extra browser --extra credentials --extra release --python 3.12
uv run --frozen --all-extras ruff check .
uv run --frozen --all-extras mypy --strict src/scriptsentinel
uv run --frozen --all-extras pytest -ra
scriptsentinel benchmark
```

Set `SCRIPTSENTINEL_BROWSER_EXECUTABLE` to an installed Chromium executable to
enable the optional real-browser tests. Otherwise they are explicitly skipped.
Do not mistake a skipped workflow for a passed workflow.

## Not executed or certified

A separate read-only model security review found staging-path traversal,
linked-state-file writes, incomplete JavaScript MIME classification, base-URL
resolution gaps and discovery budgets applied too late. Those paths were fixed
and covered by additional regression tests. The reviewer did not run exploits
or certify production security; runtime verification was performed separately.

No Docker/Kubernetes deployment, paid provider request, independent human security audit, production application
compatibility test, platform code signing or public release was performed.
Docker was unavailable locally. Snyk tooling was unavailable. C: was full; builds
and tooling used D: without deleting user files. No application deployment,
external package publication or deployment occurred. The owner subsequently
authorized delivery to main; the commit's GitHub Actions run is the source of
truth for remote check outcomes.

Source-level review and tests do not close these external release gates. See
docs/RELEASE.md and THREAT_MODEL.md for the limitations that remain relevant in
real deployments, particularly full CSP semantics, whole-program dataflow,
browser egress isolation and application-specific compatibility.
