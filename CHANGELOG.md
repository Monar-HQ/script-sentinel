# Changelog

## 1.0.0rc1 — 2026-11-24

- Added the private local console with real audit evidence, inventory, baseline
  approval, monitoring, proposal validation, research and an activity ledger.
- Added Tree-sitter capability analysis, authorized browser observation, persistent
  snapshots, staged SRI validation, guarded recovery and read-only host-agent tools.
- Added provider request budgets, Gemini adapter, OS keychain support, data-only
  research packs, locked dependencies and distribution configuration.
- Redesigned the README and current visual assets; clarified Ali's and Luke's credits.
- Raised Python minimum to 3.11.5 to use fixed Soup Sieve 4.x. Updated locks after
  dependency audit. No public release, deployment or signed artifact is implied.
- See docs/VALIDATION.md for actual tests and unrun external gates.

## 0.1.0 — 2026-11-24

### Added

- Typed audit engines: script harvesting, SHA-256/SHA-384 integrity, SRI validation, CSP grading, behavioral scanning, IOC matching, and remediation packs.
- CLI subcommands: `audit`, `check-csp`, `monitor`, `remediate`, and `export-rules`.
- `--version` and `audit --fail-on {none,low,medium,high,critical,drift}` for CI gates.
- `monitor` returns exit code `1` on pinned-baseline drift.
- JSON, Markdown, and standalone HTML reporters with MONAR visual tokens.
- Sigma YAML and Suricata HTTP/DNS exporters.
- IOC loader with validation, merge, digest, and packaged OPTIJACK feeds.
- Composite action `action.yml` and reusable workflow `.github/workflows/scriptsentinel-gate.yml`.
- Documentation suite: OPTIMJACK case study, architecture, detection rules, PCI-DSS mapping, design system, CI gate, release notes.
- OPTIMJACK case study with incident narrative, CVE links, timeline, IOC analysis, OPTIJACK lab outcome matrix, remediation, critical notes, and sources.
- `CITATION.cff` for community and research citation.
- OPTIMJACK case-study SVG and PNG, plus CVE chip in the social preview.
- Dark/light hero banners, terminal showcase, architecture diagram, Unquant partner card, and 1280×640 social preview SVG/PNG.

### Changed

- Replaced dict-based scaffolds with typed dataclasses and `py.typed`.
- Replaced cyan/green/purple CLI styling with MONAR red, bone, and slate.
- Replaced gradient-heavy HTML report styling with a flat verification-ledger layout.
- Updated README, CONTRIBUTING, SECURITY, LICENSE, and issue templates to the actual Python package and IOC schema.
- README now surfaces the OPTIMJACK case study, CVE badge, source provenance, and a community star call-to-action.
- GitHub repository metadata refreshed: description, homepage, topics, and discussions enabled.
- Removed redundant banner assets and preview scratch files.

### Verification

- `python -m pytest -v`: 67 passed in 8.08s with the OPTIJACK integration tests active.
- `python -m ruff check .`: All checks passed.
- `python -m mypy --strict src/scriptsentinel`: Success, 18 source files.
- `uv build`: wheel and sdist produced successfully.
- Clean-venv wheel install: `scriptsentinel --version` returns `0.1.0`.
- Live OPTIJACK audits: strict profile CSP A/100 with `MISSING_SRI`; no-csp profile CSP F/0 with `CSP-MISSING`; monitor drift returns `1`; `audit --fail-on high` returns `1` on no-csp.
- `designmd lint docs/DESIGN.md`: passed.
- Case-study SVG and social preview rendered; Chrome text-box geometry reports no clipping or overlap.

### Artifacts

Build artifacts and SHA-256 hashes are recorded in [docs/RELEASE.md](docs/RELEASE.md#built-artifacts).

### Notes

- Repository remains private at `https://github.com/Ally-Released/scriptsentinel`; release-stage changes live on the working branch pending merge to `main`.
- Tag `v0.1.0` and the GitHub release `v0.1.0 - Initial Release` exist. PyPI publication has not been performed.
- OPTIJACK lab validation covers 144 visits across four CSP profiles and three replicas; it demonstrates mechanism, not real-world blast radius.
