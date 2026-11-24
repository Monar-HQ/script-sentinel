# Changelog

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
- Documentation suite: architecture, detection rules, PCI-DSS mapping, design system, CI gate, release notes.
- Dark/light hero banners, terminal showcase, architecture diagram, Unquant partner card, and 1280×640 social preview SVG/PNG.

### Changed

- Replaced dict-based scaffolds with typed dataclasses and `py.typed`.
- Replaced cyan/green/purple CLI styling with MONAR red, bone, and slate.
- Replaced gradient-heavy HTML report styling with a flat verification-ledger layout.
- Updated README, CONTRIBUTING, SECURITY, LICENSE, and issue templates to the actual Python package and IOC schema.
- Removed redundant banner assets and preview scratch files.

### Verification

- `python -m pytest -v`: 67 passed in 8.06s with the OPTIJACK integration tests active.
- `python -m ruff check .`: All checks passed.
- `python -m mypy --strict src/scriptsentinel`: Success, 18 source files.
- `uv build`: wheel and sdist produced successfully.
- Clean-venv wheel install: `scriptsentinel --version` returns `0.1.0`.
- Live OPTIJACK audits: strict profile CSP A/100 with `MISSING_SRI`; no-csp profile CSP F/0 with `CSP-MISSING`; monitor drift returns `1`; `audit --fail-on high` returns `1` on no-csp.

### Artifacts

| Artifact | Size | SHA-256 |
| --- | --- | --- |
| `scriptsentinel-0.1.0-py3-none-any.whl` | 48,185 bytes | `df520ddff50bf91f19e82b565a994725b01fe3f6eeba58628366e727f526a01d` |
| `scriptsentinel-0.1.0.tar.gz` | 138,199 bytes | `a289330ef6d7e2df285a292d85f76773b9bb6367a1aad89f03850b88511ccca0` |

### Notes

- Repository remains private at `https://github.com/Ally-Released/scriptsentinel`; release-stage changes pushed to `main`.
- No PyPI publication, tag, or GitHub release has been created.
- Telegram notification delivered to chat `5700018165` (`message_id` 63).
- OPTIJACK lab validation covers 144 visits across four CSP profiles and three replicas; it demonstrates mechanism, not real-world blast radius.
