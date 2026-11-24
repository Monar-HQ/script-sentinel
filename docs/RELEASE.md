# Release 0.1.0

ScriptSentinel 0.1.0 is prepared for release under MONAR. The repository remains private; no PyPI publication, tag, or GitHub release has been performed in this stage.

## Release Scope

| Area | Artifact |
| --- | --- |
| Package | `src/scriptsentinel/` typed modules, `py.typed`, console script `scriptsentinel` |
| CLI | `audit`, `check-csp`, `monitor`, `remediate`, `export-rules`, `--version`, `--fail-on` |
| Reports | Terminal, JSON, Markdown, standalone HTML |
| Rules | Sigma YAML, Suricata HTTP/DNS |
| IOC feeds | `optimjack_2026-11-23.json`, `malicious_c2.json` |
| Documentation | README, OPTIMJACK case study, architecture, detection rules, PCI-DSS mapping, design system, CI gate, release notes |
| Visuals | Dark/light hero banners, terminal showcase, OPTIMJACK case-study card, architecture diagram, Unquant partner card, social preview SVG + PNG |
| Citation | `CITATION.cff` for community and research citation |
| CI | `ci.yml`, composite action `action.yml`, reusable workflow `scriptsentinel-gate.yml` |
| Evidence | `report/*`, `examples/baseline.json`, `CHANGELOG.md` |

## Verification Gates

Run from the repository root:

```bash
python -m pytest -v
python -m ruff check .
python -m mypy --strict src/scriptsentinel
```

Result on 2026-11-24:

- `python -m pytest -v`: 67 passed in 8.08s with OPTIJACK integration tests active.
- `python -m ruff check .`: All checks passed.
- `python -m mypy --strict src/scriptsentinel`: Success, 18 source files.
- `uv build`: wheel and sdist produced successfully.
- Clean-venv wheel install: `scriptsentinel --version` returns `0.1.0`.
- `scriptsentinel --help` lists `audit`, `check-csp`, `monitor`, `remediate`, and `export-rules`.
- `designmd lint docs/DESIGN.md`: passed.
- Case-study SVG and social preview rendered at 846×440 and 1280×640; Chrome text-box geometry reports no clipping or overlap.
- Case-study links checked against CVE Record, NVD, GHSA, Optimizely advisory, Report URI, StepSecurity, Unit42, Salesforce Security, and Netskope Threat Labs.

## Built Artifacts

| Artifact | Size | SHA-256 |
| --- | --- | --- |
| `dist/scriptsentinel-0.1.0-py3-none-any.whl` | 49,710 bytes | `e70463aaa8d4e2d95fcfa4efe716d36d3a363c21a4531d2fa00430fef4a26c7c` |
| `dist/scriptsentinel-0.1.0.tar.gz` | 183,889 bytes | `d6fa1eed9f4a03b78a2c9e83ffc349ec7b2bf46852630aca39dbdf8238e93bf8` |

Wheel contents include `scriptsentinel/py.typed`, both IOC feeds, `LICENSE`, `NOTICE`, and the `scriptsentinel` console entry point. The sdist includes `CITATION.cff`, `docs/CASE-STUDY.md`, and the OPTIMJACK case-study SVG/PNG assets.

## Live Audit Checks

- `http://localhost:8100/strict/checkout`: HTTP 200, CSP A / 100, one external script, `MISSING_SRI`.
- `http://localhost:8100/no-csp/checkout`: HTTP 200, CSP F / 0, `CSP-MISSING`, `MISSING_SRI`.
- Baseline SHA-256: `1ddc1b32fb1e4bc69c0171d8d34551897e001bd6a2bea9f7f136f34542858b01`.
- SRI digest: `sha256-HdwbMvseS8acAXHY00VRiX4AG9aivqn38TbzRUKFiwE=`.

## Release Checklist

1. Run the verification gates and confirm zero failures.
2. Build the wheel and sdist; install the wheel in a clean environment; run `scriptsentinel --version`.
3. Review README, OPTIMJACK case study, docs, assets, and social preview for relative paths, CVE links, and 846px asset width.
4. Commit release-stage changes with a clear message.
5. Create tag `v0.1.0`.
6. Make the repository public.
7. Publish `scriptsentinel` to PyPI.
8. Create the GitHub release with the terminal showcase and social preview.
9. Upload `assets/social-preview.png` as the repository social preview image.
10. Send the Telegram notification.

## Current State

- Repository: private at `https://github.com/Ally-Released/scriptsentinel`.
- Case study: `docs/CASE-STUDY.md` with CVE links, timeline, IOC analysis, OPTIJACK lab evidence, remediation, critical notes, and credits.
- GitHub metadata: description, homepage (`https://www.monarservices.org`), topics (`optimjack`, `payment-skimmer`, `content-security-policy`, `cli`, `python`, `security-tools`), and discussions enabled.
- Social preview: `assets/social-preview.png` (1280×640) is ready for GitHub UI upload; GitHub exposes no public API for social-preview upload.
- PyPI: not published.
- Git tag: not created.
- GitHub release: not created.
- Telegram notification: delivered to chat `5700018165` (`message_id` 64).
