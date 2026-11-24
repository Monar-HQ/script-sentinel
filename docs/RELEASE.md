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
| Documentation | README, architecture, detection rules, PCI-DSS mapping, design system, CI gate, release notes |
| Visuals | Dark/light hero banners, terminal showcase, architecture diagram, Unquant partner card, social preview SVG + PNG |
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

- `python -m pytest -v`: 67 passed in 8.06s with OPTIJACK integration tests active.
- `python -m ruff check .`: All checks passed.
- `python -m mypy --strict src/scriptsentinel`: Success, 18 source files.
- `uv build`: wheel and sdist produced successfully.
- Clean-venv wheel install: `scriptsentinel --version` returns `0.1.0`.
- `scriptsentinel --help` lists `audit`, `check-csp`, `monitor`, `remediate`, and `export-rules`.

## Built Artifacts

| Artifact | Size | SHA-256 |
| --- | --- | --- |
| `dist/scriptsentinel-0.1.0-py3-none-any.whl` | 48,185 bytes | `df520ddff50bf91f19e82b565a994725b01fe3f6eeba58628366e727f526a01d` |
| `dist/scriptsentinel-0.1.0.tar.gz` | 138,199 bytes | `a289330ef6d7e2df285a292d85f76773b9bb6367a1aad89f03850b88511ccca0` |

Wheel contents include `scriptsentinel/py.typed`, both IOC feeds, `LICENSE`, `NOTICE`, and the `scriptsentinel` console entry point.

## Live Audit Checks

- `http://localhost:8100/strict/checkout`: HTTP 200, CSP A / 100, one external script, `MISSING_SRI`.
- `http://localhost:8100/no-csp/checkout`: HTTP 200, CSP F / 0, `CSP-MISSING`, `MISSING_SRI`.
- Baseline SHA-256: `1ddc1b32fb1e4bc69c0171d8d34551897e001bd6a2bea9f7f136f34542858b01`.
- SRI digest: `sha256-HdwbMvseS8acAXHY00VRiX4AG9aivqn38TbzRUKFiwE=`.

## Release Checklist

1. Run the verification gates and confirm zero failures.
2. Build the wheel and sdist; install the wheel in a clean environment; run `scriptsentinel --version`.
3. Review README, docs, assets, and social preview for relative paths and 846px asset width.
4. Commit release-stage changes with a clear message.
5. Create tag `v0.1.0`.
6. Make the repository public.
7. Publish `scriptsentinel` to PyPI.
8. Create the GitHub release with the terminal showcase and social preview.
9. Upload `assets/social-preview.png` as the repository social preview image.
10. Send the Telegram notification.

## Current State

- Repository: private at `https://github.com/Ally-Released/scriptsentinel`.
- Git push: completed to the private origin on `main`.
- PyPI: not published.
- Git tag: not created.
- GitHub release: not created.
- Telegram notification: delivered to chat `5700018165` (`message_id` 63).
