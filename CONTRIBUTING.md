# Contributing to ScriptSentinel

## Ground rules

- Defensive only. Contributions must not add payload generators, exploit primitives, or bypass recipes.
- No fabricated evidence. Every IOC record needs `source` and `first_seen`. Every detection rule needs true-positive and false-positive counts backed by captured telemetry. Mark unconfirmed items as `unconfirmed`.
- No telemetry and no phone-home. Network access is limited to the target URL and the optional drift webhook.
- Typed dataclasses on the detection path. Do not add dict-based detection logic.

## Setup

```bash
python -m venv .venv
# Windows
.venv/Scripts/python -m pip install -e ".[dev]"
# Unix
.venv/bin/python -m pip install -e ".[dev]"
```

No browser or Playwright install is required. The harvester uses `httpx` and BeautifulSoup.

## Checks before a pull request

```bash
python -m pytest -v
python -m ruff check .
python -m mypy --strict src/scriptsentinel
```

Optional coverage gate:

```bash
python -m pytest --cov=scriptsentinel --cov-report=term-missing
```

## Adding an IOC

1. Append a record to `src/scriptsentinel/iocs/feeds/<feed>.json` with `kind`, `value`, `source`, `first_seen`, `severity`, and an optional `note`.
2. `kind` must be `domain` or `sha256`. Domain values are bare hostnames; SHA-256 values are 64 lowercase hex characters.
3. Bump the feed `version` and `as_of` date.
4. Add a test that the loader rejects records missing `source` or `first_seen`.

## Adding a detection rule

- CSP rules live in `src/scriptsentinel/csp_analyzer.py`; penalties are CRITICAL 35, HIGH 20, MEDIUM 10, LOW 5.
- Behavioral rules live in `src/scriptsentinel/scanner.py` under `_PATTERNS`; IOC matching lives in the same module.
- SRI statuses live in `src/scriptsentinel/integrity.py`: `VERIFIED`, `MISSING_SRI`, `INTEGRITY_MISMATCH`, `SCRIPT_DRIFT`.
- Export mappings live in `src/scriptsentinel/rules/sigma_exporter.py` and `src/scriptsentinel/rules/suricata_exporter.py`.
- Add tests under `tests/` and assert true positives on attack slices and zero false positives on clean slices.

## Style

- Python 3.10+, `from __future__ import annotations`, type annotations on public functions.
- Dataclasses for records; tuple-based immutable results.
- Prefer stdlib (`hashlib`, `json`, `re`, `base64`) and the existing runtime dependencies (`httpx`, `beautifulsoup4`, `rich`).
- Keep CLI output in the MONAR palette: red accent, bone text, slate metadata, no cyan/green/purple status walls.
