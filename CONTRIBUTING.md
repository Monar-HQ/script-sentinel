# Contributing to ScriptSentinel

## Ground rules

- Defensive only. Contributions must not add code whose purpose is to help an attacker: no payload generators, no exploit primitives, no bypass recipes.
- No fabricated evidence. Every IOC record needs a `source` and a `first_seen` date. Every rule needs TP/FP counts backed by captured telemetry. If something cannot be confirmed, mark it `unconfirmed` rather than guessing.
- No telemetry, no phone-home. Any new outbound request must be logged and opt-in.
- `--ai none` must remain the default, and the AI layer must never sit on the detection path.

## Setup

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"
.venv/Scripts/python -m playwright install chromium
```

## Checks before a PR

```bash
.venv/Scripts/python -m pytest --cov=scriptsentinel --cov-fail-under=85
.venv/Scripts/python -m ruff check src tests
.venv/Scripts/python -m mypy --strict src/scriptsentinel
```

## Adding an IOC

1. Append a record to `src/scriptsentinel/iocs/feeds/<feed>.json` with `type`, `value`, `source`, `first_seen`, and `severity`.
2. Bump the feed `version`.
3. Add a unit test that the loader rejects the record when `source` or `first_seen` is missing.

## Adding a rule

1. Add a module under `src/scriptsentinel/rules/` with `rule_id`, `family`, `reads`, `window`, `threshold`, `logic`, `severity`.
2. Register it in `rules.py` with `default_on=False` if the lab evidence does not support TP/FP counts.
3. Add telemetry slices to `tests/fixtures/` and assert TP on attack slices and 0 FP on clean slices.

## Style

- Python 3.12, type annotations on every public function (mypy strict).
- Dataclasses for data records; plain dicts for telemetry passthrough.
- Prefer stdlib (`hashlib`, `sqlite3`, `json`, `urllib`) over new dependencies.
