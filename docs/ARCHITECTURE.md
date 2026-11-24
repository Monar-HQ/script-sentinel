# Architecture

ScriptSentinel v1 RC uses one deterministic engine through three interfaces:
CLI, loopback local console and read-only host-agent stdio tools. It does not
create empty subsystems just to resemble a diagram.

```text
CLI / local console / host-agent tools
             |
   root scope + explicit permissions
             |
 inventory -> AST + heuristics -> CSP + SRI
             |                      |
     SQLite evidence ledger    attributed research
             |
 reviewed baseline -> deterministic proposal
             |
 temporary-copy validation -> application review
             |
 explicit approval -> atomic single-file apply -> guarded rollback
             |
      persistent local change monitoring
```

Optional provider advisory sees minimized rule IDs and counts. Model output has
no route into patch application. Core remains usable offline and during provider
failure. Specialized host advisory roles have explicit responsibilities and no
write or execution tools.

## Implementation boundaries

- `runtime.py`: SQLite events, versioned payloads, bounded local store.
- `env_detector.py`, `local_audit.py`: narrow local discovery and resource budgets.
- `ast_analysis.py`, `scanner.py`: syntax-aware capability findings and separate
  heuristic/IOC signals. Source positions identify AST call evidence.
- `auditor.py`, `network.py`: page audit and explicit destination scope.
  Low-level transports are injectable for reproducible tests.
- `csp_analyzer.py`: first-directive semantics, source fallbacks, supported
  posture checks and independently assessed multiple policies. The aggregate
  retains shared posture signals, not a complete host/path intersection solver.
- `integrity.py`: multiple SRI tokens and strongest supported algorithm,
  SHA-256/384/512 comparisons and baseline drift evidence.
- `browser.py`: bounded anonymous staging-page observation. No login, forms,
  exploitation or personal browser profiles.
- `monitoring.py`: reviewed local snapshots and durable change observations.
- `proposals.py`, `validation.py`: reviewed bytes, recomputed diffs, staged checks,
  explicit approval, recovery copies and later-edit protection.
- `dashboard.py`, `web/`: authenticated loopback console, text-safe evidence,
  no source-changing endpoint.
- `host.py`, `ai/`: host advice and opt-in provider adapters.
- `knowledge/`, `research.py`, `iocs/`: data-only attributed packs and hunting leads.

The older direct-write `Patcher` constructor is retired and rejects use in v1.
Code must use proposals and validation. See THREAT_MODEL.md
for trust assumptions and known boundaries; source availability is not proof of
complete product or deployment support.
