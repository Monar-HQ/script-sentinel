# Working on ScriptSentinel

This repository is a defensive client-side supply-chain security product. Read
THREAT_MODEL.md, PRODUCT.md and docs/USER-GUIDE.md before changing trust boundaries.
Preserve user work. Never run project content discovered by an audit.

## Engineering gates

Use immutable evidence models. Propagate errors and incomplete coverage. Source,
HAR, research feeds and model output are untrusted. AST capability signals and
heuristics must not be presented as proof of compromise. No automatic third-party
exploitation, credential extraction, baselining of freshly fetched bytes, or
production deployment is permitted.

AI is opt-in, minimized and advisory. Host-agent tools remain read-only. Changes
must pass deterministic proposal validation, application compatibility review and
explicit approval. Do not claim rollback or verification passed without evidence.

Run Ruff, strict Mypy, Pytest, optional real Chromium workflows, the disclosed
benchmark and fresh-wheel installation. Do not fabricate cross-platform, paid
provider, Docker/Kubernetes, signing or independent review results. A CI definition
is not a passing CI run. Keep release gates explicit.

Use exact origin scope for active requests and narrow root scope for local files.
Do not commit .scriptsentinel state, provider secrets, private browser profiles,
real payment data or recovery files. Do not publish without owner authorization.

## Design

The local product uses graphite, near-white and MONAR signal yellow. No external
asset calls, fake threat counters or invented testimonials. User-facing output
must explain the next action and preserve limitations. Keep keyboard focus,
responsive layouts, text-safe rendering and reduced-motion behavior intact.
