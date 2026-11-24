# Supported scope and acceptance matrix

The candidate supports a deliberately bounded defensive workflow. Unsupported
environments are reported; architecture discovery is heuristic, not universal.

| Surface | Implemented | Evidence / restriction |
| --- | --- | --- |
| Offline HTML + JavaScript | Inventory, AST capability signals, heuristic findings, SRI | Windows CPython 3.12 suite; limited whole-program semantics |
| Static framework output | HTML/source discovery and script audit | Next.js/React/Express/Python framework hints are heuristics |
| CSP | Supported posture rules, source fallback, first duplicates, independent policy assessment | Not a full host/path/browser-version intersection oracle |
| Browser | One bounded authorized anonymous Chromium visit | Real localhost dynamic-script and blocked-write test |
| Local console | Audits, inventory, reviewed baseline, monitoring, patch validation, research, events | Desktop/390px phone workflows; loopback only |
| Monitoring | Durable local snapshots, changes, restart persistence, explicit baseline approval | Remote bytes require scoped HTTP monitoring; 100 MB local-store cap |
| Remediation | Single-file reviewed local SRI proposal, staged checks, apply and guarded rollback | No automatic server-config edits or production deployment |
| Host agent | JSON-RPC stdio tools, scoped read-only evidence and advisory roles | Implemented MCP version 2024-11-05; no write/execution tool |
| Provider AI | Anthropic/OpenAI/OpenRouter/Gemini/custom adapters; budgets and Core fallback | Mock contracts; no paid/live model compatibility claim |
| Credentials | Matching environment keys and optional OS keyring integration | Backend availability depends on OS configuration; no subscription-token extraction |
| Python | 3.11.5+ minimum, 3.12+ recommended | 3.12.14 and 3.14.7 tested locally; 3.10 unsupported after dependency fix |
| Windows executable | Native one-file build with data assets | Unsigned local smoke check; no macOS/Linux binary claimed |
| Linux/macOS | CI matrix configured | No remote CI or physical-machine result available here |
| Docker/Kubernetes | Non-root Docker build and offline audit CronJob configuration | Local Docker daemon unavailable; no cluster deployed |

## Production acceptance

Before a production release: run the actual OS/container matrix, independent
human security review, production-compatible application tests and recovery
drills, platform signing and provenance. Publishing is a separate authorized
operation. A passing local suite or a deployment file is not a substitute for
these gates, and no universal protection or adoption target is guaranteed.
