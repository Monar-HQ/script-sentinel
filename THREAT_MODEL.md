# Threat model

## Assets and trust boundaries

Application source, approved baselines, audit history, provider credentials and
patch recovery copies stay on the operator's machine. Discovered HTML, JavaScript,
HAR, research feeds and model output are untrusted. A trusted CDN origin does not
make mutable script bytes trustworthy.

## Defenses

- Local analysis never evaluates application JavaScript or runs project commands.
  AST and regex signals describe capabilities; they do not prove malicious intent.
- Filesystem reads and proposals are confined to the selected web root, with
  symlink resolution and file/script budgets. Choose the web root, not a disk root.
- HTTP policy authorizes exact origins, rechecks redirects, denies private address
  destinations unless explicitly selected, ignores ambient proxy settings and caps
  resource bytes. DNS checks are defense in depth, not pinning against rebinding;
  use network-layer egress controls where adversarial DNS is in scope.
- Active observation requires explicit authorization and a disposable browser
  context. It proxies anonymous GET/HEAD requests, blocks writes, redirects,
  service workers, downloads and WebSockets. Browser context isolation is not a
  network/OS sandbox. Use a VM or restricted container for untrusted applications.
- Dashboard binds only to 127.0.0.1, uses a random bearer token, checks Host and
  mutation Origin, serves a restrictive CSP and renders evidence as text.
  The token is carried in the URL fragment, removed into session storage and is
  not logged. No remote access or shared-host deployment is supported.
- Baselines require an operator review assertion and provenance, but are not
  cryptographically signed. Protect their write access. Proposed SRI changes are
  recomputed, staged and checked before approval. Production compatibility is a
  separate gate. Recovery refuses to overwrite subsequent edits.
- AI is opt-in and advisory. Rule IDs and counts are shared, not source, raw
  headers, nonces or cookies. Prompt and request budgets bound use; provider limits
  and billing controls remain essential. No model can approve or apply a change.
- MCP has only read-only tools scoped to the launch workspace. It does not expose
  command execution, patch application, credentials or arbitrary path arguments.

## Out of scope

Compromise of the operator's OS, hostile concurrent filesystem mutation by a user
with equal privileges, browser zero-days, exact behavior of all CSP/browser
versions, server-side vulnerability exploitation, guaranteed malware detection,
compliance certification and reproducing a vendor's incident root cause.

Report vulnerabilities privately using SECURITY.md. Do not test third-party sites
without authorization. Runtime data and recovery files must not be committed.
