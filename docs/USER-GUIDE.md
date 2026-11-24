# Using ScriptSentinel

## Start with evidence

Python 3.11.5 or newer is required, with 3.12+ recommended. The minimum was
raised to permit the fixed Soup Sieve dependency instead of retaining an
older vulnerable release for Python 3.10 compatibility.

Install from a checkout in a virtual environment, then run `scriptsentinel demo`
or `scriptsentinel ui PATH_TO_WEBROOT`. Open the private terminal link. The
synthetic demo contains no attack code, customer data, payments or outbound calls.
The local console serves only its own assets and approved workspace operations.

Choose a narrow web root rather than a home directory or entire repository.
Node modules, virtual environments, build output and runtime state are excluded.
Discovery is limited to 5,000 files; local script/HTML content to 5 MB each;
local inventory to 1,000 scripts. Unsupported or unavailable resources are
reported rather than hashed as empty bytes.

Documents with `base href` have browser-dependent URL resolution. Local proposals
and monitoring reject them, and local external-script analysis reports them as
unavailable. Scoped HTTP inventory resolves the first document base URL. No
local fix is generated for different bytes than the browser is expected to load.

`scriptsentinel auto PATH --json` is read-only source analysis. External scripts
are unavailable offline. AST findings identify capabilities with source positions;
regex and IOC matches are separate heuristic evidence. Review ordinary analytics,
payment integrations and dynamic loaders in context before acting on a signal.

## HTTP audit

```text
scriptsentinel audit https://owned-staging.example/checkout --allow-origin https://approved-cdn.example --format json --fail-on high
```

Every additional origin must be named. Private/local destinations require
`--allow-private`. Scoped requests ignore ambient proxies, cap response bytes and
recheck redirects. Low-level Python `audit_url` retains an optional policy for
mock/transport compatibility; pass `NetworkPolicy` explicitly in integrations.
Do not expose the low-level API as an arbitrary-URL service.

Exit codes: 0 completed within the selected gate; 1 policy/drift threshold;
2 invalid configuration, incomplete audit or operational error. An audit with no
matching rule is not a certificate of safety.

## Baselines and monitoring

Independently review a release or artifact set before pinning hashes:

```text
scriptsentinel baseline PATH --reviewer "Your reviewer" --provenance "Reviewed artifact reference" --approve
scriptsentinel watch PATH --interval 60
```

The baseline is never silently overwritten. Watch records local HTML and referenced
local-script changes in `.scriptsentinel/state.sqlite3`; Ctrl+C stops it. Use
`--count 1` for CI or `--count 2 --interval 1` for a bounded check. Remote script
bytes require separately scoped HTTP observation. The local ledger stops accepting
new records after 100 MB rather than silently deleting evidence. Archive it with
the service stopped before continuing. Webhook support in the older one-shot
HTTP monitor is explicit outbound communication, not automatic telemetry.

## Reviewed remediation and recovery

Use the README's propose → validate → application review → apply sequence.
Proposals currently add SRI to local scripts with approved bytes. Existing tags
with integrity are preserved. CSP recommendations are review material and are
never blindly injected into a server config. Mutable third-party scripts may
break under SRI; pin an approved version or review a compatible strategy.

Validation copies only the candidate and relevant resources into a temporary
directory. It checks script references, inline code preservation and SRI. It
never executes your repository's build scripts, package hooks or arbitrary tests.
You must run your own functional/compatibility tests in a suitable isolated
environment before approving a production change.

Application atomically replaces one HTML file, preserves its mode and retains a
recovery copy. The adjacent proposal receipt is used for guarded rollback:

```text
scriptsentinel rollback PATH --receipt proposed-fix.json.receipt.json --approve
```

Recovery refuses to overwrite later changes or a mismatched backup. The scope is
a single-file transaction, not a deployment orchestration system. Production
deployment remains under your normal change-management process.

## Browser evidence

Install `.[browser]`, then `python -m playwright install chromium`. Use
`observe-browser URL --authorized --allow-origin ORIGIN --output evidence.json`.
For an owned localhost fixture add `--allow-private`. An optional `--executable`
selects an installed Chromium binary. The collector has no personal browser
profile, account cookies or login state. It blocks state-changing requests,
redirects, downloads, WebSockets and service workers. It never submits a form.
The observation window is bounded to 0–10 seconds, with at most 200 proxied
requests and 5 MB per resource. Browser/OS isolation and egress controls are still
required for untrusted applications. Instrumentation changes can affect behavior.

Alternatively, `observe-har page.har --page-origin ORIGIN` imports a single-page
HAR offline. HAR is supplied evidence; it does not prove execution or integrity.
Headers, bodies, cookies, queries and fragments are excluded from the inventory.
URL paths can still contain sensitive identifiers; review exports before sharing.

## Troubleshooting

- Missing AST package: reinstall the wheel or checkout's core dependencies.
- Browser executable unavailable: install Chromium using the Playwright command
  above, or select an existing binary. The browser is intentionally optional.
- Missing provider/model access: Core continues; choose a model actually available
  to your account. Subscription UI access does not imply general API entitlement.
- Baseline already exists: review and archive the old baseline explicitly. There
  is no silent trust reset button.
- API unauthorized: reopen the private terminal link in the same browser session.
  Restarting the console creates a new token.
- No Docker daemon: use native Python. Container configuration is not a running
  container, and Kubernetes manifests are not evidence of a live cluster.
