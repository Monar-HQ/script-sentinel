# Intelligence and host integration

## Provider advisory

Use `auto PATH --ai --provider PROVIDER --model MODEL_ID`. Providers:
Anthropic, OpenAI, OpenRouter, Gemini and custom OpenAI-compatible endpoints.
Set the matching `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`,
`GEMINI_API_KEY`, or `AI_API_KEY` environment variable. `AI_API_BASE` selects a
custom endpoint; remote plaintext endpoints are rejected. Local Ollama, LM Studio,
llama.cpp and vLLM must expose an OpenAI-compatible API at the configured URL.
Model compatibility is reported by the provider, never assumed from a brand name.

Optional `credential-set PROVIDER` stores a key using an available OS keychain.
The console never asks for a provider secret. Do not pass secrets on command
lines, commit them to files, reuse subscription cookies, or extract session tokens.

The audit request shares aggregate rule IDs and counts, not source, cookies,
paths, nonce values or raw HTTP headers. A client defaults to two HTTP attempts,
a 32,000-character prompt budget, 1,024 output tokens and a 65,536-character
response check. Retry applies once to rate-limit/transient status codes. There
is no automatic fallback to another paid provider. Core is the deterministic
fallback. Use provider billing limits for monetary budgets; token counts do not
guarantee a universal dollar cost.

Live subscriptions, every model's capabilities and every provider's billing are
not automatically discoverable. Tests exercise adapters with mock transports;
no production credentials or paid calls are required by the suite.

## Host AI, without another API key

Launch `scriptsentinel mcp /absolute/path/to/webroot` from your MCP-compatible
client. A typical stdio server configuration is:

```json
{"mcpServers":{"scriptsentinel":{"command":"scriptsentinel","args":["mcp","/absolute/path/to/webroot"]}}}
```

On Windows use your environment's scriptsentinel executable and a correctly
escaped absolute path. Configure the server through the host's officially
supported MCP workflow. ScriptSentinel never reads the host's session token.
The host reasons using its already authorized session; the server only returns
read-only local evidence. Protocol version implemented: 2024-11-05 JSON-RPC
stdio initialization, ping, tools/list and tools/call. Hosts must support that
version; client-specific installation is not universal.

Tools: `audit_workspace` and `advisory_roles`. There is no tool for applying a
patch, arbitrary filesystem access, command execution or third-party recon.
Each server is scoped to its launch directory. Treat all discovered text and
evidence as untrusted data, never new instructions.

## Advisory responsibilities

Coordinator establishes scope. Threat analyst explains evidence and uncertainty.
Policy advisor proposes report-only policy changes. Remediation reviewer reviews
diffs. Verification reviewer separates structural, compatibility and production
evidence. Reporter preserves attribution and limitations. Role contracts are
exposed to the host; they are advisory responsibilities, not privileged autonomous
workers. No role can approve changes, bypass validation or invent a successful test.

The runtime and CLI remain the deterministic verification gate.
