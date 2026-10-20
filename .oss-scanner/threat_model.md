# Threat model: Rush SRE agent

## What this project does and where untrusted input enters

The SRE agent is the investigation service of Rush Observability. It runs an LLM tool loop that queries a tenant's
logs, traces, metrics, deploys, anomalies and (optionally) Kubernetes, Argo CD, Flux, PostgreSQL, MySQL and GitHub
repository data, then writes a report. It never talks to browsers or API clients directly:

- Only query-api calls it. Every protected route (`/api/v1/investigate`, `/api/v1/investigation-templates`,
  `/metrics`) requires `x-rush-internal-token`, compared in constant time (`src/http.rs`). `/healthz` and `/readyz`
  are open.
- query-api authenticates the person or API key, then overwrites `tenant_id` and `scopes` in the request body.
  The agent trusts those two fields. Everything else in the body is caller-controlled: `question`,
  `additional_context`, `event_id`, `session_id`, `template_id`, `model`, `reasoning_effort`, `window`.
- Tools reach data through query-api's internal API (`src/query_api.rs`), always passing the request's tenant.
- Session state (turns, working memory, saved tool activity) is stored in query-api, keyed by tenant.

Treat as untrusted:

- the caller-controlled request fields above;
- **all telemetry content** (log bodies, span names and attributes, metric labels, Kubernetes object fields,
  repository files), which reaches the model and can carry prompt injection;
- every tool argument, since the model chooses them;
- responses from query-api, GitHub, Kubernetes and the LLM provider.

## Components that matter most / least

Most important, in order:

1. **Tenant isolation.** A session, tool call, skill, memory or past-incident lookup must never read or write another
   tenant's data, whatever the request, session ID or model output says.
2. **Scope enforcement** (`src/agent/tools.rs`, `scope_allows`). `code` (repository tools) and `kube_cluster`
   (cluster-scoped Kubernetes reads) need an explicit scope; `all` does not include them. Investigations started with
   API keys get `["all"]` only.
3. **The internal-token boundary** in `src/http.rs`.
4. **Repository tools** (`src/repository.rs`, `src/agent/built_in/repository_tools.rs`): snapshot download and
   extraction, `resolve_under` path handling, and anything that could read outside the snapshot.
5. **Kubernetes, Argo CD and Flux tools**: read-only by design (`get`/`list`), limited to the tenant's namespaces,
   never Secrets or pod exec.
6. **Redaction** (`src/agent/redact.rs`) of secrets in tool arguments and results before they are saved with a
   session or logged.

Less important: report wording, eval tooling under `src/bin/sre_evals` and `evals/`, metrics output.

## How to exercise it

- `cargo test` runs unit tests and integration tests with a mock LLM and mock query-api (`tests/common`,
  `tests/http_api.rs`, `tests/security_boundaries.rs`, `tests/security_sessions.rs`). These are the quickest way to
  build a reproducer.
- `cargo run --bin sre_evals -- replay --cases evals/replay_cases.yaml --out /tmp/out` replays recorded
  investigations without a model or network.
- The binary needs `SRE_AGENT_INTERNAL_TOKEN`, `QUERY_API_URL` and `SRE_AGENT_PORT`. A real run also needs query-api
  and a model provider, which are not available offline; use the mocks in `tests/common` instead.

## How you rate severity

- **Critical:** reading or changing another tenant's data or sessions; calling a `code` or `kube_cluster` tool
  without that scope; bypassing the internal token; remote code execution; prompt injection (from telemetry or a
  question) that makes the agent do any of these.
- **High:** reading files outside a repository snapshot (path traversal, symlinks, archive entries); SSRF that reaches
  an address the operator did not configure; secrets (provider keys, tokens, repository credentials) disclosed in
  responses, saved sessions or logs; Kubernetes access outside the tenant's namespaces or beyond `get`/`list`.
- **Medium:** denial of service from a single request that escapes the investigation budget, round or tool-call limits.
- **Low / informational:** prompt injection that only steers the agent among tools and data the caller is already
  allowed to use. The model is not a security boundary; tenant and scope checks in code are.

## Anything to leave alone

- Report quality, hallucinated conclusions, or a model choosing a poor tool, unless they cross a boundary above.
- The development defaults in the `Makefile` (`dev-local-agent-token` and localhost URLs).
- Behavior that requires a compromised query-api: query-api is trusted to authenticate callers and set `tenant_id`
  and `scopes`. Report it if the agent itself lets a caller influence those values.
