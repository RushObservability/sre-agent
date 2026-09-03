<div align="center">

# sre-agent

**It reads the dashboards so you don't have to.**

[![ci](https://github.com/RushObservability/sre-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/RushObservability/sre-agent/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-BUSL--1.1-blue)

</div>

Give sre-agent an alert or a plain-English question and it forms a hypothesis and goes looking — across traces, logs, metrics, Kubernetes, ArgoCD, and deploy history — until it can name a likely cause. It streams its reasoning as it works, so you watch the investigation rather than wait for a verdict.

Under the hood it's a ReAct loop over an OpenAI-compatible model with 25 built-in tools. The interesting problems here aren't calling the LLM; they're knowing when to stop, what to keep in a small context window, and how to keep the model from chasing its own tail.

> Not a standalone product. sre-agent is one service in a [Rush](https://github.com/RushObservability) deployment and expects the rest to be running.

## How it works

Investigations follow a five-phase playbook — orient, hypothesize, gather evidence, verify, conclude — and the agent keeps a small working memory (suspect services, confirmed facts, things ruled out) that survives transcript compaction. Duplicate tool calls come back as errors written to teach the model to self-correct. Parse retries are counted apart from real work, so a malformed response doesn't eat the investigation budget. A run of empty results forces a summary instead of more thrashing.

It reads telemetry, configuration, custom skills, and investigation history
through [query-api](https://github.com/RushObservability/query-api). The agent
receives no database credentials. Kubernetes and ArgoCD/Flux access uses its
in-cluster ServiceAccount.

## Read-only GitHub source access

The agent can inspect code linked to an observed service without webhooks and
without a general-purpose shell. Create a GitHub App with only the repository
permission **Contents: Read-only**, install it on selected repositories, and
mount its PEM private key into the agent. Each repository link can carry its
operator-approved GitHub installation and stable repository IDs. The policy is
keyed by Rush tenant, so API callers cannot claim another tenant's installation.

Required environment variables:

```text
GITHUB_APP_ID=<numeric app id>
GITHUB_APP_PRIVATE_KEY_PATH=/var/run/rush-github/private-key.pem
SRE_AGENT_GITHUB_REPOSITORY_POLICY={"acme":[{"repository":"acme/api","installationId":654321,"repositoryId":123456789}]}
REPOSITORY_CACHE_DIR=/var/run/rush-repositories
```

`GITHUB_API_URL` is optional for GitHub Enterprise Server. There is deliberately
no global installation fallback. The query API and agent both require an exact
tenant/repository/installation/repository-ID policy match before access,
including cached access. The agent mints a short-lived installation token
scoped by stable repository ID and `contents: read`, downloads a bounded
tar snapshot, rejects links/special files/path traversal, and exposes only
`list_repository_files`, `search_repository`, and `read_repository_file`.
Repository code is never executed. Successful source reads are sent to
query-api's tamper-evident audit log without tokens or source contents.

## Tools

| Tool | Purpose |
|---|---|
| `query_traces` / `get_trace` | search spans; pull a full trace by ID |
| `search_logs` | logs by severity and text |
| `query_metrics` | request rate, error rate, p50/p99 |
| `list_services` / `service_dependencies` | health snapshot; call graph |
| `compare_service_windows` / `rank_slow_dependencies` | incident-vs-baseline service comparison; slow downstream ranking |
| `analyze_trace_critical_path` | identify spans dominating a trace's duration |
| `get_resource_saturation` / `list_metric_catalog` | resource pressure; available metric names and labels |
| `detect_service_silence` | distinguish missing traffic from a healthy low-volume service |
| `inspect_postgresql` | correlate an app's PostgreSQL spans with slow-query, lock, advisor, replication, recovery, and planning evidence from the existing read-only PostgreSQL collector |
| `list_deploys` / `get_anomaly_context` / `search_past_incidents` | deploys; anomaly context; prior investigation leads |
| `get_argocd_app` / `get_flux_resource` | ArgoCD and Flux resource health |
| `kube_describe` / `kube_events` | describe resources in the caller's mapped namespaces; namespace events |
| `search_kubernetes_access` | correlate a suspected operator action with tenant-scoped Kubernetes access metadata when the paid add-on is enabled |
| `list_repository_files` / `search_repository` / `read_repository_file` | bounded, read-only access to operator-approved GitHub repositories |
| `load_skill` | load an investigation playbook |

The built-in skills are `error_rate_spike`, `latency_degradation`,
`deploy_regression`, `dependency_failure`, `argocd_unhealthy`,
`flux_unhealthy`, `throughput_anomaly`, and `postgresql_diagnostics`.

Custom skills are managed from **Settings → AI Agent → Custom skills** in the
frontend. They are stored by query-api, loaded fresh for the next investigation,
and merged with the built-ins. The agent only receives enabled skills. Custom
skill bodies are treated as untrusted advisory content and never override the
agent's system rules.

## Running it

Needs a running query-api and an OpenAI API key. The agent never connects to
ClickHouse or receives database credentials.

```bash
export QUERY_API_URL=http://localhost:8080
export SRE_AGENT_INTERNAL_TOKEN=dev-local-agent-token
export OPENAI_API_KEY=sk-...
export OPENAI_BASE_URL=https://api.openai.com   # optional
make run

make docker        # build image
make docker-push
```

| Variable | Default | |
|---|---|---|
| `SRE_AGENT_PORT` | `8081` | listen port |
| `SRE_AGENT_MAX_CONCURRENT_INVESTIGATIONS` | `4` | maximum investigations executing at once |
| `SRE_AGENT_MAX_QUEUED_INVESTIGATIONS` | `16` | maximum investigations waiting for a slot |
| `SRE_AGENT_MAX_TOOL_STEPS` | `40` | fallback maximum tool-bearing rounds per investigation; Settings takes precedence |
| `SRE_AGENT_MAX_LLM_CALLS` | `55` | fallback maximum total provider calls, including retries and final review; Settings takes precedence |
| `SRE_AGENT_RUNTIME_METRICS_INTERVAL_SECS` | `15` | process/runtime metric sampling interval |
| `SRE_AGENT_INTERNAL_TOKEN` | required | shared query-api-to-agent credential; never expose it to browsers |
| `QUERY_API_URL` | required | query-api base URL used for telemetry, configuration, and investigation state |
| `OPENAI_BASE_URL` | `https://api.openai.com` | any OpenAI-compatible endpoint |
| `OPENAI_API_KEY` | required | provider credential |
| `sre_agent_model` | `gpt-4o` | set in SRE Agent settings; not read from the environment |
| `ARGOCD_NAMESPACE` | `argocd` | where ArgoCD Application CRDs live |

The same agent settings can be managed at runtime in the frontend under
**Settings → AI Agent**:

- **Tenant access** enables the agent for all enabled tenants or an explicit list.
- **Models** defines the allowlist, default model, and reasoning levels available to users.
- **Investigation limits** changes the tool-step and LLM-call budgets for new investigations.
- **Custom skills** creates, edits, enables/disables, and deletes user-authored playbooks.

Runtime settings are stored by query-api and take effect for new investigations
(budget changes may remain cached for up to 30 seconds).

### Kubernetes access boundaries

Kubernetes inspection is deny-by-default. Set `SRE_AGENT_KUBE_TENANT_NAMESPACES`
to a JSON object that maps Rush tenant IDs to the namespaces they may inspect:

```text
SRE_AGENT_KUBE_TENANT_NAMESPACES={"acme":["acme-prod"],"*":["shared-observability"]}
```

The optional `*` entry is a shared-namespace allowlist; it does not grant
access to arbitrary namespaces. Cluster-scoped resources such as nodes and
namespace enumeration are denied unless both `SRE_AGENT_KUBE_ALLOW_CLUSTER_SCOPED=true`
and the authenticated caller has the explicit `kube_cluster` scope (the Rush
admin role is the only role that receives it). The Helm chart creates a
dedicated service account and namespace RoleBindings from
`sreAgent.kube.tenantNamespaces`; it does not grant the agent Secrets, pod-log,
node, or namespace permissions.

## API

`POST /api/v1/investigate` starts an investigation and returns a Server-Sent Events stream:

```json
{ "event_id": "", "question": "why is checkout slow?", "additional_context": "" }
```

Events: `session_created` (for a new interactive session), `thinking_delta` (incremental reasoning), `tool_call`, `tool_result`, `summary` (final or preliminary report), `error`, and `done` (token usage + round count). Sessions can be continued with follow-up questions from the frontend.

`GET /healthz` is a cheap liveness check. `GET /readyz` verifies query-api and
LLM configuration and returns `503` until both are available. `GET /metrics`
exports low-cardinality Prometheus metrics for investigation admission,
investigation outcomes, report-kind outcomes, investigation work and report
sizes, process/runtime health, SSE streams, LLM calls and token usage,
query-api requests and tool calls; it uses the
same `x-rush-internal-token` header as the API.

## Part of Rush

- [query-api](https://github.com/RushObservability/query-api) — query, ingest, config backend
- [frontend](https://github.com/RushObservability/frontend) — where investigations are launched and streamed
- [helm-charts](https://github.com/RushObservability/helm-charts) — deploys all of it together

## License

[Business Source License 1.1](LICENSE).
