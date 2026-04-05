# sre-agent

AI-powered SRE investigation agent for **[Rush Observability](https://github.com/RushObservability)**.

The agent receives investigation requests (either an anomaly event or a free-form question), forms hypotheses, and autonomously queries traces, logs, metrics, Kubernetes resources, ArgoCD state, and deploy history to identify the root cause of an incident.

> **sre-agent is not a standalone product.** It is one of three services that make up a Rush Observability deployment and must run alongside the others:
>
> - **[`rush-api`](https://github.com/RushObservability)** — the query, ingest, and config backend. Owns the `custom_skills` table and serves it to sre-agent over HTTP.
> - **`rush-frontend`** — the web UI where users trigger investigations and view streaming results.
> - **`sre-agent`** — this service; does the actual investigation loop.
>
> sre-agent talks to `rush-api` over the in-cluster service URL for custom skills, and is reached by the frontend via its own `/investigate` endpoint. All three are deployed together by the [`rushobservability` Helm chart](https://github.com/RushObservability).

## Architecture

The agent is an HTTP service that streams investigation progress over Server-Sent Events (SSE). It reads from:

- **ClickHouse** — for traces, logs, and metrics (via the Rush Observability schema)
- **rush-api over HTTP** — for user-authored custom skills (`GET /api/v1/custom-skills`), so `rush-api` remains the single source of truth and the two services never share a volume
- **Local SQLite** — for anomaly events/rules, deploy markers, and settings (per-pod; populated by the agent itself)
- **Kubernetes API** — for ArgoCD Applications and core K8s resources (via in-cluster ServiceAccount)
- **LLM API** — OpenAI-compatible chat completions endpoint

## Features

- **Structured investigation methodology** — 5-phase playbook: orient → hypothesize → gather evidence → verify → conclude
- **Investigation skills** — loadable playbooks for error rate spikes, latency degradation, deploy regressions, dependency failures, ArgoCD issues, throughput anomalies
- **Working memory** — distilled facts (suspect services, confirmed facts, ruled out) that persist across aggressive transcript compaction
- **Repeat-call detection** — rejects duplicate tool calls with structured errors that teach the model to self-correct
- **Dual counters** — separates real tool work from parse retries so malformed responses don't burn the investigation budget
- **Dead-end detection** — forces summary when multiple consecutive no-data results indicate convergence
- **Per-tool clip budgets** — log outputs get more room than metric summaries; aggressive but type-aware truncation

## Agent tools

| Tool | Purpose |
|---|---|
| `query_traces` | Search spans by service, status, time |
| `get_trace` | Full trace by ID |
| `search_logs` | Search logs with severity and text filters |
| `query_metrics` | Time-series metrics (request rate, error rate, p50/p99 latency) |
| `list_services` | System-wide service health snapshot |
| `service_dependencies` | Call graph |
| `list_deploys` | Recent deployments |
| `get_anomaly_context` | Anomaly rules and recent events |
| `get_argocd_app` | ArgoCD Application health, sync, conditions, history |
| `kube_describe` | Describe any K8s resource (pods, deployments, services, etc.) |
| `kube_events` | K8s events in a namespace |
| `load_skill` | Load an investigation playbook |

## Development

sre-agent is usually run together with `rush-api` and `rush-frontend`. For a full local stack, use the `docker-compose` / Helm setup in the main Rush Observability repo. To iterate on just the agent:

```bash
# Run locally — requires ClickHouse, rush-api, and an LLM API key.
export CLICKHOUSE_URL=http://localhost:8123
export QUERY_API_URL=http://localhost:8080   # URL of rush-api; used to fetch custom skills
export LLM_API_KEY=sk-...
export LLM_MODEL=gpt-4o
make run

# Build and push the Docker image
make docker
make docker-push
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SRE_AGENT_PORT` | `8081` | HTTP listen port |
| `CLICKHOUSE_URL` | `http://localhost:8123` | ClickHouse endpoint |
| `CLICKHOUSE_DATABASE` | `observability` | ClickHouse database name |
| `CLICKHOUSE_USER` | `default` | ClickHouse user |
| `CLICKHOUSE_PASSWORD` | `` | ClickHouse password |
| `WIDE_CONFIG_DB` | `./wide_config.db` | Local SQLite path for anomaly events / deploy markers |
| `QUERY_API_URL` | _(unset)_ | URL of `rush-api` for fetching custom skills over HTTP. When set, the agent reads `custom_skills` from rush-api (single source of truth) instead of the local DB. |
| `LLM_BASE_URL` | `https://api.openai.com` | OpenAI-compatible LLM endpoint |
| `LLM_API_KEY` | (required) | LLM API key |
| `LLM_MODEL` | `gpt-4o` | Model name |
| `ARGOCD_NAMESPACE` | `argocd` | Namespace where ArgoCD Application CRDs live |

## API

**`POST /api/v1/investigate`** — Start an investigation (returns SSE stream)

Request body:
```json
{
  "event_id": "",           // optional: anomaly event ID to investigate
  "question": "...",        // optional: free-form question
  "additional_context": ""  // optional: extra context from user
}
```

Streams these event types:
- `thinking_delta` — incremental LLM reasoning
- `tool_call` — agent calling a tool
- `tool_result` — tool output
- `summary` — final investigation report
- `error` — investigation error
- `done` — completion with token usage and round count

**`GET /healthz`** — Health check
