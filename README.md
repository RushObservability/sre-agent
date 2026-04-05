# sre-agent

AI-powered SRE investigation agent for the Wide observability platform.

The agent receives investigation requests (either an anomaly event or a free-form question), forms hypotheses, and autonomously queries traces, logs, metrics, Kubernetes resources, ArgoCD state, and deploy history to identify the root cause of an incident.

## Architecture

The agent is a standalone HTTP service that streams investigation progress over Server-Sent Events (SSE). It reads from:

- **ClickHouse** — for traces, logs, and metrics (via the Wide observability schema)
- **SQLite** — for anomaly events/rules, deploy markers, and settings (shared with query-api)
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

```bash
# Run locally (requires CLICKHOUSE_URL, LLM_API_KEY, shared SQLite file)
export CLICKHOUSE_URL=http://localhost:8123
export LLM_API_KEY=sk-...
export LLM_MODEL=gpt-4o
export WIDE_CONFIG_DB=/path/to/wide_config.db
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
| `WIDE_CONFIG_DB` | `./wide_config.db` | SQLite config database path (shared with query-api) |
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
