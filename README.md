<div align="center">

# sre-agent

**It reads the dashboards so you don't have to.**

[![ci](https://github.com/RushObservability/sre-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/RushObservability/sre-agent/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-BUSL--1.1-blue)

</div>

Give sre-agent an alert or a plain-English question and it forms a hypothesis and goes looking — across traces, logs, metrics, Kubernetes, ArgoCD, and deploy history — until it can name a likely cause. It streams its reasoning as it works, so you watch the investigation rather than wait for a verdict.

Under the hood it's a ReAct loop over an OpenAI-compatible model with a dozen built-in tools. The interesting problems here aren't calling the LLM; they're knowing when to stop, what to keep in a small context window, and how to keep the model from chasing its own tail.

> Not a standalone product. sre-agent is one service in a [Rush](https://github.com/RushObservability) deployment and expects the rest to be running.

## How it works

Investigations follow a five-phase playbook — orient, hypothesize, gather evidence, verify, conclude — and the agent keeps a small working memory (suspect services, confirmed facts, things ruled out) that survives transcript compaction. Duplicate tool calls come back as errors written to teach the model to self-correct. Parse retries are counted apart from real work, so a malformed response doesn't eat the investigation budget. A run of empty results forces a summary instead of more thrashing.

It reads telemetry straight from ClickHouse, fetches user-authored skills from [query-api](https://github.com/RushObservability/query-api) over HTTP (one source of truth, no shared volume), and reaches Kubernetes and ArgoCD through the in-cluster ServiceAccount.

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
| `list_deploys` / `get_anomaly_context` | recent deploys; anomaly rules and events |
| `get_argocd_app` | Application health, sync, history |
| `kube_describe` / `kube_events` | describe resources in the caller's mapped namespaces; namespace events |
| `load_skill` | load an investigation playbook |

## Running it

Needs ClickHouse, a running query-api, and an OpenAI API key:

```bash
export CLICKHOUSE_URL=http://localhost:8123
export QUERY_API_URL=http://localhost:8080   # where it fetches custom skills
export OPENAI_API_KEY=sk-...
export OPENAI_BASE_URL=https://api.openai.com   # optional
make run

make docker        # build image
make docker-push
```

| Variable | Default | |
|---|---|---|
| `SRE_AGENT_PORT` | `8081` | listen port |
| `OPENAI_BASE_URL` | `https://api.openai.com` | any OpenAI-compatible endpoint |
| `OPENAI_API_KEY` | required | provider credential |
| `sre_agent_model` | `gpt-4o` | set in SRE Agent settings; not read from the environment |
| `ARGOCD_NAMESPACE` | `argocd` | where ArgoCD Application CRDs live |

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

Events: `thinking_delta` (incremental reasoning), `tool_call`, `tool_result`, `summary` (the report), `error`, and `done` (token usage + round count). `GET /healthz` for liveness.

## Part of Rush

- [query-api](https://github.com/RushObservability/query-api) — query, ingest, config backend
- [frontend](https://github.com/RushObservability/frontend) — where investigations are launched and streamed
- [helm-charts](https://github.com/RushObservability/helm-charts) — deploys all of it together

## License

[Business Source License 1.1](LICENSE).
