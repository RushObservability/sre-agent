# sre-agent

[![ci](https://github.com/RushObservability/sre-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/RushObservability/sre-agent/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-BUSL--1.1-blue)

Start with an alert or ask "Why is checkout slow?" in the Rush frontend.
sre-agent checks traces, logs, metrics, and recent deploys for evidence. It
streams its progress and reports a likely cause or explains what evidence is
missing. You can ask follow-up questions in the same session.

The agent runs as part of [Rush](https://github.com/RushObservability) and
requires [query-api](https://github.com/RushObservability/query-api) v0.1.11 or
later. Query-api handles telemetry queries and model requests. It holds the
database and provider credentials.

## Run locally

Set up a model provider and enable the agent for your tenant in
**Settings → AI Agent** in the [frontend](https://github.com/RushObservability/frontend).
Use the same internal token in query-api and the agent. The agent listens on
port `8081` by default.

```bash
export QUERY_API_URL=http://localhost:8080
export SRE_AGENT_INTERNAL_TOKEN=dev-local-agent-token
make run

make docker        # build image
make docker-push
```

For deployment with [helm-charts](https://github.com/RushObservability/helm-charts)
and the full environment variable reference, see [Enabling the agent](https://rushobservability.com/docs/agent-enable).
The amd64 and arm64 images use a Chainguard runtime and run as UID/GID `65532`.
Give that user write access to any mounted repository cache.

## Investigation tools

- Compare an incident with a baseline, trace slow requests to a downstream service, or check a recent deploy. [Using the agent](https://rushobservability.com/docs/agent-usage)
- Compare CPU hotspots and call paths when the investigation includes `profiles` or `all` scope and the service sends profiles. [Send profiles to Rush](https://rushobservability.com/docs/profiling)
- Enable Kubernetes and GitOps inspection by mapping Rush tenants to approved namespaces. Kubernetes access is denied by default. [Kubernetes setup](https://rushobservability.com/docs/agent-enable)
- Let the agent read source and compare deploy commits through a GitHub App with read-only Contents permission. Rush checks the tenant's repository policy before each read and audits successful reads. [Connect GitHub](https://rushobservability.com/docs/agent-github)
- Use a built-in playbook or enable a custom one under **Settings → AI Agent → Custom skills**. [Investigation skills](https://rushobservability.com/docs/agent-skills)

## API and health

Call `POST /api/v1/investigate` through query-api to start an investigation.
The response streams Server-Sent Events with progress, tool results, and the
summary.

```json
{ "event_id": "", "question": "why is checkout slow?", "additional_context": "" }
```

The agent serves `GET /healthz` for liveness and `GET /readyz` for query-api
and model readiness. The Prometheus endpoint, `GET /metrics`, requires the
`x-rush-internal-token` header.

## License

[Business Source License 1.1](LICENSE).
