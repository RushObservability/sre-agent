BINARY  := sre-agent
VERSION := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
IMAGE   := ghcr.io/rushobservability/sre-agent

# Local development wiring. These values are used only by `make dev` and
# `make watch`; `make run` sources the production-style `.env` file instead.
DEV_SRE_AGENT_PORT           := 8081
DEV_CLICKHOUSE_URL           := http://localhost:8123
DEV_QUERY_API_URL            := http://localhost:8080
DEV_SRE_AGENT_INTERNAL_TOKEN := dev-local-agent-token
DEV_CLICKHOUSE_CONTAINER     ?= wide-clickhouse-1

# Resolve local ClickHouse credentials at recipe runtime so passwords never
# appear in Make's echoed command. Explicit CLICKHOUSE_USER/PASSWORD values win;
# otherwise the standard `wide` ClickHouse container supplies any missing value.
define run-with-dev-env
	@set -e; \
	ch_user="$${CLICKHOUSE_USER:-}"; \
	ch_password="$${CLICKHOUSE_PASSWORD:-}"; \
	if [ "$(DEV_CLICKHOUSE_URL)" = "http://localhost:8123" ] && \
	   { [ -z "$$ch_user" ] || [ -z "$$ch_password" ]; } && \
	   command -v docker >/dev/null 2>&1 && \
	   docker inspect "$(DEV_CLICKHOUSE_CONTAINER)" >/dev/null 2>&1; then \
		ch_env="$$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$(DEV_CLICKHOUSE_CONTAINER)")"; \
		if [ -z "$$ch_user" ]; then ch_user="$$(printf '%s\n' "$$ch_env" | sed -n 's/^CLICKHOUSE_USER=//p')"; fi; \
		if [ -z "$$ch_password" ]; then ch_password="$$(printf '%s\n' "$$ch_env" | sed -n 's/^CLICKHOUSE_PASSWORD=//p')"; fi; \
	fi; \
	ch_user="$${ch_user:-default}"; \
	SRE_AGENT_PORT=$(DEV_SRE_AGENT_PORT) \
	CLICKHOUSE_URL=$(DEV_CLICKHOUSE_URL) \
	CLICKHOUSE_USER="$$ch_user" \
	CLICKHOUSE_PASSWORD="$$ch_password" \
	QUERY_API_URL=$(DEV_QUERY_API_URL) \
	SRE_AGENT_INTERNAL_TOKEN=$(DEV_SRE_AGENT_INTERNAL_TOKEN) \
	RUST_LOG=sre_agent=debug,tower_http=debug \
	$(1)
endef

.PHONY: build release run check test test-integration eval-replay eval-release-gate fmt lint clean docker docker-push help

## Development

build:                ## Build debug binary
	cargo build

release:              ## Build optimised release binary
	cargo build --release

dev:                  ## Run the agent with local development wiring
	$(call run-with-dev-env,cargo run --bin $(BINARY))

run:                  ## Run the agent with variables sourced from .env
	@set -e; \
	test -f .env || { echo "ERROR: sre-agent/.env is required for make run" >&2; exit 1; }; \
	set -a; . ./.env; set +a; \
	RUST_LOG="$${RUST_LOG:-sre_agent=info,tower_http=info}" cargo run --bin $(BINARY)

watch:                ## Watch the agent with local development wiring
	$(call run-with-dev-env,cargo watch -x "run --bin $(BINARY)")

## Quality

check:                ## Type-check without building
	cargo check

test:                 ## Run tests
	cargo test

eval-replay:          ## Run the deterministic PR6 RCA replay suite
	cargo run --bin sre_evals -- replay --cases evals/replay_cases.yaml --out evals/out

eval-release-gate:    ## Compare a PR6 replay run with the checked-in baseline (CURRENT=...)
	@test -n "$(CURRENT)" || { echo "Usage: make eval-release-gate CURRENT=evals/out/<run>.json" >&2; exit 1; }
	cargo run --bin sre_evals -- release-gate --current "$(CURRENT)" --baseline evals/baseline-pr6.json

# Runs the FULL suite including the #[ignore]d DB-gated tests.
#
# Port note: several DB-gated tests (src/agent/tools.rs, skills_tool.rs)
# hardcode http://localhost:8123, so the test ClickHouse MUST be reachable on
# host port 8123 — a remapped port (e.g. 18123) would only satisfy the tests
# that honor CLICKHOUSE_URL. If something is already listening on :8123 (your
# dev ClickHouse, which also carries query-api's config_* schema that several
# of these tests expect), it is reused and left running; otherwise a
# disposable container is started and always torn down via a shell trap.
test-integration:     ## Run full test suite incl. DB-gated tests (ClickHouse on :8123)
	@set -e; \
	if curl -sf http://localhost:8123/ping >/dev/null 2>&1; then \
		echo "==> ClickHouse already listening on :8123 — reusing it (no teardown)"; \
		CLICKHOUSE_URL=http://localhost:8123 cargo test -- --include-ignored; \
	else \
		echo "==> Starting disposable ClickHouse container on :8123"; \
		docker run -d --rm --name sre-agent-test-ch -p 8123:8123 clickhouse/clickhouse-server:24.8 >/dev/null; \
		trap 'echo "==> Stopping sre-agent-test-ch"; docker stop sre-agent-test-ch >/dev/null 2>&1 || true' EXIT; \
		echo "==> Waiting for ClickHouse to answer /ping (timeout 60s)"; \
		i=0; until curl -sf http://localhost:8123/ping >/dev/null 2>&1; do \
			i=$$((i+1)); \
			if [ $$i -ge 60 ]; then echo "ClickHouse did not become ready in 60s" >&2; exit 1; fi; \
			sleep 1; \
		done; \
		echo "==> ClickHouse ready — note: a fresh container lacks query-api's config_* schema;"; \
		echo "    tests touching config_anomaly_rules/config_skills need a dev ClickHouse instead."; \
		CLICKHOUSE_URL=http://localhost:8123 cargo test -- --include-ignored; \
	fi

fmt:                  ## Format code
	cargo fmt

lint:                 ## Run clippy lints
	cargo clippy -- -D warnings

## Docker

docker:               ## Build Docker image
	docker build --platform linux/amd64 -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

docker-push:          ## Push Docker image
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):latest

## Cleanup

clean:                ## Remove build artefacts
	cargo clean

## Help

help:                 ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
