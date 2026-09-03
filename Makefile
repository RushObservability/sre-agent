BINARY  := sre-agent
VERSION := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
IMAGE   := ghcr.io/rushobservability/sre-agent

# Local development wiring. These values are used only by `make dev` and
# `make watch`; `make run` sources the production-style `.env` file instead.
DEV_SRE_AGENT_PORT           := 8081
DEV_QUERY_API_URL            := http://localhost:8080
DEV_SRE_AGENT_INTERNAL_TOKEN := dev-local-agent-token

define run-with-dev-env
	@set -e; \
	SRE_AGENT_PORT=$(DEV_SRE_AGENT_PORT) \
	QUERY_API_URL=$(DEV_QUERY_API_URL) \
	SRE_AGENT_INTERNAL_TOKEN=$(DEV_SRE_AGENT_INTERNAL_TOKEN) \
	RUST_LOG=sre_agent=debug,tower_http=debug \
	$(1)
endef

.PHONY: build build-release release run check test test-integration eval-replay eval-release-gate fmt lint clean docker docker-push help

## Development

build:                ## Build debug binary
	cargo build

build-release:        ## Build optimised release binary
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

test-integration:     ## Run tests that require the local query-api
	@set -e; \
	curl -fsS "$(DEV_QUERY_API_URL)/healthz" >/dev/null || { \
		echo "query-api is not reachable at $(DEV_QUERY_API_URL)" >&2; exit 1; \
	}; \
	QUERY_API_URL=$(DEV_QUERY_API_URL) \
	SRE_AGENT_INTERNAL_TOKEN=$(DEV_SRE_AGENT_INTERNAL_TOKEN) \
	cargo test -- --include-ignored

fmt:                  ## Format code
	cargo fmt

lint:                 ## Run clippy lints
	cargo clippy -- -D warnings

## Release

release:              ## Open a version-bump PR: make release VERSION=0.1.2
	@VERSION="$(VERSION)" DRY_RUN="$(DRY_RUN)" ./scripts/release.sh

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
