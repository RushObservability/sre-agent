BINARY  := sre-agent
VERSION := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
IMAGE   := mzupan/sre-agent

.PHONY: build release run check test fmt lint clean docker docker-push help

## Development

build:                ## Build debug binary
	cargo build

release:              ## Build optimised release binary
	cargo build --release

run:                  ## Run the agent locally on :8081
	RUST_LOG=sre_agent=debug,tower_http=debug cargo run

watch:                ## Watch & restart on code changes
	RUST_LOG=sre_agent=debug,tower_http=debug cargo watch -x run

## Quality

check:                ## Type-check without building
	cargo check

test:                 ## Run tests
	cargo test

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
