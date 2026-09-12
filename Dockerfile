# 1.88+ required: the agent uses `let`-chains (if let … && …), stabilized in Rust 1.88.
FROM rust:1.98-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --locked --release --bin sre-agent

# Minimal glibc runtime with CA certificates, without a shell or package manager.
# Pin the multi-architecture index; Dependabot tracks updates to the latest tag.
FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:94ec8c23c45c7aad22b6ab400dc7e1b46dd36f4c71d6c7a3976c8ad4e36ca266

COPY --from=builder /app/target/release/sre-agent /usr/local/bin/sre-agent

USER 65532:65532

EXPOSE 8081

CMD ["sre-agent"]
