# 1.88+ required: the agent uses `let`-chains (if let … && …), stabilized in Rust 1.88.
FROM rust:1.98-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --locked --release --bin sre-agent

# Minimal glibc runtime with CA certificates, without a shell or package manager.
# Pin the multi-architecture index; Dependabot tracks updates to the latest tag.
FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:5380a8b913d0900cf44180e2205bf3ebf0e0b00a32a0f2fa4ab16cb06d7f9cdf

COPY --from=builder /app/target/release/sre-agent /usr/local/bin/sre-agent

USER 65532:65532

EXPOSE 8081

CMD ["sre-agent"]
