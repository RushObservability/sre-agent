# 1.88+ required: the agent uses `let`-chains (if let … && …), stabilized in Rust 1.88.
FROM rust:1.98-slim AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release

# Must match the builder's Debian release: rust:1.90-slim is built on trixie
# (glibc 2.39); bookworm (glibc 2.36) can't run the binary ("GLIBC_2.39 not found").
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

RUN groupadd --system appgroup && useradd --system --gid appgroup --no-create-home appuser

COPY --from=builder /app/target/release/sre-agent /usr/local/bin/sre-agent

USER appuser

EXPOSE 8081

CMD ["sre-agent"]
