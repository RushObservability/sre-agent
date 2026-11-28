# Match or exceed the Rust version in rust-toolchain.toml.
FROM rust:1.100-slim@sha256:24516ae4487ab804e3db145c93f7240e58e225587ab9b7c62ea31a218727bf67 AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY contracts ./contracts

RUN cargo build --locked --release --bin sre-agent

# Minimal glibc runtime with CA certificates, without a shell or package manager.
# Pin the multi-architecture index; Dependabot tracks updates to the latest tag.
FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:7fc93aea6a9305a44f4f10d0cab0c6f5211ab24a2a97320ec75619ab149ee25e

COPY --from=builder /app/target/release/sre-agent /usr/local/bin/sre-agent

USER 65532:65532

EXPOSE 8081

CMD ["sre-agent"]
