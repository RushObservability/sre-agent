# Image for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
#
# The audit runs offline, so this build installs the pinned Rust toolchain, fetches every crate and compiles the
# agent, the eval runner and the tests. threat_model.md, next to this file, says what matters and how to exercise it.
FROM rust:1.88-bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang pkg-config libssl-dev ca-certificates curl git jq python3 ripgrep \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# An ARG, so that it bounds the memory this build uses without reaching the audit environment.
ARG CARGO_BUILD_JOBS=8

# Every crate, then the agent, sre_evals and the tests, as CI builds them (with debug info).
# A step that fails fails the build, and primary_contact gets the log.
RUN cargo fetch --locked
RUN cargo build --locked --all-targets
RUN cargo test --locked --all-targets --no-run

# Run the tests and CI's deterministic replay so the log shows the image works, without letting a failure abort the
# build. The replay uses recorded cases and needs no model or network.
RUN (timeout 1800 cargo test --locked || echo "WARNING: cargo test reported failures") \
    && (python3 -m unittest discover -s scripts -p 'test_*.py' || echo "WARNING: script tests reported failures") \
    && (SRE_EVALS_RUN_ID=oss-scanner timeout 600 cargo run --locked --bin sre_evals -- replay \
          --cases evals/replay_cases.yaml --out /tmp/sre-evals || echo "WARNING: the eval replay reported failures")

# Everything is fetched. From here on cargo must not wait for a registry that it cannot reach.
ENV CARGO_NET_OFFLINE=true
