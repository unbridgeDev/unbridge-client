# Multi-stage build for the Unbridge client workspace.
# Builds the client crates (crates/frost, crates/pool-note, crates/frost-verify-check,
# crates/confidential-vault) into a small runtime image usable in CI or air-gapped
# ceremony sessions.

FROM rust:1.78-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Dependency cache: copy manifests, build stubs, so subsequent source edits
# do not pull the full dep graph again.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates crates
RUN cargo build --workspace --release --all-targets || true

# Real build.
RUN cargo build --workspace --release


FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 1001 --create-home unbridge
USER unbridge

WORKDIR /out
COPY --from=builder /build/target/release/frost-verify-check /out/frost-verify-check
COPY --from=builder /build/target/release/confidential-vault /out/confidential-vault

CMD ["/out/frost-verify-check", "--help"]
