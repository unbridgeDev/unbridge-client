# Multi-stage build for reproducible cross-machine compilation.
# The resulting artifact is the on-chain program binary; length should
# match the deployed program at 6ESjwd4u6qW8SP9PtNwNus1hBJTxKViWra91C36RRALu.

FROM rust:1.78-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        build-essential \
        curl \
        git \
    && rm -rf /var/lib/apt/lists/*

# Solana CLI for cargo-build-sbf.
RUN curl -sSfL https://release.solana.com/v1.18.26/install | sh
ENV PATH="/root/.local/share/solana/install/active_release/bin:${PATH}"

WORKDIR /build

# Dependency cache: copy manifests, build empty crate, so subsequent source
# edits do not pull the full dep graph again.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY programs/zkcash/Cargo.toml programs/zkcash/Cargo.toml
COPY programs/zkcash/Xargo.toml programs/zkcash/Xargo.toml
RUN mkdir -p programs/zkcash/src \
    && echo "pub fn _stub() {}" > programs/zkcash/src/lib.rs \
    && cargo build-sbf --manifest-path programs/zkcash/Cargo.toml || true

# Real build.
COPY programs programs
RUN cargo build-sbf --manifest-path programs/zkcash/Cargo.toml


FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 1001 --create-home unbridge
USER unbridge

WORKDIR /out
COPY --from=builder /build/target/deploy/zkcash.so /out/zkcash.so

CMD ["ls", "-la", "/out/zkcash.so"]
