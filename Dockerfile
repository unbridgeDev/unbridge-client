FROM rust:1.79-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      pkg-config libssl-dev build-essential ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY engine engine
COPY rustfmt.toml clippy.toml ./
RUN cargo build --release --workspace

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --uid 1001 --create-home unbridge
USER unbridge
WORKDIR /home/unbridge

COPY --from=builder --chown=unbridge:unbridge \
      /build/target/release /home/unbridge/bin

ENV PATH="/home/unbridge/bin:${PATH}"
ENV UNBRIDGE_LOG_LEVEL=info

ENTRYPOINT ["/home/unbridge/bin/coordinator"]
