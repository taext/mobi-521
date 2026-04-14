# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM rust:latest AS builder

WORKDIR /build

# Cache dependencies before copying source
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml  crates/core/Cargo.toml
COPY crates/cli/Cargo.toml   crates/cli/Cargo.toml
COPY crates/wasm/Cargo.toml  crates/wasm/Cargo.toml
COPY crates/python/Cargo.toml crates/python/Cargo.toml

# Stub sources so cargo can resolve the full dependency graph
RUN mkdir -p crates/core/src crates/cli/src crates/wasm/src crates/python/src \
 && echo 'pub fn stub() {}' > crates/core/src/lib.rs \
 && echo 'fn main() {}'     > crates/cli/src/main.rs \
 && echo 'pub fn stub() {}' > crates/wasm/src/lib.rs \
 && echo 'pub fn stub() {}' > crates/python/src/lib.rs \
 && cargo build --release -p mobi521 \
 && rm -rf crates/*/src

# Build the real thing
COPY crates/ crates/
RUN touch crates/core/src/lib.rs crates/cli/src/main.rs \
 && cargo build --release -p mobi521

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/mobi521 /usr/local/bin/mobi521

ENTRYPOINT ["mobi521"]
CMD ["--help"]
