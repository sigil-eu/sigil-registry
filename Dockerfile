# ── Build stage ──────────────────────────────────────────────────────────────
FROM rust:1.85-slim AS builder

# Install build dependencies for sqlx + TLS
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies first
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release 2>/dev/null; rm -f target/release/deps/sigil_registry*

# Build the real binary
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary and migrations
COPY --from=builder /app/target/release/sigil-registry ./sigil-registry
COPY --from=builder /app/migrations ./migrations

# Non-root user for security
RUN useradd -r -s /bin/false sigil
USER sigil

EXPOSE 3100

ENV RUST_LOG="sigil_registry=info,warn"
ENV LISTEN_ADDR="0.0.0.0:3100"

CMD ["./sigil-registry"]
