# Build stage
FROM rust:1.83-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./

# Create dummy source to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    echo "pub fn placeholder() {}" > src/lib.rs

# Build dependencies only (cached unless Cargo.toml/lock changes)
RUN cargo build --release && rm -rf src target/release/.fingerprint/traffic_management*

# Copy actual source code
COPY src ./src
COPY benches ./benches
COPY config ./config

# Build the release binary
RUN cargo build --release --bin traffic_management

# Runtime stage - minimal image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -r -s /bin/false -u 1000 trafficcop

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/traffic_management /app/trafficcop

# Copy example config
COPY --from=builder /app/config/example.yaml /app/config/example.yaml

# Create directories for data and certs
RUN mkdir -p /app/data /app/certs && \
    chown -R trafficcop:trafficcop /app

# Switch to non-root user
USER trafficcop

# Expose standard ports
# 80 - HTTP (ACME challenges, redirects)
# 443 - HTTPS
# 9090 - Prometheus metrics
EXPOSE 80 443 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/trafficcop", "--validate", "-c", "/app/config/config.yaml"] || exit 1

# Default entrypoint
ENTRYPOINT ["/app/trafficcop"]

# Default command - config path can be overridden
CMD ["-c", "/app/config/config.yaml"]
