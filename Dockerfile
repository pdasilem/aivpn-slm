# AIVPN Server Production Dockerfile
# Multi-stage build for minimal image size

# Stage 1: Build
FROM rust:1.86-slim AS builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace
COPY Cargo.toml ./
COPY aivpn-common aivpn-common/
COPY aivpn-server aivpn-server/
COPY aivpn-admin aivpn-admin/
COPY aivpn-admin-web aivpn-admin-web/

# Prune client-only crates from the server image build workspace.
RUN sed -e '/"aivpn-client"/d' -e '/"aivpn-android-core"/d' Cargo.toml > Cargo.toml.pruned && \
    mv Cargo.toml.pruned Cargo.toml

# Build in release mode
RUN cargo build --release --features metrics --bin aivpn-server --bin aivpn-admin --bin aivpn-admin-web

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    iptables \
    iproute2 \
    netcat-openbsd \
    bc \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 aivpn

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/aivpn-server /usr/local/bin/aivpn-server
COPY --from=builder /app/target/release/aivpn-admin /usr/local/bin/aivpn-admin
COPY --from=builder /app/target/release/aivpn-admin-web /usr/local/bin/aivpn-admin-web

# Create config directory and TUN device node
RUN mkdir -p /etc/aivpn /dev/net && \
    mknod /dev/net/tun c 10 200 2>/dev/null || true && \
    chmod 600 /dev/net/tun

# Expose ports
EXPOSE 443/udp
EXPOSE 9100/tcp
EXPOSE 27449/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD test "$(basename "$(readlink /proc/1/exe 2>/dev/null)")" = "aivpn-server" || exit 1

# Run as root (required for TUN device and NAT)
ENTRYPOINT ["/usr/local/bin/aivpn-server"]
CMD ["--listen", "0.0.0.0:443", "--key-file", "/etc/aivpn/server.key"]
