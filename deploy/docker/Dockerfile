# AIP service + verifier — multi-stage build.
# Build context MUST be the repository root (both workspaces are needed because
# aip-service path-depends on ../aip-standalone):
#
#   docker build -f deploy/docker/Dockerfile -t aip-service .

FROM rust:1-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build

# Both workspaces (aip-service depends on ../aip-standalone via path deps).
COPY aip-standalone ./aip-standalone
COPY aip-service ./aip-service

# Build the deployable service and the auditor verifier.
RUN cargo build --release --manifest-path aip-service/Cargo.toml \
 && cargo build --release --manifest-path aip-standalone/Cargo.toml -p aip-verify

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -d /var/lib/aip aip

COPY --from=builder /build/aip-service/target/release/airon-aip /usr/local/bin/aip-service
COPY --from=builder /build/aip-standalone/target/release/aip-verify /usr/local/bin/aip-verify

USER aip
WORKDIR /var/lib/aip

# Defaults; override via environment (see deploy/docker/docker-compose.yml).
ENV AIP_PORT=8081 \
    AIP_KEY_PATH=/var/lib/aip/signing.key \
    AIP_VAULT_PATH=/var/lib/aip/evidence.jsonl \
    AIP_DELEGATION_LOG_PATH=/var/lib/aip/delegation.jsonl \
    AIP_REVOCATION_LOG_PATH=/var/lib/aip/revocation.jsonl \
    AIP_API_KEYS_PATH=/etc/aip/keys.json \
    RUST_LOG=info

EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/aip-service"]
