# AIP service + verifiers — multi-stage build.
# Build context MUST be the repository root: the repository is one Cargo
# workspace (root Cargo.toml) and aip-service path-depends on ../aip-standalone.
#
#   docker build -f deploy/docker/Dockerfile -t aip-service .

FROM rust:1-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build

# The whole workspace: root manifest + lockfile, both crate trees.
COPY Cargo.toml Cargo.lock ./
COPY aip-standalone ./aip-standalone
COPY aip-service ./aip-service

# Build from the workspace root: the service (PostgreSQL backend + aip-migrate),
# the EvidencePacket/bundle verifier, and the Ghost verdict/NEXORA verifier.
RUN cargo build --release --locked \
      -p airon-aip --features airon-aip/postgres \
      -p aip-verify \
      -p aip-nexora --bin nexora-verify

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -d /var/lib/aip aip

COPY --from=builder /build/target/release/airon-aip     /usr/local/bin/aip-service
COPY --from=builder /build/target/release/aip-migrate   /usr/local/bin/aip-migrate
COPY --from=builder /build/target/release/aip-verify    /usr/local/bin/aip-verify
COPY --from=builder /build/target/release/nexora-verify /usr/local/bin/nexora-verify

USER aip
WORKDIR /var/lib/aip

# Defaults; override via environment (see deploy/docker/docker-compose.yml).
# trivy DS-0031: these ENV values are file PATHS / config, not secret values.
# The signing key and API keys live in files at these paths (mounted volumes),
# never baked into the image — so there is no secret exposure here.
#
# The service REFUSES TO START with an unwrapped signing key unless
# AIP_CUSTODY_POLICY=development: set AIP_KEY_PASSPHRASE (wraps the key with
# Argon2id + XChaCha20-Poly1305) in the runtime environment. Neither is set here.
#trivy:ignore:AVD-DS-0031
ENV AIP_PORT=8081 \
    AIP_KEY_PATH=/var/lib/aip/signing.key \
    AIP_VAULT_PATH=/var/lib/aip/evidence.jsonl \
    AIP_REVOCATION_LOG_PATH=/var/lib/aip/revocation.jsonl \
    AIP_API_KEYS_PATH=/etc/aip/keys.json \
    RUST_LOG=info

EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/aip-service"]
