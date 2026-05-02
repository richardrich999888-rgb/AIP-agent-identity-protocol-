# airon-aip — workspace-aware multi-stage build
# Build context: airon/ (monorepo root)

FROM rust:1.88-slim AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# ── Layer 1: workspace manifests (cache-busted only on dep changes) ───────────
COPY Cargo.toml ./
COPY contracts/Cargo.toml    contracts/
COPY services/aip/Cargo.toml     services/aip/
COPY services/gateway/Cargo.toml services/gateway/
COPY services/ccvl/Cargo.toml    services/ccvl/
COPY services/vcp/Cargo.toml     services/vcp/
COPY services/chrono/Cargo.toml  services/chrono/
COPY services/pce/Cargo.toml     services/pce/

# ── Layer 2: stub sources → compile all dependencies ─────────────────────────
# The stub main.rs has no module declarations, so the compiler won't look for
# keys.rs / tokens.rs / models.rs / handlers.rs during this cache-warming step.
RUN mkdir -p contracts \
    && printf '// stub\n' > contracts/types.rs \
    && for svc in gateway aip ccvl vcp chrono pce; do \
         mkdir -p services/${svc}/src; \
         echo 'fn main(){}' > services/${svc}/src/main.rs; \
       done
RUN cargo build --release -p airon-aip

# ── Layer 3: real sources (cache-busted on every source change) ───────────────
COPY contracts/types.rs contracts/types.rs
# Copy all source files in one step — picks up keys.rs, tokens.rs, models.rs, handlers.rs
COPY services/aip/src/ services/aip/src/
RUN touch services/aip/src/main.rs && cargo build --release -p airon-aip

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Create the default key directory; can be overridden via AIP_KEY_PATH + a volume mount.
RUN mkdir -p /var/lib/aip && chmod 700 /var/lib/aip

COPY --from=builder /app/target/release/airon-aip /usr/local/bin/airon-aip

EXPOSE 8081

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:8081/health || exit 1

CMD ["airon-aip"]
