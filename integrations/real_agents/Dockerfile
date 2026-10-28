# Build separately on disposable infrastructure. No model secrets at build time.
# Caller supplies a digest-pinned Python 3.12 Debian base and uv version.
ARG PYTHON_IMAGE
FROM ${PYTHON_IMAGE}
ARG FRAMEWORK
ARG REPOSITORY
ARG COMMIT
ARG UV_VERSION
LABEL org.opencontainers.image.revision=${COMMIT}
LABEL org.opencontainers.image.source=${REPOSITORY}
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates build-essential libffi-dev libssl-dev tmux ripgrep && rm -rf /var/lib/apt/lists/*
RUN test -n "$UV_VERSION" && pip install --no-cache-dir "uv==$UV_VERSION"
RUN git clone "$REPOSITORY" /opt/framework && cd /opt/framework && git checkout --detach "$COMMIT" && test "$(git rev-parse HEAD)" = "$COMMIT"
WORKDIR /opt/framework
RUN if [ "$FRAMEWORK" = agent_zero ]; then python -m venv .venv && .venv/bin/pip install -r requirements.txt; \
    elif [ "$FRAMEWORK" = deerflow ]; then cd backend && uv sync --frozen; \
    elif [ "$FRAMEWORK" = openhands ]; then uv sync --frozen --all-packages; \
    else exit 1; fi
RUN useradd --uid 10001 --create-home agent && mkdir -p /opt/snifferdog /work
COPY adapters/launch.py /opt/snifferdog/launch.py
COPY adapters/entrypoint.sh /opt/snifferdog/entrypoint.sh
ENV HOME=/tmp/home UV_CACHE_DIR=/tmp/uv-cache
ENV DEER_FLOW_HOME=/work/deerflow-state
ENV FRAMEWORK=${FRAMEWORK}
USER 10001:10001
ENTRYPOINT ["/bin/sh", "/opt/snifferdog/entrypoint.sh"]
