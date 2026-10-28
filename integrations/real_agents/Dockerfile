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
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates build-essential libffi-dev libssl-dev libgomp1 libgl1 libmagic1 tmux ripgrep nodejs && rm -rf /var/lib/apt/lists/*
RUN test -n "$UV_VERSION" && pip install --no-cache-dir "uv==$UV_VERSION"
RUN git init /opt/framework && cd /opt/framework && git remote add origin "$REPOSITORY" && git fetch --depth=1 origin "$COMMIT" && git checkout --detach FETCH_HEAD && test "$(git rev-parse HEAD)" = "$COMMIT"
WORKDIR /opt/framework
RUN if [ "$FRAMEWORK" = agent_zero ]; then python -m venv .venv && \
        uv pip install --python .venv/bin/python --no-cache torch==2.14.1 torchvision==0.29.1 --index-url https://download.pytorch.org/whl/cpu && \
        printf 'torch==2.14.1+cpu\ntorchvision==0.29.1+cpu\n' > /tmp/cpu-constraints.txt && \
        uv pip install --python .venv/bin/python --no-cache -r requirements.txt -c /tmp/cpu-constraints.txt && \
        uv pip check --python .venv/bin/python; \
    elif [ "$FRAMEWORK" = deerflow ]; then cd backend && uv sync --frozen; \
    elif [ "$FRAMEWORK" = openhands ]; then uv sync --frozen --all-packages; \
    else exit 1; fi
RUN useradd --uid 10001 --create-home agent && mkdir -p /opt/snifferdog /work && \
    ln -s /opt/framework /a0 && \
    rm -rf /opt/framework/tmp /opt/framework/logs && \
    ln -s /tmp/framework /opt/framework/tmp && ln -s /tmp/framework-logs /opt/framework/logs
COPY adapters/launch.py /opt/snifferdog/launch.py
COPY adapters/agent_zero_runtime.py adapters/smoke.py /opt/snifferdog/
COPY adapters/entrypoint.sh /opt/snifferdog/entrypoint.sh
ENV PATH="/opt/framework/.venv/bin:${PATH}" PYTHONDONTWRITEBYTECODE=1
ENV HOME=/tmp/home UV_CACHE_DIR=/tmp/uv-cache
ENV DEER_FLOW_HOME=/work/deerflow-state
ENV FRAMEWORK=${FRAMEWORK}
USER 10001:10001
ENTRYPOINT ["/bin/sh", "/opt/snifferdog/entrypoint.sh"]
