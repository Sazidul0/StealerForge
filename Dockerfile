# Linux/amd64 analysis image. Downloads occur only at build time.
FROM python:3.12-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git ca-certificates libmagic1 xz-utils \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.lock requirements-dev.lock requirements-engines.lock /build/
RUN python -m venv /opt/core && /opt/core/bin/pip install --no-cache-dir -r /build/requirements.lock
RUN python -m venv /opt/engines && /opt/engines/bin/pip install --no-cache-dir -r /build/requirements-engines.lock
COPY scripts/fetch_assets.py /build/fetch_assets.py
COPY container/assets.lock.json /build/assets.lock.json
RUN python /build/fetch_assets.py --lock /build/assets.lock.json --destination /opt/assets

FROM python:3.12-slim-bookworm AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 libstdc++6 libgomp1 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 analyst \
    && mkdir /output /samples && chown analyst:analyst /output
COPY --from=builder /opt/core /opt/core
COPY --from=builder /opt/engines /opt/engines
COPY --from=builder /opt/assets /opt/assets
WORKDIR /app
COPY main.py config.yaml /app/
COPY core /app/core
COPY rules /app/rules
COPY container/config.yaml /app/container/config.yaml
ENV PATH="/opt/core/bin:${PATH}" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 XDG_CACHE_HOME=/tmp/stealerforge-cache
USER analyst
ENTRYPOINT ["python", "/app/main.py", "-c", "/app/container/config.yaml", "--static-only", "--local-engines", "--offline-llm"]
CMD ["--help"]

FROM runtime AS test
USER root
COPY requirements-dev.lock /build/requirements-dev.lock
RUN /opt/core/bin/pip install --no-cache-dir -r /build/requirements-dev.lock
COPY tests /app/tests
COPY managed /app/managed
COPY Dockerfile .dockerignore requirements.lock requirements-dev.lock requirements-engines.lock /app/
COPY container/assets.lock.json /app/container/assets.lock.json
COPY scripts/fetch_assets.py /app/scripts/fetch_assets.py
ENV STEALERFORGE_ENGINE_PYTHON=/opt/engines/bin/python
USER analyst
ENTRYPOINT ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
CMD []
