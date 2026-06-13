# syntax=docker/dockerfile:1

# ---- builder ---------------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src

# Build a wheel so the runtime image installs a clean, pinned artifact.
RUN pip install --upgrade pip build && python -m build --wheel --outdir /dist

# ---- runtime ---------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Create an unprivileged user to run the service.
RUN groupadd --system mnemosyne && useradd --system --gid mnemosyne --create-home mnemosyne

WORKDIR /app
COPY --from=builder /dist/*.whl /tmp/
RUN pip install /tmp/*.whl "mnemosyne-guard[api]" && rm -f /tmp/*.whl

# Drop privileges.
USER mnemosyne

EXPOSE 8000

# NOTE: provide a real key at runtime, e.g.
#   docker run -e MNEMOSYNE_INTEGRITY_KEY=... -e MNEMOSYNE_API_KEYS=... ...
ENV MNEMOSYNE_LOG_JSON=true

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"

ENTRYPOINT ["uvicorn", "mnemosyne.api.main:factory", "--factory", \
            "--host", "0.0.0.0", "--port", "8000"]
