# Cloud Relay WAF Tester
# Tests WAF effectiveness with common attack payloads

FROM python:3.11-slim as builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# Production image
FROM python:3.11-slim

WORKDIR /app

RUN useradd -r -u 1000 -g root waftester && \
    mkdir -p /app/logs /app/certs /app/payloads && \
    chown -R waftester:root /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

COPY --chown=waftester:root src/ ./src/
COPY --chown=waftester:root payloads/ ./payloads/

USER waftester

EXPOSE 8443 9090

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f -k https://localhost:8443/health || exit 1

ENTRYPOINT ["python", "-m", "src.main"]
