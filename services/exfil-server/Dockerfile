# Cloud Relay Exfil Server
# Handles data exfiltration simulation via HTTP, DNS, ICMP

FROM python:3.11-slim as builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# Production image
FROM python:3.11-slim

WORKDIR /app

RUN useradd -r -u 1000 -g root exfil && \
    mkdir -p /app/logs /app/certs /app/data/exfil && \
    chown -R exfil:root /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

COPY --chown=exfil:root src/ ./src/

USER exfil

EXPOSE 8443 5353/udp 9090

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f -k https://localhost:8443/health || exit 1

ENTRYPOINT ["python", "-m", "src.main"]
