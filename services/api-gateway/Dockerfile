# Cloud Relay API Gateway
# Multi-tenant security gateway with mTLS, rate limiting, and quota enforcement

FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# Production image
FROM python:3.11-slim

WORKDIR /app

# Security: Run as non-root user
RUN useradd -r -u 1000 -g root gateway && \
    mkdir -p /app/logs /app/certs && \
    chown -R gateway:root /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels and install
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Copy application code
COPY --chown=gateway:root *.py ./

# Switch to non-root user
USER gateway

# Environment variables (can be overridden at runtime)
ENV REDIS_URL=redis://redis:6379/0 \
    REQUIRE_MTLS=true \
    REQUIRE_SIGNATURE=true \
    DEBUG=false \
    HTTP_C2_URL=http://http-c2:8080 \
    WAF_TESTER_URL=http://waf-tester:8080 \
    PAYLOAD_SERVER_URL=http://payload-server:8080

# Expose HTTP port (TLS terminated at ingress)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application with uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
