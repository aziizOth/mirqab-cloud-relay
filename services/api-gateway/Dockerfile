# Cloud Relay API Gateway
# Handles routing, authentication, and service discovery

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
COPY --chown=gateway:root src/ ./src/
COPY --chown=gateway:root config/ ./config/

# Switch to non-root user
USER gateway

# Expose ports
EXPOSE 8443 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f -k https://localhost:8443/health || exit 1

# Run the application
ENTRYPOINT ["python", "-m", "src.main"]
