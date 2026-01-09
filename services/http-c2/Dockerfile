# Mirqab HTTP C2 Relay Service
# Multi-stage build for minimal production image

FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

WORKDIR /app

# Create non-root user
RUN groupadd -r mirqab && useradd -r -g mirqab mirqab

# Copy dependencies from builder
COPY --from=builder /root/.local /home/mirqab/.local

# Copy application code
COPY main.py .

# Set environment
ENV PATH=/home/mirqab/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1

# Switch to non-root user
USER mirqab

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8080/health', timeout=2)" || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
