# Mirqab SMTP Phishing Service
# Sends real phishing emails for security validation

FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

WORKDIR /app

RUN groupadd -r mirqab && useradd -r -g mirqab mirqab

COPY --from=builder /root/.local /home/mirqab/.local
COPY main.py .
COPY templates/ ./templates/

ENV PATH=/home/mirqab/.local/bin:$PATH
ENV PYTHONUNBUFFERED=1

USER mirqab

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8081/health', timeout=2)" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8081"]
