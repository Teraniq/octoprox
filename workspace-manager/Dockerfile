FROM python:3.12.8-slim-bookworm AS builder

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY app /app/app

FROM python:3.12.8-slim-bookworm

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY --from=builder /usr/local /usr/local
COPY --from=builder /app/app /app/app

RUN groupadd --gid 1000 appgroup \
    && useradd --uid 1000 --gid appgroup --home-dir /app --create-home --shell /bin/bash appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appgroup /app \
    && chmod 750 /app/data

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python - <<'PY'
import http.client
import sys

try:
    conn = http.client.HTTPConnection("localhost", 8000, timeout=5)
    conn.request("GET", "/health")
    resp = conn.getresponse()
except Exception:
    sys.exit(1)

sys.exit(0 if resp.status == 200 else 1)
PY

USER appuser
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--proxy-headers", "--no-server-header", "--limit-concurrency", "100"]
