FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY app.py /app/app.py

EXPOSE 7000
CMD ["sh", "-c", "uvicorn app:app --host ${MCP_BIND_HOST:-0.0.0.0} --port ${MCP_PORT:-7000}"]
