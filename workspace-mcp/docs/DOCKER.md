# Docker Deployment Guide

This guide covers Docker deployment options for Octoprox, including multi-stage builds, configuration, and production deployment patterns.

## Table of Contents

- [Quick Start](#quick-start)
- [Multi-Stage Builds](#multi-stage-builds)
- [Environment Variables](#environment-variables)
- [Volume Mounts](#volume-mounts)
- [Docker Compose](#docker-compose)
- [Production Deployment](#production-deployment)
- [Security Considerations](#security-considerations)

---

## Quick Start

### Build and Run

```bash
# Build the Docker image
cd workspace-mcp
docker build -t octoprox .

# Run with minimal configuration
docker run -d \
  -p 7000:7000 \
  -e WORKSPACE_OWNER_USER_ID=123 \
  -e MANAGER_INTROSPECT_URL=http://manager:8000/api/v1/auth/introspect \
  --name octoprox \
  octoprox
```

### Verify Installation

```bash
# Check logs
docker logs octoprox

# Test health endpoint
curl http://localhost:7000/health
```

---

## Multi-Stage Builds

### Default Build (Minimal)

The default Dockerfile provides a lightweight image suitable for most use cases:

```dockerfile
FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    git openssh-client && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY app.py /app/app.py
COPY octoprox /app/octoprox

EXPOSE 7000
CMD ["sh", "-c", "uvicorn app:app --host ${MCP_BIND_HOST:-0.0.0.0} --port ${MCP_PORT:-7000}"]
```

**Image Size:** ~150MB

### Build with Playwright Support

For browser automation features, build with Playwright:

```dockerfile
FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install system dependencies for Playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    git openssh-client \
    libnss3 libatk-bridge2.0 libxss1 libgtk-3-0 \
    libgbm1 libasound2 fonts-liberation wget \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Install Playwright and browsers
RUN pip install playwright && playwright install chromium

COPY app.py /app/app.py
COPY octoprox /app/octoprox

EXPOSE 7000
CMD ["sh", "-c", "uvicorn app:app --host ${MCP_BIND_HOST:-0.0.0.0} --port ${MCP_PORT:-7000}"]
```

**Build command:**
```bash
docker build -t octoprox:playwright -f Dockerfile.playwright .
```

**Image Size:** ~1.2GB

### Using Build Arguments

Control features at build time:

```dockerfile
ARG INSTALL_PLAYWRIGHT=false

# ... base setup ...

RUN if [ "$INSTALL_PLAYWRIGHT" = "true" ]; then \
    pip install playwright && playwright install chromium; \
    fi
```

**Build command:**
```bash
docker build \
  --build-arg INSTALL_PLAYWRIGHT=true \
  -t octoprox:browser \
  .
```

---

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `WORKSPACE_OWNER_USER_ID` | User ID of workspace owner | `123` |
| `MANAGER_INTROSPECT_URL` | Token introspection endpoint | `http://manager:8000/api/v1/auth/introspect` |

### Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_PORT` | `7000` | Port to bind the MCP server |
| `MCP_BIND_HOST` | `0.0.0.0` | Host interface to bind |

### Feature Flags

| Variable | Default | Description |
|----------|---------|-------------|
| `OCTOPROX_ENABLE_OPENAPI` | `true` | Enable OpenAPI adapter tools |
| `OCTOPROX_ENABLE_GITLAB` | `true` | Enable GitLab integration |
| `OCTOPROX_ENABLE_FETCH` | `true` | Enable HTTP fetch tools |
| `OCTOPROX_ENABLE_BROWSER` | `false` | Enable headless browser |
| `OCTOPROX_ENABLE_READABILITY` | `true` | Enable HTML-to-markdown |
| `OCTOPROX_ENABLE_SEARCH` | `true` | Enable web search |
| `OCTOPROX_ENABLE_SHELL` | `false` | Enable shell commands |
| `OCTOPROX_ENABLE_DATABASE` | `false` | Enable database tools |
| `OCTOPROX_ENABLE_MEMORY` | `true` | Enable memory tools |
| `OCTOPROX_ENABLE_TIME` | `true` | Enable time utilities |

### GitLab Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GITLAB_BASE_URL` | `https://gitlab.com` | GitLab instance URL |
| `GITLAB_TOKEN` | - | Personal access token |
| `GITLAB_OPENAPI_URL` | Auto-derived | OpenAPI spec URL |

### Cache Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CACHE_TTL_SECONDS` | `60` | General cache TTL |
| `OPENAPI_CACHE_TTL_SECONDS` | `3600` | OpenAPI spec cache TTL |
| `GITLAB_SPEC_CACHE_TTL_SECONDS` | `3600` | GitLab spec cache TTL |

---

## Volume Mounts

### Workspace Data

Mount the workspace directory for persistent storage:

```bash
docker run -d \
  -v /host/workspace:/workspace:rw \
  -e WORKSPACE_OWNER_USER_ID=123 \
  octoprox
```

**Important:** The container expects `/workspace` to exist and be writable.

### SSH Keys

Mount existing SSH keys (optional):

```bash
docker run -d \
  -v /host/workspace:/workspace:rw \
  -v /host/ssh-keys:/workspace/.ssh:ro \
  -e WORKSPACE_OWNER_USER_ID=123 \
  octoprox
```

If not mounted, keys are auto-generated on first access.

### Configuration

Mount configuration files:

```bash
docker run -d \
  -v /host/workspace:/workspace:rw \
  -v /host/config:/etc/octoprox:ro \
  -e CONFIG_PATH=/etc/octoprox/config.yaml \
  octoprox
```

### Cache Directory

For persistent caching between restarts:

```bash
docker run -d \
  -v /host/workspace:/workspace:rw \
  -v octoprox-cache:/app/.cache \
  octoprox
```

---

## Docker Compose

### Basic Setup

```yaml
version: '3.8'

services:
  mcp-server:
    build:
      context: ./workspace-mcp
    container_name: octoprox-${WORKSPACE_ID}
    environment:
      - WORKSPACE_OWNER_USER_ID=${WORKSPACE_OWNER_USER_ID}
      - MANAGER_INTROSPECT_URL=http://workspace-manager:8000/api/v1/auth/introspect
      - MCP_PORT=7000
      - OCTOPROX_ENABLE_OPENAPI=true
      - OCTOPROX_ENABLE_GITLAB=true
    volumes:
      - workspace-data:/workspace
    ports:
      - "7000:7000"
    networks:
      - octoprox-network
    restart: unless-stopped

volumes:
  workspace-data:

networks:
  octoprox-network:
    external: true
```

### With Playwright Support

```yaml
version: '3.8'

services:
  mcp-server:
    build:
      context: ./workspace-mcp
      args:
        INSTALL_PLAYWRIGHT: "true"
    container_name: octoprox-${WORKSPACE_ID}
    environment:
      - WORKSPACE_OWNER_USER_ID=${WORKSPACE_OWNER_USER_ID}
      - MANAGER_INTROSPECT_URL=http://workspace-manager:8000/api/v1/auth/introspect
      - OCTOPROX_ENABLE_BROWSER=true
    volumes:
      - workspace-data:/workspace
    ports:
      - "7000:7000"
    # Required for Playwright/Chromium
    cap_add:
      - SYS_ADMIN
    networks:
      - octoprox-network
    restart: unless-stopped

volumes:
  workspace-data:

networks:
  octoprox-network:
    external: true
```

### Production Configuration

```yaml
version: '3.8'

services:
  mcp-server:
    build:
      context: ./workspace-mcp
    container_name: octoprox-${WORKSPACE_ID}
    environment:
      # Required
      - WORKSPACE_OWNER_USER_ID=${WORKSPACE_OWNER_USER_ID}
      - MANAGER_INTROSPECT_URL=${MANAGER_INTROSPECT_URL}
      
      # Security: Disable dangerous features
      - OCTOPROX_ENABLE_SHELL=false
      - OCTOPROX_ENABLE_BROWSER=false
      - OCTOPROX_ENABLE_DATABASE=false
      
      # Enable safe features
      - OCTOPROX_ENABLE_OPENAPI=true
      - OCTOPROX_ENABLE_GITLAB=true
      - OCTOPROX_ENABLE_FETCH=true
      - OCTOPROX_ENABLE_READABILITY=true
      - OCTOPROX_ENABLE_MEMORY=true
      - OCTOPROX_ENABLE_TIME=true
      
      # GitLab config
      - GITLAB_BASE_URL=${GITLAB_BASE_URL:-https://gitlab.com}
    volumes:
      - workspace-data:/workspace:rw
      - /etc/ssl/certs:/etc/ssl/certs:ro  # Mount host CA certs
    ports:
      - "127.0.0.1:7000:7000"  # Bind to localhost only
    networks:
      - octoprox-internal
    restart: unless-stopped
    
    # Security options
    read_only: true
    user: "1000:1000"
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 128M

volumes:
  workspace-data:
    driver: local

networks:
  octoprox-internal:
    internal: true  # No external access
```

### Multi-Workspace Setup

```yaml
version: '3.8'

services:
  mcp-server-1:
    build: ./workspace-mcp
    container_name: octoprox-ws-1
    environment:
      - WORKSPACE_OWNER_USER_ID=1
      - MANAGER_INTROSPECT_URL=http://manager:8000/api/v1/auth/introspect
      - MCP_PORT=7000
    volumes:
      - workspace-1:/workspace
    networks:
      - octoprox-network

  mcp-server-2:
    build: ./workspace-mcp
    container_name: octoprox-ws-2
    environment:
      - WORKSPACE_OWNER_USER_ID=2
      - MANAGER_INTROSPECT_URL=http://manager:8000/api/v1/auth/introspect
      - MCP_PORT=7000
    volumes:
      - workspace-2:/workspace
    networks:
      - octoprox-network

volumes:
  workspace-1:
  workspace-2:

networks:
  octoprox-network:
```

---

## Production Deployment

### Health Checks

Add health checks to your deployment:

```yaml
services:
  mcp-server:
    # ... other config ...
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

### Logging Configuration

```yaml
services:
  mcp-server:
    # ... other config ...
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        labels: "service,environment"
        env: "WORKSPACE_OWNER_USER_ID"
```

### Reverse Proxy (Traefik)

```yaml
services:
  mcp-server:
    # ... other config ...
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.octoprox.rule=Host(`mcp.example.com`)"
      - "traefik.http.routers.octoprox.tls=true"
      - "traefik.http.routers.octoprox.tls.certresolver=letsencrypt"
      - "traefik.http.services.octoprox.loadbalancer.server.port=7000"
    networks:
      - octoprox-network
      - traefik-network
```

### Monitoring (Prometheus)

Add Prometheus metrics endpoint support:

```yaml
services:
  mcp-server:
    # ... other config ...
    environment:
      - ENABLE_METRICS=true
      - METRICS_PORT=8000
    ports:
      - "7000:7000"  # MCP endpoint
      - "8000:8000"  # Metrics endpoint
```

---

## Security Considerations

### Non-Root User

Run containers as non-root:

```dockerfile
# Dockerfile
RUN useradd -m -u 1000 octoprox && \
    chown -R octoprox:octoprox /workspace
USER octoprox
```

```yaml
# docker-compose.yml
services:
  mcp-server:
    user: "1000:1000"
```

### Read-Only Filesystem

```yaml
services:
  mcp-server:
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    volumes:
      - workspace-data:/workspace:rw
```

### Capability Dropping

```yaml
services:
  mcp-server:
    cap_drop:
      - ALL
    cap_add:
      - CHOWN  # Only if needed
      - SETGID
      - SETUID
```

### Network Isolation

```yaml
services:
  mcp-server:
    networks:
      - internal
    # No external network access by default
    
networks:
  internal:
    internal: true
```

### Secret Management

Use Docker secrets or environment files:

```yaml
services:
  mcp-server:
    secrets:
      - gitlab_token
    environment:
      - GITLAB_TOKEN_FILE=/run/secrets/gitlab_token

secrets:
  gitlab_token:
    file: ./secrets/gitlab_token.txt
```

---

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker logs octoprox

# Check environment variables
docker inspect octoprox | jq '.[0].Config.Env'

# Verify volume permissions
docker exec octoprox ls -la /workspace
```

### Permission Denied

```bash
# Fix volume ownership
sudo chown -R 1000:1000 /host/workspace

# Or run as root (not recommended for production)
docker run -u 0 ...
```

### Network Issues

```bash
# Test network connectivity
docker exec octoprox ping manager

# Check DNS resolution
docker exec octoprox nslookup manager
```

### High Memory Usage

```bash
# Monitor memory
docker stats octoprox

# Set memory limits
docker run -m 512m --memory-swap 512m ...
```

---

## Building for Multiple Architectures

```bash
# Create buildx builder
docker buildx create --name multiarch --use

# Build for multiple platforms
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t octoprox:latest \
  --push \
  .
```
