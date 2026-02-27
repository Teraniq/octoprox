# Octoprox Deployment Guide

This document provides comprehensive instructions for deploying, migrating, and maintaining Octoprox in production environments.

## Table of Contents

- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Environment Setup](#environment-setup)
- [Database Migration](#database-migration)
- [Deployment Procedures](#deployment-procedures)
- [Post-Deployment Verification](#post-deployment-verification)
- [Rollback Procedures](#rollback-procedures)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## Pre-Deployment Checklist

Before deploying Octoprox to production, ensure the following items are completed:

### Security Preparation

- [x] Generate secure `SECRET_KEY` (minimum 32 characters)
- [x] Generate secure `JWT_SECRET_KEY` (minimum 32 characters, recommended 64+)
- [x] Generate secure `INTROSPECT_SECRET` (optional, for introspection endpoint)
- [x] Change default `BOOTSTRAP_ADMIN_PASSWORD` from default value
- [x] Review and configure rate limiting settings
- [x] Verify Docker socket security measures are in place

### Infrastructure

- [x] Ensure Docker and Docker Compose are installed
- [x] Verify network connectivity between services
- [x] Confirm port 8080 is available (or configure alternative)
- [x] Set up log aggregation and monitoring
- [x] Configure backup solution for database volume

### Testing

- [x] Run full test suite: `cd workspace-manager && pytest`
- [x] Verify all API endpoints respond correctly
- [x] Test authentication flows (session, API key, JWT)
- [x] Validate workspace provisioning and deletion
- [x] Test rate limiting behavior

### Environment Variables

| Variable | Status | Notes |
|----------|--------|-------|
| `SECRET_KEY` | ⬜ | Must be ≥32 chars |
| `JWT_SECRET_KEY` | ⬜ | Must be ≥32 chars |
| `BOOTSTRAP_ADMIN_USERNAME` | ⬜ | Change from default |
| `BOOTSTRAP_ADMIN_PASSWORD` | ⬜ | Strong password required |
| `PUBLIC_BASE_URL` | ⬜ | Match production URL |
| `DATABASE_URL` | ⬜ | SQLite or external DB |

---

## Environment Setup

### 1. Generate Secure Secrets

```bash
# Generate SECRET_KEY (session management)
export SECRET_KEY=$(openssl rand -base64 32)
echo "SECRET_KEY=$SECRET_KEY"

# Generate JWT_SECRET_KEY (JWT signing)
export JWT_SECRET_KEY=$(openssl rand -base64 64)
echo "JWT_SECRET_KEY=$JWT_SECRET_KEY"

# Generate INTROSPECT_SECRET (optional, for introspection)
export INTROSPECT_SECRET=$(openssl rand -base64 32)
echo "INTROSPECT_SECRET=$INTROSPECT_SECRET"

# Generate strong admin password
export BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -base64 24)
echo "BOOTSTRAP_ADMIN_PASSWORD=$BOOTSTRAP_ADMIN_PASSWORD"
```

### 2. Create Environment File

Create a `.env` file in the project root:

```bash
# Copy example file
cp .env.example .env

# Edit with your favorite editor
nano .env
```

**Required Configuration:**

```bash
# Security (REQUIRED - DO NOT USE DEFAULTS)
SECRET_KEY=your-generated-secret-key
JWT_SECRET_KEY=your-generated-jwt-secret

# Bootstrap Admin (REQUIRED)
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=your-secure-password

# Application
PUBLIC_BASE_URL=https://your-domain.com
DATABASE_URL=sqlite:///./data/manager.db

# Rate Limiting (optional, defaults shown)
API_RATE_LIMIT=200
AUTH_RATE_LIMIT=60

# NEXUSGATE Integration (optional)
NEXUSGATE_INTEGRATION_ENABLED=false
INTROSPECT_SECRET=your-introspect-secret
```

### 3. Directory Structure Setup

```bash
# Create data directory with proper permissions
mkdir -p data
chmod 755 data

# For SQLite persistence in Docker
mkdir -p octoprox/workspace-manager/data
chmod 755 octoprox/workspace-manager/data
```

### 4. Docker Network Configuration

The application uses a dedicated Docker network `mcpnet`. It will be created automatically by Docker Compose, but you can verify/create it manually:

```bash
# Check if network exists
docker network ls | grep mcpnet

# Create manually if needed
docker network create mcpnet
```

---

## Database Migration

Octoprox uses SQLAlchemy's `create_all()` for database schema management rather than Alembic migrations. This approach is suitable for SQLite and simplifies deployment.

### Schema Creation (First Deployment)

On first startup, the application automatically creates all required tables:

```python
# This happens automatically in app/db.py
Base.metadata.create_all(bind=engine)
```

### Tables Created

| Table | Purpose | Key Fields |
|-------|---------|------------|
| `users` | User accounts | id, username, role, status, nexusgate_user_id |
| `api_keys` | API key storage | id, user_id, key_prefix, key_hash, last_used_at |
| `workspaces` | Workspace definitions | id, user_id, name, status, metadata |

### Migration from Existing Database

If you have an existing Octoprox database without NEXUSGATE fields:

#### Option 1: Automatic Schema Migration (Recommended for Development)

SQLAlchemy will add new columns automatically on startup when using `create_all()` with `checkfirst=True` (default behavior).

**Note:** This does NOT add columns to existing tables. For production migrations, use Option 2.

#### Option 2: Manual Migration Script (Recommended for Production)

For existing databases, run these SQL commands:

```sql
-- Backup first!
-- cp data/manager.db data/manager.db.backup.$(date +%Y%m%d)

-- Add NEXUSGATE fields to users table
ALTER TABLE users ADD COLUMN updated_at TIMESTAMP;
ALTER TABLE users ADD COLUMN nexusgate_user_id VARCHAR(36) UNIQUE;
ALTER TABLE users ADD COLUMN nexusgate_role VARCHAR(64);
ALTER TABLE users ADD COLUMN last_synced_at TIMESTAMP;
CREATE INDEX idx_users_nexusgate_user_id ON users(nexusgate_user_id);

-- Add NEXUSGATE fields to api_keys table
ALTER TABLE api_keys ADD COLUMN last_used_at TIMESTAMP;
ALTER TABLE api_keys ADD COLUMN nexusgate_token_id VARCHAR(64) UNIQUE;
ALTER TABLE api_keys ADD COLUMN name VARCHAR(128);
ALTER TABLE api_keys ADD COLUMN expires_at TIMESTAMP;
CREATE INDEX idx_api_keys_nexusgate_token_id ON api_keys(nexusgate_token_id);

-- Add NEXUSGATE fields to workspaces table
ALTER TABLE workspaces ADD COLUMN updated_at TIMESTAMP;
ALTER TABLE workspaces ADD COLUMN metadata JSON DEFAULT '{}';
ALTER TABLE workspaces ADD COLUMN nexusgate_service_id VARCHAR(64);
ALTER TABLE workspaces ADD COLUMN container_id VARCHAR(64);
ALTER TABLE workspaces ADD COLUMN container_status VARCHAR(32);
CREATE INDEX idx_workspaces_nexusgate_service_id ON workspaces(nexusgate_service_id);
```

#### Option 3: Fresh Database (Clean Slate)

For a completely fresh start:

```bash
# WARNING: This deletes all data!
docker-compose down
rm -f data/manager.db
# Or for Docker volume:
docker volume rm octoprox_manager-data

# Restart to create fresh database
docker-compose up -d
```

### Verification

Verify database schema after migration:

```bash
# Access SQLite database
docker exec -it workspace-manager sh
sqlite3 /app/data/manager.db

# Check table schema
.schema users
.schema api_keys
.schema workspaces

# Verify new columns exist
SELECT name FROM pragma_table_info('users');
SELECT name FROM pragma_table_info('api_keys');
SELECT name FROM pragma_table_info('workspaces');
```

---

## Deployment Procedures

### Standard Deployment

#### Step 1: Build Images

```bash
# Build all images
docker-compose --profile build build

# Or build specific service
docker-compose build workspace-manager
docker-compose build mcp-gitfs
```

#### Step 2: Deploy Services

```bash
# Load environment variables
export $(cat .env | xargs)

# Deploy
docker-compose up -d

# Verify services are running
docker-compose ps
```

#### Step 3: Verify Deployment

```bash
# Check logs
docker-compose logs -f workspace-manager

# Test health endpoint
curl http://localhost:8080/api/v1/health

# Test introspection (if configured)
curl -X POST http://localhost:8080/api/v1/auth/introspect \
  -H "Content-Type: application/json" \
  -d '{"token": "test"}'
```

### Zero-Downtime Deployment (Blue/Green)

For production environments requiring zero downtime:

```bash
# 1. Build new image with tag
docker-compose -f docker-compose.yml build workspace-manager
docker tag workspace-manager:latest workspace-manager:new

# 2. Start new containers alongside existing
docker-compose -f docker-compose.yml -f docker-compose.new.yml up -d

# 3. Update Traefik labels to point to new service
# (Modify docker-compose.new.yml to use different container name)

# 4. Verify new deployment
curl http://localhost:8080/api/v1/health

# 5. Stop old containers
docker-compose stop workspace-manager

# 6. Remove old containers
docker-compose rm workspace-manager
```

### Production Deployment with TLS

For production with TLS termination:

```bash
# Update PUBLIC_BASE_URL to HTTPS
export PUBLIC_BASE_URL=https://api.yourdomain.com

# Configure reverse proxy (nginx/traefik) for TLS
# See README.md for Nginx Proxy Manager setup

# Deploy
docker-compose up -d
```

---

## Post-Deployment Verification

### Automated Verification Script

```bash
#!/bin/bash
# verify-deployment.sh

BASE_URL="${PUBLIC_BASE_URL:-http://localhost:8080}"
FAILED=0

echo "=== Octoprox Deployment Verification ==="
echo "Base URL: $BASE_URL"

# Test 1: Health Check
echo -n "1. Health check... "
if curl -sf "$BASE_URL/api/v1/health" > /dev/null; then
    echo "PASS"
else
    echo "FAIL"
    FAILED=1
fi

# Test 2: API Response Format
echo -n "2. API response format... "
RESPONSE=$(curl -sf "$BASE_URL/api/v1/health")
if echo "$RESPONSE" | grep -q '"status"'; then
    echo "PASS"
else
    echo "FAIL"
    FAILED=1
fi

# Test 3: Database Connectivity
echo -n "3. Database connectivity... "
if echo "$RESPONSE" | grep -q '"database":{"status":"healthy"'; then
    echo "PASS"
else
    echo "FAIL"
    FAILED=1
fi

# Test 4: Docker Connectivity
echo -n "4. Docker connectivity... "
if echo "$RESPONSE" | grep -q '"docker":{"status":"healthy"'; then
    echo "PASS"
else
    echo "FAIL"
    FAILED=1
fi

# Test 5: Authentication Required
echo -n "5. Authentication enforcement... "
if curl -sf "$BASE_URL/api/v1/users" > /dev/null 2>&1; then
    echo "FAIL (should require auth)"
    FAILED=1
else
    echo "PASS"
fi

echo ""
if [ $FAILED -eq 0 ]; then
    echo "=== All tests passed! Deployment successful. ==="
    exit 0
else
    echo "=== Some tests failed. Check logs: docker-compose logs ==="
    exit 1
fi
```

### Manual Verification Checklist

- [x] Access web UI at `/app`
- [x] Log in with bootstrap admin credentials
- [x] Create a test workspace
- [x] Generate an API key
- [x] Test API key authentication
- [x] Verify rate limiting (make 60+ auth requests)
- [x] Check security headers in responses
- [x] Verify audit logs are being written
- [x] Test workspace soft-delete and purge

---

## Rollback Procedures

### Rollback Triggers

Initiate rollback if any of the following occur:

- Application fails health checks for >5 minutes
- Error rate exceeds 1% of requests
- Database connectivity issues
- Authentication system failures
- Performance degradation (>5s response times)
- Critical security vulnerability discovered

### Quick Rollback (Docker)

```bash
# 1. Identify previous image tag
docker images | grep workspace-manager

# 2. Stop current containers
docker-compose down

# 3. Restore database from backup
cp data/manager.db.backup.YYYYMMDD data/manager.db

# 4. Start with previous image
docker-compose up -d
```

### Database Rollback

```bash
# If using SQLite, restore from backup
# List available backups
ls -la data/manager.db.backup.*

# Restore specific backup
cp data/manager.db.backup.20250210 data/manager.db

# Restart application
docker-compose restart workspace-manager
```

### Configuration Rollback

```bash
# Restore previous .env file
git checkout HEAD -- .env

# Or restore from backup
cp .env.backup.YYYYMMDD .env

# Restart services
docker-compose up -d
```

### Emergency Procedures

#### Complete Service Stop

```bash
# Stop all services immediately
docker-compose down

# Prevent automatic restart
docker-compose stop
```

#### Data Recovery

```bash
# If database is corrupted, check for SQLite recovery options
sqlite3 data/manager.db ".recover" | sqlite3 data/manager.db.recovered

# Verify recovered database
sqlite3 data/manager.db.recovered "SELECT COUNT(*) FROM users;"

# Replace if valid
mv data/manager.db data/manager.db.corrupted
mv data/manager.db.recovered data/manager.db
```

---

## Security Considerations

### Critical Security Checklist

#### Secrets Management

- [x] `SECRET_KEY` is at least 32 characters and randomly generated
- [x] `JWT_SECRET_KEY` is at least 32 characters (different from SECRET_KEY)
- [x] `BOOTSTRAP_ADMIN_PASSWORD` is strong and unique
- [x] `INTROSPECT_SECRET` is configured if using introspection
- [x] No secrets are committed to version control
- [x] `.env` file has restricted permissions (chmod 600)

#### Docker Security

- [x] Docker socket access is secured
- [x] Consider using Docker socket proxy (tecnativa/docker-socket-proxy)
- [x] Container runs as non-root user
- [x] Image is regularly updated for security patches

**Docker Socket Security Options:**

```yaml
# Option 1: Docker Socket Proxy (Recommended)
services:
  socket-proxy:
    image: tecnativa/docker-socket-proxy
    environment:
      - CONTAINERS=1
      - NETWORKS=1
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro

  workspace-manager:
    environment:
      - DOCKER_HOST=tcp://socket-proxy:2375
    # Remove direct socket mount
```

#### Network Security

- [x] Firewall configured to expose only port 8080
- [x] Internal endpoints (`/internal/*`) are not exposed externally
- [x] Traefik is configured with proper middleware
- [x] Rate limiting is enabled and tested

#### API Security

- [x] Rate limiting is configured (200 req/min general, 60 req/min auth)
- [x] Security headers are present on all responses
- [x] JWT tokens have appropriate expiration (default: 15 minutes)
- [x] API keys are stored hashed (Argon2)
- [x] Session cookies are HTTP-only and secure

#### Data Protection

- [x] Database backups are encrypted
- [x] API key tokens are only displayed once on creation
- [x] Passwords are hashed with Argon2
- [x] Audit logs capture security events
- [x] Sensitive data is not logged

### Security Headers Verification

```bash
curl -I http://localhost:8080/api/v1/health

# Expected headers:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# X-XSS-Protection: 1; mode=block
# Content-Security-Policy: default-src 'self'
# Referrer-Policy: strict-origin-when-cross-origin
```

### Penetration Testing Checklist

- [x] Test for SQL injection in all user inputs
- [x] Test for XSS in workspace names and metadata
- [x] Verify path traversal protection in filesystem tools
- [x] Test authentication bypass attempts
- [x] Verify rate limiting effectiveness
- [x] Test for insecure direct object references
- [x] Check for information disclosure in error messages

---

## Troubleshooting

### Common Issues

#### Issue: Application fails to start

**Symptoms:** Container exits immediately

**Solutions:**
```bash
# Check logs
docker-compose logs workspace-manager

# Verify environment variables are set
docker-compose config

# Check if required secrets are set
if [ -z "$SECRET_KEY" ]; then echo "SECRET_KEY not set"; fi
if [ -z "$JWT_SECRET_KEY" ]; then echo "JWT_SECRET_KEY not set"; fi
```

#### Issue: Database errors

**Symptoms:** "unable to open database file" or permission errors

**Solutions:**
```bash
# Check directory permissions
ls -la data/

# Fix permissions
chmod 755 data
touch data/manager.db
chmod 644 data/manager.db

# For Docker, ensure volume is mounted correctly
docker volume ls | grep manager-data
docker volume inspect octoprox_manager-data
```

#### Issue: Docker socket errors

**Symptoms:** "Cannot connect to Docker daemon"

**Solutions:**
```bash
# Check Docker socket exists
ls -la /var/run/docker.sock

# Verify Docker is running
docker info

# Check container has access
docker exec workspace-manager ls -la /var/run/docker.sock
```

#### Issue: JWT validation errors

**Symptoms:** "JWT_SECRET_KEY must be at least 32 characters"

**Solutions:**
```bash
# Generate new key
export JWT_SECRET_KEY=$(openssl rand -base64 64)
echo "JWT_SECRET_KEY length: ${#JWT_SECRET_KEY}"

# Update .env and restart
echo "JWT_SECRET_KEY=$JWT_SECRET_KEY" >> .env
docker-compose restart workspace-manager
```

#### Issue: Rate limiting too aggressive

**Symptoms:** Frequent 429 responses

**Solutions:**
```bash
# Temporarily increase limits in .env
API_RATE_LIMIT=500
AUTH_RATE_LIMIT=120

# Restart
docker-compose up -d

# Monitor and adjust based on actual usage
```

### Getting Help

If you encounter issues not covered here:

1. Check application logs: `docker-compose logs -f workspace-manager`
2. Review test output: `cd workspace-manager && pytest -v`
3. Verify configuration: `docker-compose config`
4. Check system resources: `docker stats`

---

## Appendix

### Environment Variable Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | Yes | Generated | Session signing key (≥32 chars) |
| `JWT_SECRET_KEY` | Yes | Generated | JWT signing key (≥32 chars) |
| `BOOTSTRAP_ADMIN_USERNAME` | Yes | - | Initial admin username |
| `BOOTSTRAP_ADMIN_PASSWORD` | Yes | - | Initial admin password |
| `PUBLIC_BASE_URL` | No | http://localhost:8080 | External URL |
| `DATABASE_URL` | No | sqlite:///./data/manager.db | Database connection |
| `JWT_ALGORITHM` | No | HS256 | JWT signing algorithm |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | No | 15 | JWT token lifetime |
| `NEXUSGATE_INTEGRATION_ENABLED` | No | false | Enable NEXUSGATE features |
| `INTROSPECT_SECRET` | No | - | Introspection endpoint secret |
| `API_RATE_LIMIT` | No | 200 | General API rate limit (req/min) |
| `AUTH_RATE_LIMIT` | No | 60 | Auth endpoint rate limit (req/min) |
| `PURGE_INTERVAL_SECONDS` | No | 300 | Workspace purge interval |
| `WORKSPACE_IMAGE` | No | mcp-gitfs:latest | Workspace container image |
| `DOCKER_NETWORK` | No | mcpnet | Docker network name |

### Backup Script

```bash
#!/bin/bash
# backup-octoprox.sh

BACKUP_DIR="/backups/octoprox"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup database
docker cp workspace-manager:/app/data/manager.db "$BACKUP_DIR/manager.db.$DATE"

# Backup environment
cp .env "$BACKUP_DIR/env.$DATE"

# Compress
cd "$BACKUP_DIR"
tar czf "octoprox-backup-$DATE.tar.gz" "manager.db.$DATE" "env.$DATE"
rm "manager.db.$DATE" "env.$DATE"

# Keep only last 7 backups
ls -t octoprox-backup-*.tar.gz | tail -n +8 | xargs rm -f

echo "Backup completed: $BACKUP_DIR/octoprox-backup-$DATE.tar.gz"
```

---

**Document Version:** 1.0.0  
**Last Updated:** 2026-02-10  
**Compatibility:** Octoprox NEXUSGATE Integration v1.0.0+
