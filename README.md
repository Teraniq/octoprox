<img width="2048" height="2048" alt="wenga_Create_a_logo_for_a_new_software_service_called_octoprox _d9528fc8-46f1-43e3-93ed-ce6a508ee392" src="https://github.com/user-attachments/assets/54a52c1d-7f15-42fa-aeb5-5e298adc6df6" />

# Octoprox

Production-shaped MVP for managing user workspaces and dedicated MCP servers with per-user API keys.

**⚠️ SECURITY NOTICE:** Docker socket access is required for workspace provisioning. This grants significant privileges. See [Security](#security) section for mitigation strategies.

## Features
- FastAPI + Jinja2 + HTMX admin/user UI
- Sessions with username/password auth
- RBAC (admin vs user)
- API keys (bearer tokens shown once; stored hashed)
- Workspace provisioning (one container per workspace, volume-backed)
- Traefik routing with `/app/*` and `/ws/<name>/*`
- MCP server per workspace exposing git + filesystem tools
- MCP GitLab API proxy tool (configure GitLab endpoint + token in MCP client)
- MCP helpers to fetch the GitLab OpenAPI spec and enumerate/inspect operations for endpoint discovery
- Soft-delete + purge job
- User deactivation (stops workspaces + hides them from UI)
- **NEXUSGATE Integration**: JWT authentication, RESTful API, rate limiting, audit logging

## Table of Contents

- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [Architecture](#architecture)
- [NEXUSGATE Integration](#nexusgate-integration)
- [Authentication](#authentication)
- [API Usage](#api-usage)
- [Security](#security)
- [Nginx Proxy Manager Setup](#nginx-proxy-manager-tls-termination---traefik)
- [Workspace MCP Endpoints](#workspace-mcp-endpoints)
- [Internal Auth Introspection](#internal-auth-introspection)
- [User Deactivation](#user-deactivation)
- [Testing](#testing)
- [Repository Structure](#repository-structure)
- [Example Client](#example-client)

## Quick Start

1. **Build the images**
   ```bash
   docker compose --profile build build
   ```
2. **Run the stack**
   ```bash
   PUBLIC_BASE_URL=http://localhost:8080 docker compose up -d
   ```
3. **Open the UI**
   - http://localhost:8080/app

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SECRET_KEY` | Session signing key (min 32 chars) | `openssl rand -base64 32` |
| `BOOTSTRAP_ADMIN_USERNAME` | Initial admin username | `admin` |
| `BOOTSTRAP_ADMIN_PASSWORD` | Initial admin password | `change-me-in-production` |
| `JWT_SECRET_KEY` | JWT signing key (min 32 chars) | `openssl rand -base64 64` |

### JWT Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET_KEY` | - | **Required.** Secret key for JWT token signing (minimum 32 characters) |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm (HS256, HS384, HS512) |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Access token expiration time in minutes |

### NEXUSGATE Integration

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXUSGATE_INTEGRATION_ENABLED` | `false` | Enable NEXUSGATE integration features |
| `INTROSPECT_SECRET` | - | Optional secret for introspection endpoint authentication |

### Application Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `PUBLIC_BASE_URL` | `http://localhost:8080` | External URL for generated links |
| `DATABASE_URL` | `sqlite:///./data/manager.db` | Database connection string |
| `WORKSPACE_IMAGE` | `mcp-gitfs:latest` | Docker image for workspace containers |
| `DOCKER_NETWORK` | `mcpnet` | Docker network for workspaces |
| `PURGE_INTERVAL_SECONDS` | `300` | Interval for cleanup jobs (5 minutes) |

### Rate Limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `API_RATE_LIMIT` | `200` | General API requests per minute |
| `AUTH_RATE_LIMIT` | `60` | Authentication endpoint requests per minute |

### HTTPS Enforcement

| Variable | Default | Description |
|----------|---------|-------------|
| `ENFORCE_HTTPS` | `false` | Enable HSTS header for HTTPS enforcement |
| `HSTS_MAX_AGE` | `31536000` | HSTS max-age in seconds (1 year) |
| `HSTS_INCLUDE_SUBDOMAINS` | `true` | Include subdomains in HSTS policy |

**Note:** Only enable `ENFORCE_HTTPS` when running behind an HTTPS reverse proxy.

### Security Best Practices

```bash
# Generate secure keys
export SECRET_KEY=$(openssl rand -base64 32)
export JWT_SECRET_KEY=$(openssl rand -base64 64)
export INTROSPECT_SECRET=$(openssl rand -base64 32)

# Set strong bootstrap credentials
export BOOTSTRAP_ADMIN_USERNAME=admin
export BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -base64 24)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Traefik (Port 8080)                            │
│                    ┌─────────────────────────────────┐                      │
│                    │        Path Routing             │                      │
│                    │  /app/*     → Manager UI        │                      │
│                    │  /api/v1/*  → REST API          │                      │
│                    │  /ws/<name>/* → Workspace MCP   │                      │
│                    └─────────────────────────────────┘                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                       │
            ┌──────────────────────────┼──────────────────────────┐
            │                          │                          │
            ▼                          ▼                          ▼
┌─────────────────────────┐  ┌─────────────────────┐  ┌──────────────────────┐
│   Web UI (HTMX)         │  │   REST API Layer    │  │   Workspace MCP      │
│                         │  │                     │  │   Containers         │
│ • Session Auth          │  │ • JWT Auth          │  │                      │
│ • User Management       │  │ • API Key Auth      │  │ • Git Tools          │
│ • Workspace Management  │  │ • Rate Limiting     │  │ • Filesystem Tools   │
│ • API Key Generation    │  │ • RBAC Enforcement  │  │ • GitLab API Proxy   │
│                         │  │ • Audit Logging     │  │                      │
└─────────────────────────┘  └─────────────────────┘  └──────────────────────┘
            │                          │                          │
            └──────────────────────────┼──────────────────────────┘
                                       │
                              ┌─────────────────┐
                              │   SQLite DB     │
                              │                 │
                              │ • users         │
                              │ • api_keys      │
                              │ • workspaces    │
                              └─────────────────┘
```

### NEXUSGATE Integration Architecture

The NEXUSGATE integration adds a comprehensive API layer:

```
┌──────────────────────────────────────────────────────────────┐
│                     API Clients                              │
│  (Web UI, External Apps, MCP Clients)                        │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                    Authentication Layer                      │
│  ┌──────────────┬──────────────┬──────────────────────────┐  │
│  │ Session Auth │  API Key     │  JWT Bearer              │  │
│  │  (Cookies)   │  (Bearer)    │  (Bearer)                │  │
│  └──────────────┴──────────────┴──────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                    API Gateway (/api/v1)                     │
│  • Rate Limiting (200 req/min general, 60 req/min auth)     │
│  • Security Headers (CSP, HSTS, XSS Protection)             │
│  • Input Validation & Sanitization                          │
│  • Audit Logging                                            │
└──────────────────────────────────────────────────────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            │                 │                 │
            ▼                 ▼                 ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│  User API     │  │ Workspace API │  │ API Key Mgmt  │
│  /users       │  │ /workspaces   │  │ /api-keys     │
│               │  │               │  │               │
│ • List/Get    │  │ • CRUD        │  │ • Create      │
│ • Update      │  │ • Soft Delete │  │ • List        │
│ • Deactivate  │  │ • Metadata    │  │ • Revoke      │
└───────────────┘  └───────────────┘  └───────────────┘
```

## NEXUSGATE Integration

Octoprox includes comprehensive NEXUSGATE integration for enterprise authentication and API management.

### Features

| Feature | Description |
|---------|-------------|
| **JWT Authentication** | Stateless JWT tokens for API access with configurable expiration |
| **Unified Authentication** | Supports session cookies, API keys, and JWT simultaneously |
| **RESTful API** | Full CRUD API for users, workspaces, and API key management |
| **RBAC** | Role-based access control with admin and user roles |
| **Rate Limiting** | IP-based rate limiting with configurable limits |
| **Security Headers** | Comprehensive security headers on all responses |
| **Audit Logging** | Structured logging for security-sensitive operations |
| **MCP Bridge** | Tool invocation endpoints for MCP integration |
| **Token Introspection** | RFC 7662 compliant token introspection endpoint |

### Authentication Methods

The API supports three authentication methods:

1. **Session-Based** (Web UI): Uses HTTP-only cookies
2. **API Key** (Applications): Bearer tokens with `mcp_` prefix
3. **JWT** (External Services): Bearer tokens with configurable expiration

All methods work through the same `Authorization: Bearer <token>` header or session cookies.

### Rate Limiting

| Endpoint Type | Limit | Window |
|--------------|-------|--------|
| General API | 200 requests | 1 minute |
| Authentication | 60 requests | 1 minute |

When rate limit is exceeded:
- HTTP Status: `429 Too Many Requests`
- Response Header: `Retry-After: <seconds>`
- Response Body: `{"error": "Rate limit exceeded", "retry_after": <seconds>}`

### Security Headers

All API responses include:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Content-Security-Policy: default-src 'self'`
- `Referrer-Policy: strict-origin-when-cross-origin`

## Authentication

### Authentication Flows

#### 1. Web UI Session Flow

```
┌─────────┐                    ┌──────────────┐
│  User   │─── POST /login ───▶│   Octoprox   │
│ (Browser│◀── Set-Cookie ────│              │
└─────────┘                    └──────────────┘
      │
      │ Cookie: session=xxx
      ▼
┌──────────────┐
│  Protected   │
│    Pages     │
└──────────────┘
```

1. User submits credentials to `/login`
2. Server validates credentials against Argon2 hash
3. Server creates session and sets HTTP-only cookie
4. Subsequent requests automatically include session cookie
5. Server validates session on each request

#### 2. API Key Authentication Flow

```
┌──────────┐                              ┌──────────────┐
│  Client  │────── GET /api/v1/workspaces ─▶│   Octoprox   │
│          │  Authorization: Bearer mcp_xxx │              │
│          │◀────────── 200 OK ────────────│              │
└──────────┘                              └──────────────┘
                                                 │
                                                 ▼
                                          ┌──────────────┐
                                          │  Extract     │
                                          │  prefix      │
                                          └──────────────┘
                                                 │
                                                 ▼
                                          ┌──────────────┐
                                          │  Verify      │
                                          │  Argon2 hash │
                                          └──────────────┘
```

1. Client sends request with `Authorization: Bearer mcp_<prefix>_<secret>`
2. Server extracts prefix from token
3. Server looks up API key by prefix
4. Server verifies Argon2 hash of provided secret
5. Server checks if user is active
6. Request proceeds with user's permissions

#### 3. JWT Authentication Flow

```
┌──────────┐                              ┌──────────────┐
│  Client  │────── GET /api/v1/users ────▶│   Octoprox   │
│          │  Authorization: Bearer eyJ...│              │
│          │◀────────── 200 OK ───────────│              │
└──────────┘                              └──────────────┘
                                                 │
                                                 ▼
                                          ┌──────────────┐
                                          │  Verify      │
                                          │  Signature   │
                                          └──────────────┘
                                                 │
                                                 ▼
                                          ┌──────────────┐
                                          │  Check Exp   │
                                          │  & Claims    │
                                          └──────────────┘
```

1. Client sends request with `Authorization: Bearer <jwt_token>`
2. Server verifies JWT signature using `JWT_SECRET_KEY`
3. Server validates token expiration and claims
4. Server looks up user from `sub` claim
5. Server checks if user is active
6. Request proceeds with user's role from token

### Token Introspection (RFC 7662)

External services can validate tokens:

```bash
curl -X POST https://api.example.com/api/v1/auth/introspect \
  -H "Content-Type: application/json" \
  -H "X-Introspect-Secret: <optional_secret>" \
  -d '{"token": "mcp_abc123_xyz789"}'
```

Response for valid token:
```json
{
  "active": true,
  "sub": "1",
  "username": "admin",
  "role": "admin",
  "token_type": "api_key"
}
```

Response for invalid token:
```json
{
  "active": false
}
```

## API Usage

### Base URL

```
https://your-domain.com/api/v1
```

### Response Format

All API responses use a wrapped format:

```json
{
  "data": { ... },
  "meta": {
    "page": 1,
    "per_page": 20,
    "total": 100
  }
}
```

### Authentication Examples

#### Using API Key
```bash
# List your workspaces
curl -H "Authorization: Bearer mcp_abc123_xyz789" \
  https://api.example.com/api/v1/workspaces

# Create a new workspace
curl -X POST \
  -H "Authorization: Bearer mcp_abc123_xyz789" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-project", "metadata": {"description": "My project workspace"}}' \
  https://api.example.com/api/v1/workspaces

# List your API keys
curl -H "Authorization: Bearer mcp_abc123_xyz789" \
  https://api.example.com/api/v1/api-keys
```

#### Using JWT
```bash
# List users (admin only)
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  https://api.example.com/api/v1/users

# Get specific user
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  https://api.example.com/api/v1/users/1
```

### User Management Examples

```bash
# List all users (admin only)
curl -H "Authorization: Bearer $API_KEY" \
  "https://api.example.com/api/v1/users?page=1&per_page=20&role=admin"

# Update user role (admin only)
curl -X PUT \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin", "nexusgate_user_id": "uuid-here"}' \
  https://api.example.com/api/v1/users/2

# Deactivate user (admin only)
curl -X DELETE \
  -H "Authorization: Bearer $API_KEY" \
  https://api.example.com/api/v1/users/2
```

### Workspace Management Examples

```bash
# List workspaces
curl -H "Authorization: Bearer $API_KEY" \
  "https://api.example.com/api/v1/workspaces?page=1&status=active"

# Create workspace
curl -X POST \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "development",
    "metadata": {
      "description": "Development environment",
      "project": "my-app"
    }
  }' \
  https://api.example.com/api/v1/workspaces

# Get workspace details
curl -H "Authorization: Bearer $API_KEY" \
  https://api.example.com/api/v1/workspaces/1

# Delete workspace (soft delete)
curl -X DELETE \
  -H "Authorization: Bearer $API_KEY" \
  https://api.example.com/api/v1/workspaces/1
```

### API Key Management Examples

```bash
# Create new API key
curl -X POST \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "CI/CD Pipeline"}' \
  https://api.example.com/api/v1/api-keys

# Response:
# {
#   "data": {
#     "api_key": "mcp_def456_abc789...",
#     "name": "CI/CD Pipeline",
#     "warning": "This key will only be shown once. Store it securely."
#   }
# }

# List API keys
curl -H "Authorization: Bearer $API_KEY" \
  https://api.example.com/api/v1/api-keys

# Revoke API key
curl -X DELETE \
  -H "Authorization: Bearer $API_KEY" \
  https://api.example.com/api/v1/api-keys/2
```

### Health Check

```bash
# Check API health (no authentication required)
curl https://api.example.com/api/v1/health
```

Response:
```json
{
  "data": {
    "status": "healthy",
    "timestamp": "2026-02-10T12:00:00Z",
    "components": {
      "database": {"status": "healthy"},
      "docker": {"status": "healthy"}
    },
    "workspaces": {
      "total": 10,
      "active": 8
    }
  }
}
```

### MCP Bridge Examples

```bash
# List available MCP tools
curl -H "Authorization: Bearer $API_KEY" \
  "https://api.example.com/api/v1/mcp/tools?workspace_id=1"

# Invoke MCP tool
curl -X POST \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "workspace_id": 1,
    "tool": "git_status",
    "parameters": {}
  }' \
  https://api.example.com/api/v1/mcp/invoke
```

### Complete API Documentation

See [API.md](API.md) for complete endpoint documentation including:
- All request/response schemas
- Error codes and messages
- Query parameters
- Authentication requirements

## Security

### Bootstrap Admin Credentials

**⚠️ CRITICAL:** These credentials MUST be set before first start. The application will **fail to start** if they are not configured.

```bash
# Required - application will fail to start if not set
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=change-me-please-use-strong-password
SECRET_KEY=$(openssl rand -base64 32)
PUBLIC_BASE_URL=https://mcp.example.com
```

The admin account is created on first startup if no admin exists.

### Security Best Practices

- **SECRET_KEY**: Generate a secure random value: `openssl rand -base64 32`
- **JWT_SECRET_KEY**: Generate a separate secure key: `openssl rand -base64 64`
- **BOOTSTRAP_ADMIN_PASSWORD**: Use a strong password (min 16 characters recommended)
- **INTROSPECT_SECRET**: Optional but recommended for production: `openssl rand -base64 32`
- Never use default credentials in production
- Rotate JWT_SECRET_KEY periodically
- Monitor audit logs for suspicious activity

### Docker Socket Security

The workspace-manager requires access to the Docker socket for provisioning containers. This is a **significant security risk** as it grants the container full Docker control.

#### Mitigation Strategies:

1. **Docker Socket Proxy**: Use [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) to limit API access
2. **Rootless Docker**: Run Docker in rootless mode to reduce privilege escalation risks
3. **Network Segmentation**: Isolate the MCP infrastructure on a separate Docker network
4. **Read-Only Socket**: Mount the socket as read-only where possible (note: provisioning requires write access)

### API Security

- All API endpoints (except health) require authentication
- API keys are shown only once at creation
- Only prefix and hash stored in database
- Argon2 hashing for key verification
- Keys are invalidated when user is deactivated
- Rate limiting prevents brute force attacks
- All inputs are validated and sanitized

## Nginx Proxy Manager (TLS termination) -> Traefik

1. In Nginx Proxy Manager, create a **Proxy Host** for `mcp.example.com`.
2. Forward to:
   - **Forward Hostname / IP:** `<docker-host-ip>`
   - **Forward Port:** `8080`
3. Enable SSL in NPM.
4. Set `PUBLIC_BASE_URL=https://mcp.example.com` for the manager so UI uses the correct endpoint URLs.

## Workspace MCP Endpoints

Each workspace exposes:
```
https://PUBLIC_BASE_URL/ws/<workspaceName>/mcp
```

Click a workspace row in the UI to expand details and **copy a full `mcp.json` snippet** to clipboard. The snippet includes:
- `servers.<name>.type = "http"`
- `servers.<name>.url = "<endpoint>"`
- `servers.<name>.headers.Authorization = "Bearer ${input:mcp_token}"`
- `inputs` entry for `mcp_token`

Paste this snippet into VS Code `mcp.json`.

## Internal Auth Introspection

Workspace containers validate bearer tokens by calling:
```
POST http://workspace-manager:8000/internal/auth/introspect
{"token":"<api_key>"}
```

Response: `{"active": bool, "user_id": str, "role": str}`

## User Deactivation

Admins can deactivate users (instead of deleting). Deactivation:
- prevents login
- stops user workspace containers
- marks workspaces inactive (hidden from UI)

## Testing

```bash
cd workspace-manager
pytest
```

Run with coverage:
```bash
pytest --cov=app --cov-report=term-missing
```

## Repository Structure

```
.
├── docker-compose.yml          # Production orchestration
├── README.md                   # This file
├── API.md                      # Complete API documentation
├── CONTRIBUTING.md             # Development guidelines
├── .cursorrules               # Cursor IDE rules
├── workspace-manager/         # Main FastAPI application
│   ├── app/
│   │   ├── main.py           # HTTP routes and handlers
│   │   ├── models.py         # SQLAlchemy database models
│   │   ├── auth.py           # Authentication (JWT, API keys)
│   │   ├── db.py             # Database configuration
│   │   ├── services.py       # Business logic layer
│   │   ├── provisioning.py   # Docker container management
│   │   ├── settings.py       # Configuration management
│   │   ├── static/           # CSS, images
│   │   └── templates/        # Jinja2 HTML templates
│   ├── tests/                # pytest test suite
│   ├── Dockerfile
│   └── requirements.txt
├── workspace-mcp/            # MCP server implementation
│   ├── app.py               # FastMCP tools and server
│   ├── Dockerfile
│   └── requirements.txt
└── client/                   # Example client implementations
    ├── mcp_client.py        # Streamable HTTP MCP client
    └── temporal_activities.py # Temporal workflow activities
```

## Example Client

See `client/mcp_client.py` and `client/temporal_activities.py` for a minimal Streamable HTTP client and Temporal activity wrappers.

---

**Note**: For detailed API endpoint documentation, request/response schemas, and error codes, see [API.md](API.md).
