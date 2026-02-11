# Octoprox API Documentation

## Base URL

```
https://your-domain.com/api/v1
```

## Authentication

All API endpoints (except health) require authentication via one of three methods:

### 1. Session Cookie Authentication

Used by the web UI for browser-based requests.

- Login via `POST /auth/login` to establish a session
- Session cookie is set with `HttpOnly`, `Secure`, and `SameSite` attributes
- Session expires after 7 days of inactivity

**Example:**
```bash
curl -c cookies.txt \
  -X POST https://api.example.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secret"}'

# Use session cookie for subsequent requests
curl -b cookies.txt \
  https://api.example.com/api/v1/users/me
```

### 2. API Key Authentication

Use API keys for programmatic access. API keys have the `mcp_` prefix.

**Header format:**
```
Authorization: Bearer mcp_xxxxxxxxxxxxxxxx
```

**Getting an API Key:**

API keys are generated via the web UI at `/app/keys` or via the API:
```bash
POST /api/v1/api-keys
{
  "name": "My Application Key"
}
```

**Response:**
```json
{
  "data": {
    "id": 1,
    "name": "My Application Key",
    "key": "mcp_abc123_xyz789_this_is_the_full_key",
    "created_at": "2026-02-10T12:00:00Z"
  }
}
```

**Important**: The full API key is shown only once on creation. Store it securely.

**Example usage:**
```bash
curl https://api.example.com/api/v1/workspaces \
  -H "Authorization: Bearer mcp_abc123_xyz789"
```

### 3. JWT Bearer Authentication

JWT tokens are used for stateless authentication, typically for short-lived access.

**Token format:**
- Access tokens expire after 15 minutes
- Include claims: `sub` (user_id), `username`, `role`, `jti`
- Signed with the server's JWT secret

**Header format:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

**Example usage:**
```bash
curl https://api.example.com/api/v1/workspaces \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

### Authentication Priority

When multiple credentials are provided, the following priority is used:
1. Session cookie (highest priority for browser requests)
2. API key Bearer token
3. JWT Bearer token

### Token Introspection

API keys and JWT tokens can be introspected at:
```
POST /auth/introspect
{
  "token": "mcp_abc123_xyz789"
}
```

**Response:**
```json
{
  "active": true,
  "user_id": 1,
  "username": "admin",
  "role": "admin",
  "token_type": "api_key"
}
```

See the [Auth Introspection](#auth-introspection) section for details.

## Common Response Format

All responses use the wrapped format:
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

## Users

### List Users

```
GET /users?page=1&per_page=20&status=active&role=admin
```

**Access**: Admin sees all users, regular users see only self.

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| page | integer | Page number (default: 1) |
| per_page | integer | Items per page (default: 20, max: 100) |
| status | string | Filter by status: `active` or `inactive` |
| role | string | Filter by role: `admin` or `user` |

**Response**:
```json
{
  "data": {
    "users": [
      {
        "id": 1,
        "username": "admin",
        "role": "admin",
        "is_active": true,
        "created_at": "2026-02-10T12:00:00Z",
        "updated_at": "2026-02-10T12:00:00Z",
        "nexusgate_user_id": null,
        "nexusgate_role": null,
        "last_synced_at": null
      }
    ]
  },
  "meta": {
    "page": 1,
    "per_page": 20,
    "total": 1
  }
}
```

### Get User

```
GET /users/{user_id}
```

**Access**: Admin or self only.

**Response**:
```json
{
  "data": {
    "id": 1,
    "username": "admin",
    "role": "admin",
    "is_active": true,
    "created_at": "2026-02-10T12:00:00Z",
    "updated_at": "2026-02-10T12:00:00Z",
    "workspaces": [...],
    "api_keys": [...]
  }
}
```

### Update User

```
PUT /users/{user_id}
{
  "role": "admin",
  "is_active": true,
  "nexusgate_user_id": "uuid-here"
}
```

**Access**: Admin only.

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| role | string | No | New role: `admin` or `user` |
| is_active | boolean | No | Activate/deactivate user |
| nexusgate_user_id | string | No | Link to NEXUSGATE user ID |

**Notes**:
- Cannot demote yourself from admin
- Cannot deactivate the last admin

**Response**:
```json
{
  "data": {
    "id": 1,
    "username": "admin",
    "role": "admin",
    "is_active": true,
    "updated_at": "2026-02-10T12:00:00Z"
  }
}
```

### Deactivate User

```
DELETE /users/{user_id}
```

**Access**: Admin only.

**Notes**:
- Cannot deactivate yourself
- Cannot deactivate the last admin
- Deactivating a user stops all their workspaces

**Response**: `204 No Content`

## Workspaces

### List Workspaces

```
GET /workspaces?page=1&per_page=20&status=active&user_id=1
```

**Access**: Admin sees all, user sees own.

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| page | integer | Page number (default: 1) |
| per_page | integer | Items per page (default: 20, max: 100) |
| status | string | Filter by status: `active`, `inactive`, or `deleted` |
| user_id | integer | Filter by owner (admin only) |

**Response**:
```json
{
  "data": {
    "workspaces": [
      {
        "id": 1,
        "name": "my-workspace",
        "user_id": 1,
        "status": "active",
        "endpoint_url": "https://domain.com/ws/my-workspace/mcp",
        "created_at": "2026-02-10T12:00:00Z",
        "updated_at": "2026-02-10T12:00:00Z",
        "metadata": {},
        "nexusgate_service_id": null,
        "container_id": "abc123",
        "container_status": "running"
      }
    ]
  },
  "meta": { ... }
}
```

### Create Workspace

```
POST /workspaces
{
  "name": "my-workspace",
  "metadata": {
    "description": "My workspace"
  }
}
```

**Access**: Any authenticated user.

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Workspace name (alphanumeric, hyphens, dots, underscores) |
| metadata | object | No | Additional workspace metadata |

**Validation**:
- Name required
- Alphanumeric, hyphens, dots, underscores only
- Max 128 characters
- Must be unique per user

**Response**: `201 Created`
```json
{
  "data": {
    "id": 1,
    "name": "my-workspace",
    "user_id": 1,
    "status": "active",
    "endpoint_url": "https://domain.com/ws/my-workspace/mcp",
    "created_at": "2026-02-10T12:00:00Z",
    "container_id": "abc123",
    "container_status": "starting"
  }
}
```

### Get Workspace

```
GET /workspaces/{workspace_id}
```

**Access**: Admin or owner only.

**Response**:
```json
{
  "data": {
    "id": 1,
    "name": "my-workspace",
    "user_id": 1,
    "status": "active",
    "endpoint_url": "https://domain.com/ws/my-workspace/mcp",
    "created_at": "2026-02-10T12:00:00Z",
    "updated_at": "2026-02-10T12:00:00Z",
    "metadata": {},
    "container_id": "abc123",
    "container_status": "running",
    "tools": [...]
  }
}
```

### Delete Workspace

```
DELETE /workspaces/{workspace_id}
```

**Access**: Admin or owner only.

**Note**: Soft delete - workspace is marked as deleted and container stopped.

**Response**: `204 No Content`

## API Keys

### List API Keys

```
GET /api-keys?page=1&per_page=20&user_id=1
```

**Access**: Admin sees all, user sees own.

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| page | integer | Page number (default: 1) |
| per_page | integer | Items per page (default: 20, max: 100) |
| user_id | integer | Filter by owner (admin only) |

**Response**:
```json
{
  "data": {
    "api_keys": [
      {
        "id": 1,
        "name": "My Key",
        "prefix": "mcp_abc123",
        "user_id": 1,
        "created_at": "2026-02-10T12:00:00Z",
        "last_used_at": "2026-02-10T13:00:00Z",
        "nexusgate_token_id": null,
        "expires_at": null
      }
    ]
  },
  "meta": { ... }
}
```

**Note**: Full key_hash is never returned, only prefix.

### Create API Key

```
POST /api-keys
{
  "name": "My Application",
  "user_id": 1
}
```

**Access**: Any authenticated user. Admin can specify user_id.

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Descriptive name for the key |
| user_id | integer | No | Owner user ID (admin only) |

**Response**:
```json
{
  "data": {
    "id": 1,
    "api_key": "mcp_abc123_xyz789",
    "name": "My Application",
    "prefix": "mcp_abc123",
    "warning": "This key will only be shown once. Store it securely."
  }
}
```

### Revoke API Key

```
DELETE /api-keys/{key_id}
```

**Access**: Admin or owner only.

**Response**: `204 No Content`

## Authentication

### Token Introspection

```
POST /auth/introspect
{
  "token": "mcp_abc123_xyz789"
}
```

**Access**: No authentication required (optional secret header).

**Headers**:
- `X-Introspect-Secret`: Optional secret if INTROSPECT_SECRET is configured

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| token | string | Yes | Token to introspect |

**Response** (RFC 7662 compliant):
```json
{
  "active": true,
  "sub": "1",
  "username": "admin",
  "role": "admin",
  "token_type": "api_key"
}
```

Or for invalid tokens:
```json
{
  "active": false
}
```

## Health

### Health Check

```
GET /health
```

**Access**: No authentication required.

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2026-02-10T12:00:00Z",
  "components": {
    "database": {
      "status": "healthy",
      "response_time_ms": 5
    },
    "docker": {
      "status": "healthy",
      "version": "24.0.7"
    }
  },
  "workspaces": {
    "total": 10,
    "active": 8
  }
}
```

**Status codes**:
- 200: Healthy or degraded
- 503: Unhealthy

## MCP Bridge

The MCP Bridge provides REST API access to MCP (Model Context Protocol) tools running within workspace containers. This allows external systems to invoke tools without direct MCP protocol support.

### List MCP Tools

List all available MCP tools for a specific workspace.

```
GET /api/v1/mcp/tools?workspace_id=1
```

**Access**: Any authenticated user.

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| workspace_id | integer | Yes | Workspace ID to query |

**Response**:
```json
{
  "data": {
    "tools": [
      {
        "name": "fs_list",
        "description": "List files and directories at the given path"
      },
      {
        "name": "fs_read_text",
        "description": "Read text content from a file"
      },
      {
        "name": "fs_write_text",
        "description": "Write text content to a file"
      },
      {
        "name": "fs_delete",
        "description": "Delete a file or directory"
      },
      {
        "name": "git",
        "description": "Execute git commands within the workspace"
      },
      {
        "name": "gitlab_request",
        "description": "Proxy any GitLab REST API request"
      },
      {
        "name": "gitlab_openapi_paths",
        "description": "List GitLab OpenAPI paths and methods"
      },
      {
        "name": "gitlab_openapi_operation",
        "description": "Get schema details for a GitLab API operation"
      },
      {
        "name": "gitlab_openapi_spec",
        "description": "Return the GitLab OpenAPI YAML specification"
      },
      {
        "name": "gitlab_tool_help",
        "description": "Return machine-readable help for GitLab MCP tools"
      },
      {
        "name": "ssh_public_key",
        "description": "Get the SSH public key for this workspace"
      },
      {
        "name": "openapi_load",
        "description": "Load an OpenAPI specification"
      },
      {
        "name": "openapi_list_apis",
        "description": "List all loaded OpenAPI APIs"
      },
      {
        "name": "openapi_list_endpoints",
        "description": "List endpoints from a loaded API"
      },
      {
        "name": "openapi_get_operation",
        "description": "Get detailed information about an API operation"
      },
      {
        "name": "openapi_call",
        "description": "Call an API operation"
      }
    ],
    "count": 16
  }
}
```

**Error Responses**:

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `{"detail": "workspace_id is required"}` | Missing workspace_id parameter |
| 403 | `{"detail": "Not authorized to access this workspace"}` | User not authorized |
| 404 | `{"detail": "Workspace not found"}` | Workspace does not exist |
| 503 | `{"detail": "MCP server unavailable"}` | Workspace MCP server not responding |

### Invoke MCP Tool

Execute an MCP tool in a specific workspace.

```
POST /api/v1/mcp/invoke
```

**Access**: Admin or workspace owner only.

**Request Body**:
```json
{
  "workspace_id": 1,
  "tool": "fs_read_text",
  "parameters": {
    "path": "README.md"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| workspace_id | integer | Yes | Target workspace ID |
| tool | string | Yes | Tool name to invoke |
| parameters | object | No | Tool-specific parameters |

**Response**:
```json
{
  "data": {
    "tool": "fs_read_text",
    "workspace_id": 1,
    "result": "# My Project\n\nThis is the README content..."
  }
}
```

**Example - Git Status:**
```bash
curl -X POST https://api.example.com/api/v1/mcp/invoke \
  -H "Authorization: Bearer mcp_abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "workspace_id": 1,
    "tool": "git",
    "parameters": {
      "args": ["status", "--short"]
    }
  }'
```

**Example - OpenAPI Call:**
```bash
curl -X POST https://api.example.com/api/v1/mcp/invoke \
  -H "Authorization: Bearer mcp_abc123" \
  -H "Content-Type: application/json" \
  -d '{
    "workspace_id": 1,
    "tool": "openapi_load",
    "parameters": {
      "name": "petstore",
      "spec_url": "https://petstore.swagger.io/v2/swagger.json"
    }
  }'
```

**Error Responses**:

| Status | Error | Description |
|--------|-------|-------------|
| 400 | `{"detail": "Invalid request body"}` | Malformed JSON |
| 400 | `{"detail": "workspace_id is required"}` | Missing workspace_id |
| 400 | `{"detail": "tool is required"}` | Missing tool name |
| 403 | `{"detail": "Not authorized to invoke tools in this workspace"}` | Not owner/admin |
| 404 | `{"detail": "Workspace not found"}` | Workspace does not exist |
| 404 | `{"detail": "Tool not found"}` | Tool does not exist |
| 422 | `{"detail": "Invalid parameters"}` | Tool parameter validation failed |
| 500 | `{"detail": "Tool execution failed"}` | Tool execution error |
| 503 | `{"detail": "MCP server unavailable"}` | Workspace MCP server not responding |

### MCP Bridge Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  API Client     │────▶│  MCP Bridge      │────▶│  MCP Server     │
│  (REST)         │     │  (workspace-     │     │  (workspace-    │
│                 │◀────│   manager)       │◀────│   mcp)          │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │  Auth Check      │
                        │  (owner/admin)   │
                        └──────────────────┘
```

The MCP Bridge:
1. Validates authentication (any valid user)
2. For invoke: validates authorization (owner or admin)
3. Proxies request to workspace MCP server
4. Returns tool results or error details

## Error Responses

### 400 Bad Request

```json
{
  "detail": "Invalid workspace name format"
}
```

### 401 Unauthorized

```json
{
  "detail": "Not authenticated"
}
```

### 403 Forbidden

```json
{
  "detail": "Not authorized to access this resource"
}
```

### 404 Not Found

```json
{
  "detail": "User not found"
}
```

### 429 Too Many Requests

```json
{
  "error": "Rate limit exceeded",
  "retry_after": 60
}
```

**Headers**:
- `Retry-After: 60`
- `X-RateLimit-Limit: 200`
- `X-RateLimit-Remaining: 0`

### 500 Internal Server Error

```json
{
  "detail": "Internal server error"
}
```

## Rate Limiting

API requests are rate-limited per IP address:

| Endpoint Type | Limit | Window |
|---------------|-------|--------|
| General endpoints | 200 requests | 1 minute |
| Authentication endpoints | 60 requests | 1 minute |

Rate limit headers are included in all responses:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed |
| `X-RateLimit-Remaining` | Remaining requests in current window |
| `X-RateLimit-Reset` | Unix timestamp when limit resets |

When rate limit is exceeded:
- HTTP status: `429 Too Many Requests`
- Response includes `retry_after` seconds
- `Retry-After` header indicates seconds to wait

## SDK Examples

### Python

```python
import requests

BASE_URL = "https://api.example.com/api/v1"
API_KEY = "mcp_abc123_xyz789"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# List workspaces
response = requests.get(f"{BASE_URL}/workspaces", headers=headers)
workspaces = response.json()

# Create workspace
response = requests.post(
    f"{BASE_URL}/workspaces",
    headers=headers,
    json={"name": "my-project"}
)
workspace = response.json()

# Invoke MCP tool
response = requests.post(
    f"{BASE_URL}/mcp/invoke",
    headers=headers,
    json={
        "workspace_id": workspace["data"]["id"],
        "tool": "git_status",
        "parameters": {}
    }
)
result = response.json()
```

### JavaScript/Node.js

```javascript
const BASE_URL = 'https://api.example.com/api/v1';
const API_KEY = 'mcp_abc123_xyz789';

const headers = {
  'Authorization': `Bearer ${API_KEY}`,
  'Content-Type': 'application/json'
};

// List workspaces
const workspaces = await fetch(`${BASE_URL}/workspaces`, { headers })
  .then(r => r.json());

// Create workspace
const workspace = await fetch(`${BASE_URL}/workspaces`, {
  method: 'POST',
  headers,
  body: JSON.stringify({ name: 'my-project' })
}).then(r => r.json());

// Invoke MCP tool
const result = await fetch(`${BASE_URL}/mcp/invoke`, {
  method: 'POST',
  headers,
  body: JSON.stringify({
    workspace_id: workspace.data.id,
    tool: 'git_status',
    parameters: {}
  })
}).then(r => r.json());
```

### cURL

```bash
# List workspaces
curl -H "Authorization: Bearer mcp_abc123_xyz789" \
  https://api.example.com/api/v1/workspaces

# Create workspace
curl -X POST \
  -H "Authorization: Bearer mcp_abc123_xyz789" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-project"}' \
  https://api.example.com/api/v1/workspaces

# Invoke MCP tool
curl -X POST \
  -H "Authorization: Bearer mcp_abc123_xyz789" \
  -H "Content-Type: application/json" \
  -d '{"workspace_id": 1, "tool": "git_status", "parameters": {}}' \
  https://api.example.com/api/v1/mcp/invoke
```

## Changelog

### v2.0.0 - NEXUSGATE Integration
- Added JWT-based authentication
- Added unified authentication (session, API key, JWT)
- Added RESTful API endpoints
- Added RBAC with admin/user roles
- Added rate limiting
- Added security headers
- Added audit logging
- Added MCP Bridge endpoints
