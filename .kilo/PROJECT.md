# Workspace MCP Hub - Project Architecture

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                    CLIENT LAYER                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐                      │
│  │   Web Browser   │  │   VS Code MCP   │  │  Custom Client  │                      │
│  │   (Admin UI)    │  │   Extension     │  │  (Temporal/etc) │                      │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘                      │
└───────────┼────────────────────┼────────────────────┼────────────────────────────────┘
            │                    │                    │
            │ HTTP/Sessions      │ HTTP/Bearer        │ HTTP/Bearer
            │                    │                    │
┌───────────┼────────────────────┼────────────────────┼────────────────────────────────┐
│           │         REVERSE PROXY (Traefik)                                       │
│           │    ┌─────────────────────────────────────────────────────────┐         │
│           │    │  Path Routing:                                          │         │
│           │    │    /app/*      → workspace-manager:8000                │         │
│           │    │    /ws/<name>/* → ws_<name>:7000 (dynamic)             │         │
│           │    │                                                         │         │
│           │    │  Labels drive service discovery from Docker containers  │         │
│           │    └─────────────────────────────────────────────────────────┘         │
└───────────┼────────────────────┼────────────────────┼────────────────────────────────┘
            │                    │                    │
            ▼                    │                    │
┌─────────────────────────┐     │                    │
│   WORKSPACE MANAGER     │     │                    │
│   (FastAPI Application) │     │                    │
│                         │     │                    │
│  ┌───────────────────┐  │     │                    │
│  │   HTTP Routes     │  │     │                    │
│  │  - /login (form)  │  │     │                    │
│  │  - /workspaces    │  │     │                    │
│  │  - /keys          │  │     │                    │
│  │  - /admin/users   │  │     │                    │
│  └───────────────────┘  │     │                    │
│                         │     │                    │
│  ┌───────────────────┐  │     │                    │
│  │   Services Layer  │  │     │                    │
│  │  - create_workspace│  │     │                    │
│  │  - soft_delete_ws │  │     │                    │
│  │  - purge_workspaces│ │     │                    │
│  │  - deactivate_user│  │     │                    │
│  └───────────────────┘  │     │                    │
│                         │     │                    │
│  ┌───────────────────┐  │     │                    │
│  │   Provisioning    │  │     │                    │
│  │  - Docker SDK     │  │     │                    │
│  │  - Container mgmt │  │     │                    │
│  │  - Volume mgmt    │  │     │                    │
│  └───────────────────┘  │     │                    │
│                         │     │                    │
│  ┌───────────────────┐  │     │                    │
│  │   Auth Layer      │  │     │                    │
│  │  - Session auth   │  │     │                    │
│  │  - API key gen    │  │     │                    │
│  │  - Introspection  │◄─┼─────┼────────────────────┘
│  └───────────────────┘  │     │
│                         │     │
│  ┌───────────────────┐  │     │
│  │   Database        │  │     │
│  │  - SQLite (default)│ │     │
│  │  - SQLAlchemy 2.0 │  │     │
│  │  - Users, Keys,   │  │     │
│  │    Workspaces     │  │     │
│  └───────────────────┘  │     │
└─────────────────────────┘     │
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              WORKSPACE CONTAINERS                                    │
│                                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐                      │
│  │   ws_alpha      │  │   ws_beta       │  │   ws_gamma      │  ...                 │
│  │                 │  │                 │  │                 │                      │
│  │ ┌─────────────┐ │  │ ┌─────────────┐ │  │ ┌─────────────┐ │                      │
│  │ │  MCP Server │ │  │ │  MCP Server │ │  │ │  MCP Server │ │                      │
│  │ │  Port 7000  │ │  │ │  Port 7000  │ │  │ │  Port 7000  │ │                      │
│  │ └─────────────┘ │  │ └─────────────┘ │  │ └─────────────┘ │                      │
│  │       │         │  │       │         │  │       │         │                      │
│  │ ┌─────┴─────┐   │  │ ┌─────┴─────┐   │  │ ┌─────┴─────┐   │                      │
│  │ │  Tools:   │   │  │ │  Tools:   │   │  │ │  Tools:   │   │                      │
│  │ │  - fs_*   │   │  │ │  - fs_*   │   │  │ │  - fs_*   │   │                      │
│  │ │  - git    │   │  │ │  - git    │   │  │ │  - git    │   │                      │
│  │ │  - gitlab_*│  │  │ │  - gitlab_*│  │  │ │  - gitlab_*│  │                      │
│  │ └───────────┘   │  │ └───────────┘   │  │ └───────────┘   │                      │
│  │       │         │  │       │         │  │       │         │                      │
│  │ ┌─────┴─────┐   │  │ ┌─────┴─────┐   │  │ ┌─────┴─────┐   │                      │
│  │ │  Volume   │   │  │ │  Volume   │   │  │ │  Volume   │   │                      │
│  │ │ /workspace│   │  │ │ /workspace│   │  │ │ /workspace│   │                      │
│  │ └───────────┘   │  │ └───────────┘   │  │ └───────────┘   │                      │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘                      │
│                                                                                      │
│  Each container:                                                                     │
│  - Isolated Docker volume for persistence                                           │
│  - Independent MCP server (FastMCP)                                                 │
│  - Validates tokens via manager introspection                                        │
│  - Has unique Traefik routing labels                                                 │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## Component Descriptions

### 1. Traefik Reverse Proxy

**Purpose**: Routes incoming requests to appropriate services

**Configuration**:
- Listens on port 8080
- Docker provider for dynamic configuration
- Path-based routing rules
- Automatic service discovery from container labels

**Routes**:
- `/app/*` → workspace-manager (UI and admin API)
- `/ws/<name>/*` → Individual workspace containers (dynamic)

### 2. Workspace Manager

**Purpose**: Core application managing users, workspaces, and authentication

**Key Components**:

#### HTTP Layer (`main.py`)
- Session-based authentication for UI
- Form handling with HTMX
- Rate limiting on login
- Admin vs user role enforcement

#### Service Layer (`services.py`)
- Business logic orchestration
- Transaction management
- Validation rules
- Soft-delete and purge logic

#### Provisioning Layer (`provisioning.py`)
- Docker container lifecycle
- Volume management
- Traefik label generation
- Network attachment

#### Auth Layer (`auth.py`)
- Argon2 password hashing
- API key generation (format: `mcp_<prefix>_<random>`)
- Token verification
- Prefix extraction for lookups

#### Models (`models.py`)

**User**:
```python
- id: int (PK)
- username: str (unique, indexed)
- password_hash: str (Argon2)
- role: enum('admin', 'user')
- status: enum('active', 'inactive')
- created_at: datetime
- relationships: api_keys[], workspaces[]
```

**ApiKey**:
```python
- id: int (PK)
- user_id: int (FK → users)
- key_prefix: str (indexed, for lookup)
- key_hash: str (Argon2 hash of full token)
- created_at: datetime
- relationship: user
```

**Workspace**:
```python
- id: int (PK)
- user_id: int (FK → users)
- name: str (unique, indexed, validated: ^[a-zA-Z0-9._-]{1,128}$)
- status: enum('active', 'inactive', 'deleted')
- created_at: datetime
- deleted_at: datetime | None
- purge_after: datetime | None
- relationship: user
```

### 3. Workspace MCP Containers

**Purpose**: Isolated execution environment per workspace

**Container Configuration**:
- Image: `mcp-gitfs:latest` (from `workspace-mcp/`)
- Name: `ws_<workspace_name>`
- Port: 7000
- Volume: `ws_<workspace_name>` mounted at `/workspace`
- Network: `mcpnet`

**Environment Variables**:
- `WORKSPACE_NAME` - Workspace identifier
- `WORKSPACE_OWNER_USER_ID` - Owner's user ID
- `MANAGER_INTROSPECT_URL` - Auth validation endpoint
- `MCP_BIND_HOST` - Interface to bind (0.0.0.0)
- `MCP_PORT` - Server port (7000)

**Traefik Labels** (auto-generated):
```yaml
traefik.enable: "true"
traefik.http.routers.ws_<name>.rule: "PathPrefix(`/ws/<name>`)"
traefik.http.routers.ws_<name>.entrypoints: "web"
traefik.http.routers.ws_<name>.middlewares: "ws_<name>-stripprefix"
traefik.http.middlewares.ws_<name>-stripprefix.stripprefix.prefixes: "/ws/<name>"
traefik.http.services.ws_<name>.loadbalancer.server.port: "7000"
```

**MCP Tools**:

| Tool | Purpose | Auth Required |
|------|---------|---------------|
| `fs_list` | List directory contents | Yes |
| `fs_read_text` | Read file contents | Yes |
| `fs_write_text` | Write file atomically | Yes |
| `fs_delete` | Delete files/directories | Yes |
| `git` | Execute git commands | Yes |
| `ssh_public_key` | Get workspace SSH key | Yes |
| `gitlab_request` | Proxy GitLab API calls | Yes |
| `gitlab_openapi_spec` | Fetch OpenAPI spec | Yes |
| `gitlab_openapi_paths` | List API endpoints | Yes |
| `gitlab_openapi_operation` | Get operation details | Yes |
| `gitlab_tool_help` | Tool documentation | Yes |

## Data Flow

### User Login Flow

```
1. Browser → POST /login (username, password)
2. Manager → Verify credentials (Argon2)
3. Manager → Check user.status == 'active'
4. Manager → Create session (signed cookie)
5. Browser → Redirect to /workspaces
```

### Workspace Creation Flow

```
1. Browser → POST /workspaces (name)
2. Manager → Validate name (regex, uniqueness)
3. Manager → BEGIN TRANSACTION
4. Manager → INSERT workspace (status='active')
5. Manager → COMMIT
6. Manager → Docker: create volume
7. Manager → Docker: run container with labels
8. Traefik → Auto-discovers new route
9. Browser → Redirect to /workspaces
```

### MCP Request Flow

```
1. Client → GET /ws/<name>/mcp (Authorization: Bearer <token>)
2. Traefik → Route to ws_<name> container
3. MCP Server → Extract token
4. MCP Server → POST /internal/auth/introspect {token}
5. Manager → Lookup by prefix, verify hash
6. Manager → Return {active, user_id, role}
7. MCP Server → Cache result (60s)
8. MCP Server → Execute tool
9. MCP Server → Return result
```

### Soft Delete Flow

```
1. Browser → POST /workspaces/<id>/delete
2. Manager → UPDATE workspace (status='deleted', deleted_at=now, purge_after=now+24h)
3. Manager → Docker: stop container
4. Purge Loop (every 5 min) → SELECT workspaces WHERE purge_after <= now
5. Purge Loop → Docker: delete container
6. Purge Loop → Docker: delete volume
7. Purge Loop → DELETE workspace record
```

### User Deactivation Flow

```
1. Admin → POST /admin/users/<id>/deactivate
2. Manager → Verify not last admin
3. Manager → UPDATE user (status='inactive')
4. Manager → For each workspace:
   - UPDATE workspace (status='inactive')
   - Docker: stop container
5. All tokens now fail introspection
```

## Key Design Decisions

### 1. Container-per-Workspace

**Decision**: Each workspace runs in its own Docker container

**Rationale**:
- Strong isolation between users
- Resource limits can be applied per workspace
- Independent scaling and restart
- Clear failure boundaries

**Trade-offs**:
- Higher resource overhead than shared process
- More complex orchestration
- Slower startup time

### 2. Soft Delete with Purge

**Decision**: Workspaces are soft-deleted, then purged later

**Rationale**:
- Allows recovery from accidental deletion
- Audit trail preservation
- Graceful cleanup (can be deferred)

**Implementation**:
- `deleted_at` timestamp
- `purge_after` scheduled cleanup time
- Background purge loop

### 3. Session + Bearer Dual Auth

**Decision**: Different auth for UI vs API

**Rationale**:
- Sessions are natural for browser-based UI
- Bearer tokens work better for MCP protocol
- Clear separation of concerns

**Implementation**:
- UI: Starlette SessionMiddleware with signed cookies
- API: Bearer tokens with introspection endpoint

### 4. API Key Prefix Pattern

**Decision**: Store only prefix + hash, show full token once

**Rationale**:
- Keys cannot be recovered if lost
- Database breach doesn't expose usable keys
- Prefix allows efficient lookup

**Format**: `mcp_<8-char-prefix>_<32-char-random>`

### 5. Path Traversal Protection

**Decision**: All filesystem paths resolved and validated

**Implementation**:
```python
def _resolve_path(path: str) -> pathlib.Path:
    target = (WORKSPACE_ROOT / path).resolve()
    if not str(target).startswith(str(WORKSPACE_ROOT)):
        raise ValueError("Path escapes workspace")
    return target
```

### 6. Introspection-based Auth

**Decision**: Workspace containers validate tokens via manager

**Rationale**:
- Single source of truth for auth state
- Immediate revocation (deactivation)
- No shared secrets between containers

**Caching**: 60-second cache to reduce load

### 7. SQLite Default Database

**Decision**: SQLite as default, SQLAlchemy for portability

**Rationale**:
- Zero configuration for development
- Single file, easy backup
- Can migrate to PostgreSQL via SQLAlchemy

**Production**: Should use PostgreSQL with proper backups

## Security Model

### Authentication Layers

1. **Transport**: HTTP (TLS termination at reverse proxy)
2. **Session**: Signed cookies (itsdangerous)
3. **API**: Bearer tokens (introspection)
4. **Container**: Token validation via manager

### Authorization Matrix

| Action | Admin | User (Owner) | Other |
|--------|-------|--------------|-------|
| View all workspaces | ✓ | ✗ | ✗ |
| View own workspaces | ✓ | ✓ | ✗ |
| Create workspace | ✓ | ✓ | ✗ |
| Delete workspace | ✓ | ✓ (own) | ✗ |
| Manage API keys | ✓ | ✓ (own) | ✗ |
| Create users | ✓ | ✗ | ✗ |
| Deactivate users | ✓ | ✗ | ✗ |
| Access MCP tools | ✓ | ✓ (own ws) | ✗ |

### Data Protection

- Passwords: Argon2 hashing
- API keys: Argon2 hashing, only prefix stored
- Sessions: Signed cookies with SECRET_KEY
- Volumes: Isolated per workspace
- Files: Path traversal protection

### Network Security

- Internal endpoints (`/internal/*`) not exposed via Traefik
- Workspace containers on isolated network
- No direct container-to-container communication
- All MCP auth goes through manager introspection

## Scalability Considerations

### Current Limitations

- Single SQLite database
- Single manager instance
- Docker on single host
- In-memory rate limiting

### Future Scaling Options

1. **Database**: Migrate to PostgreSQL with connection pooling
2. **Manager**: Run multiple instances behind load balancer
3. **Workspaces**: Docker Swarm or Kubernetes for multi-host
4. **Rate Limiting**: Redis-based distributed rate limiting
5. **Introspection**: Cache with Redis, shorter TTL

## Monitoring and Observability

### Logs

- Manager: Structured logging via Python logging
- Workspaces: Docker container logs
- Traefik: Access logs

### Key Metrics

- Active workspaces per user
- API key usage (via introspection logs)
- Container lifecycle events
- Purge job statistics

### Health Checks

- Manager: `/app/` (requires session)
- Workspaces: Implicit via Traefik health checks
- Database: Connection validation on startup
