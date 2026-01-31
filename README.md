# Workspace MCP Hub

Production-shaped MVP for managing user workspaces and dedicated MCP servers with per-user API keys.

## Features
- FastAPI + Jinja2 + HTMX admin/user UI
- Sessions with username/password auth
- RBAC (admin vs user)
- API keys (bearer tokens shown once; stored hashed)
- Workspace provisioning (one container per workspace, volume-backed)
- Traefik routing with `/app/*` and `/ws/<name>/*`
- MCP server per workspace exposing git + filesystem tools
- Soft-delete + purge job
- User deactivation (stops workspaces + hides them from UI)

## Quick start
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

## Bootstrap admin credentials
Set these environment variables before first start:
```bash
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=change-me
SECRET_KEY=change-me-please
PUBLIC_BASE_URL=https://mcp.example.com
```
The admin account is created on first startup if no admin exists.

## Nginx Proxy Manager (TLS termination) -> Traefik
1. In Nginx Proxy Manager, create a **Proxy Host** for `mcp.example.com`.
2. Forward to:
   - **Forward Hostname / IP:** `<docker-host-ip>`
   - **Forward Port:** `8080`
3. Enable SSL in NPM.
4. Set `PUBLIC_BASE_URL=https://mcp.example.com` for the manager so UI uses the correct endpoint URLs.

## Workspace MCP endpoints
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

## Internal auth introspection
Workspace containers validate bearer tokens by calling:
```
POST http://workspace-manager:8000/internal/auth/introspect
{"token":"<api_key>"}
```

## User deactivation
Admins can deactivate users (instead of deleting). Deactivation:
- prevents login
- stops user workspace containers
- marks workspaces inactive (hidden from UI)

## Running tests
```bash
cd workspace-manager
pytest
```

## Repo structure
```
.
├── docker-compose.yml
├── workspace-manager/
├── workspace-mcp/
└── client/
```

## Example client
See `client/mcp_client.py` and `client/temporal_activities.py` for a minimal Streamable HTTP client and Temporal activity wrappers.
