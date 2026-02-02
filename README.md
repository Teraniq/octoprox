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
**⚠️ CRITICAL:** These credentials MUST be set before first start. The application will **fail to start** if they are not configured.

```bash
# Required - application will fail to start if not set
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD=change-me-please-use-strong-password
SECRET_KEY=$(openssl rand -base64 32)
PUBLIC_BASE_URL=https://mcp.example.com
```

The admin account is created on first startup if no admin exists.

### Security
- **SECRET_KEY**: Generate a secure random value: `openssl rand -base64 32`
- **BOOTSTRAP_ADMIN_PASSWORD**: Use a strong password (min 16 characters recommended)
- Never use default credentials in production

## Docker Socket Security
The workspace-manager requires access to the Docker socket for provisioning containers. This is a **significant security risk** as it grants the container full Docker control.

### Mitigation Strategies:
1. **Docker Socket Proxy**: Use [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) to limit API access
2. **Rootless Docker**: Run Docker in rootless mode to reduce privilege escalation risks
3. **Network Segmentation**: Isolate the MCP infrastructure on a separate Docker network
4. **Read-Only Socket**: Mount the socket as read-only where possible (note: provisioning requires write access)

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
