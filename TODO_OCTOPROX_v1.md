
  - `title: str`, `version: str`

- [x] **11.1.3** Implement API spec storage
  - `_loaded_apis: dict[str, LoadedAPI] = {}`

### Ref Resolution
- [x] **11.2.1** Implement `_resolve_ref(spec: dict, ref: str) -> dict`
  - Parse `$ref` pointer (e.g., `#/components/schemas/Foo`)
  - Navigate spec to resolve reference

- [x] **11.2.2** Implement `_deep_resolve(spec: dict, obj: Any) -> Any`
  - Recursively resolve all `$ref` pointers in an object

### Tool Implementations
- [x] **11.3.1** Implement `openapi_load` tool
  - Parameters: `name`, `spec_url`, `spec_content`, `auth_header`, `auth_header_name`, `base_url_override`
  - Fetch from URL or parse inline content (YAML/JSON)
  - Extract title, version from spec
  - Determine base URL (override or from `servers[0].url`)
  - Count endpoints (paths × methods)
  - Store in `_loaded_apis[name]`
  - Annotations: `readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True`

- [x] **11.3.2** Implement `openapi_list_endpoints` tool
  - Parameters: `name`, `filter`, `tag`, `limit`, `offset`
  - Get `_loaded_apis[name]`
  - Iterate `spec["paths"]`, apply filters
  - Paginate results
  - Annotations: `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

- [x] **11.3.3** Implement `openapi_get_operation` tool
  - Parameters: `name`, `path`, `method`
  - Look up path and method in spec
  - Resolve `$ref` pointers for parameters, requestBody, responses
  - Return structured operation details
  - Annotations: `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

- [x] **11.3.4** Implement `openapi_call` tool
  - Parameters: `name`, `path`, `method`, `path_params`, `query_params`, `headers`, `body`, `timeout_s`, `max_response_bytes`
  - Build URL: `base_url + path` with path params substituted
  - Set query params, auth header, additional headers
  - Make HTTP request with httpx
  - Parse response (JSON or text)
  - Truncate if needed
  - Annotations: `readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True`

- [x] **11.3.5** Implement `openapi_list_apis` tool
  - Return summary of all loaded APIs
  - Annotations: `readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False`

### GitLab Integration
- [x] **11.4.1** Refactor existing GitLab tools
  - Keep GitLab-specific tools for backwards compatibility
  - Internally delegate to generic adapter where possible
  - Keep `gitlab_request` separate (has GitLab-specific auth logic)

### Testing
- [x] **11.5.1** Create `workspace-mcp/tests/test_openapi.py`
- [x] **11.5.2** Test spec loading from URL and inline content
- [x] **11.5.3** Test `$ref` resolution
- [x] **11.5.4** Test endpoint listing and filtering
- [x] **11.5.5** Test operation detail extraction
- [x] **11.5.6** Test API call construction
- [x] **11.5.7** Test auth header injection
- [x] **11.5.8** Test base URL override

---

## Phase 12: REST API Exposure for NEXUSGATE Integration

> **Files:** `workspace-manager/app/main.py`, `workspace-manager/app/auth.py`  
> **Goal:** Expose management capabilities via REST JSON API for NEXUSGATE  
> **Dependencies:** Phase 0 (workspace-manager is separate from workspace-mcp)  

### New Dependencies
- [x] **12.1.1** Add `PyJWT>=2.8.0` to `workspace-manager/requirements.txt`
- [x] **12.1.2** Add `cryptography>=41.0.0` to `workspace-manager/requirements.txt`

### Authentication Changes
- [x] **12.2.1** Create `workspace-manager/app/auth_jwt.py`
  - Implement `create_access_token(user_id, username, role, secret)`
  - Implement `verify_access_token(token, secret)`
  - 15-minute expiration, include `jti`

- [x] **12.2.2** Add unified authentication to `workspace-manager/app/main.py`
  - `get_current_user_unified()` function
  - Try session auth first
  - Try API key (`mcp_*` prefix)
  - Try JWT Bearer token
  - Raise 401 if all fail

### User Endpoints
- [x] **12.3.1** Implement `GET /api/v1/users`
  - List users (admin sees all, user sees own)
  - Response with pagination
  - Dependencies: 12.2.2

- [x] **12.3.2** Implement `GET /api/v1/users/{id}`
  - Get user details including workspaces, API keys
  - Include `nexusgate_user_id` field
  - Dependencies: 12.2.2

- [x] **12.3.3** Implement `PUT /api/v1/users/{id}`
  - Update user: role, status, nexusgate_user_id
  - Admin only for other users
  - Dependencies: 12.2.2

- [x] **12.3.4** Implement `DELETE /api/v1/users/{id}`
  - Deactivate user (admin only, not self)
  - Dependencies: 12.2.2

### Workspace Endpoints
- [x] **12.4.1** Implement `GET /api/v1/workspaces`
  - List workspaces with pagination
  - Dependencies: 12.2.2

- [x] **12.4.2** Implement `POST /api/v1/workspaces`
  - Create workspace from JSON
  - Support `metadata` field with `nexusgate_service_id`
  - Dependencies: 12.2.2

- [x] **12.4.3** Implement `GET /api/v1/workspaces/{id}`
  - Get workspace details
  - Dependencies: 12.2.2

- [x] **12.4.4** Implement `DELETE /api/v1/workspaces/{id}`
  - Soft-delete workspace
  - Dependencies: 12.2.2

### API Key Endpoints
- [x] **12.5.1** Implement `GET /api/v1/api-keys`
  - List API keys for current user (admin sees all)
  - Dependencies: 12.2.2

- [x] **12.5.2** Implement `POST /api/v1/api-keys`
  - Create API key
  - Return raw key once with warning
  - Dependencies: 12.2.2

- [x] **12.5.3** Implement `DELETE /api/v1/api-keys/{id}`
  - Revoke API key
  - Dependencies: 12.2.2

### Authentication Endpoints
- [x] **12.6.1** Implement `POST /api/v1/auth/introspect`
  - Public token introspection (RFC 7662)
  - No IP restriction (unlike `/internal/auth/introspect`)
  - Response: `{"active": true/false, "sub": ..., "username": ..., "role": ...}`
  - Dependencies: 12.2.1

### Health Endpoint
- [x] **12.7.1** Implement `GET /api/v1/health`
  - Detailed health check
  - Response: status, timestamp, components (database, docker)
  - Dependencies: 12.2.2

### MCP Bridge Endpoints
- [x] **12.8.1** Implement `GET /api/v1/mcp/tools`
  - List available MCP tools for a workspace
  - Query param: `workspace_id`
  - Dependencies: 12.2.2

- [x] **12.8.2** Implement `POST /api/v1/mcp/invoke`
  - Invoke MCP tool via REST
  - Request: `{"workspace_id": 456, "tool": "fs_list", "arguments": {"path": "."}}`
  - Dependencies: 12.2.2

### Data Model Changes
- [x] **12.9.1** Add `nexusgate_user_id` column to User model
  - Type: String, nullable
  - Migration required

- [x] **12.9.2** Update Workspace model
  - Ensure `metadata` JSON field exists
  - Add `nexusgate_service_id` helper property

### Testing
- [x] **12.10.1** Create `workspace-manager/tests/test_rest_api.py`
- [x] **12.10.2** Test all user endpoints
- [x] **12.10.3** Test all workspace endpoints
- [x] **12.10.4** Test all API key endpoints
- [x] **12.10.5** Test token introspection
- [x] **12.10.6** Test MCP bridge endpoints
- [x] **12.10.7** Test authentication flows (session, API key, JWT)

---

## Phase 13: Testing & Documentation

### Test Infrastructure
- [x] **13.1.1** Create `workspace-mcp/tests/conftest.py`
  - Shared fixtures for mock auth
  - Workspace root fixture
  - Mock httpx client fixture
  - Mock subprocess fixture

- [x] **13.1.2** Create `workspace-mcp/tests/test_config.py`
  - Test feature flag loading
  - Test configuration validation
  - Test environment variable parsing

### Test Coverage Goals
- [x] **13.2.1** Achieve 80%+ coverage for all tool modules
- [x] **13.2.2** Achieve 90%+ coverage for auth and security code
- [x] **13.2.3** All external dependencies mocked in tests

### Documentation
- [x] **13.3.1** Update `workspace-mcp/README.md`
  - Document all 56 tools
  - Include usage examples
  - Document feature flags

- [x] **13.3.2** Create `workspace-mcp/docs/TOOLS.md`
  - Detailed documentation for each capability
  - Parameter descriptions
  - Return value schemas
  - Annotation explanations

- [x] **13.3.3** Create `workspace-mcp/docs/SECURITY.md`
  - SSRF protection details
  - Command execution safeguards
  - Database security measures
  - Best practices for operators

- [x] **13.3.4** Update `workspace-manager/API.md`
  - Document all REST API endpoints
  - Include request/response examples
  - Document authentication methods

- [x] **13.3.5** Create `workspace-mcp/docs/DOCKER.md`
  - Multi-stage build instructions
  - Playwright optional install
  - Environment variable reference

### Integration Testing
- [x] **13.4.1** Create integration test suite
  - Test full workspace lifecycle
  - Test MCP tool invocation via REST
  - Test container provisioning

- [x] **13.4.2** Add CI/CD pipeline configuration
  - GitHub Actions workflow
  - Run unit tests
  - Run integration tests
  - Build and push Docker images

### Final Review
- [x] **13.5.1** Code review all new modules
- [x] **13.5.2** Security audit (SSRF, command injection, SQL injection)
- [x] **13.5.3** Performance testing (load test MCP endpoints)
- [x] **13.5.4** Documentation review for completeness

---

## Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `OCTOPROX_ENABLE_FETCH` | `true` | Enable HTTP fetch tools |
| `OCTOPROX_ENABLE_BROWSER` | `false` | Enable Playwright browser tools |
| `OCTOPROX_ENABLE_READABILITY` | `true` | Enable readability extraction |
| `OCTOPROX_ENABLE_SEARCH` | `true` | Enable web search |
| `OCTOPROX_ENABLE_SHELL` | `false` | Enable shell command execution |
| `OCTOPROX_ENABLE_DATABASE` | `false` | Enable SQL database tools |
| `OCTOPROX_ENABLE_MEMORY` | `true` | Enable memory/knowledge graph |
| `OCTOPROX_ENABLE_TIME` | `true` | Enable time tools |
| `OCTOPROX_ENABLE_OPENAPI` | `true` | Enable generic OpenAPI adapter |
| `OCTOPROX_ENABLE_GITLAB` | `true` | Enable GitLab-specific tools |
| `OCTOPROX_SEARXNG_URL` | `""` | SearxNG instance URL for web search |
| `OCTOPROX_DATABASE_CONNECTIONS` | `""` | Comma-separated `name=dsn` pairs |
| `OCTOPROX_DATABASE_READ_ONLY` | `false` | Restrict DB to read-only queries |
| `OCTOPROX_SHELL_ALLOWED_COMMANDS` | `""` | Comma-separated allowed commands |
| `OCTOPROX_SHELL_BLOCKED_COMMANDS` | `"rm -rf /,..."` | Comma-separated blocked patterns |
| `OCTOPROX_SHELL_MAX_TIMEOUT` | `600` | Max shell command timeout seconds |

---

## Dependencies Summary

### Core Dependencies (requirements.txt)
```
mcp==1.26.0
httpx==0.28.1
uvicorn==0.40.0
PyYAML==6.0.3
cachetools==5.5.0
beautifulsoup4==4.13.3
markdownify==0.14.1
readability-lxml==0.8.4.1
lxml==5.3.1
asyncpg==0.30.0
python-dateutil==2.9.0
```

### Optional Browser Dependencies (requirements-browser.txt)
```
playwright==1.49.1
```

---

## File Structure

```
workspace-mcp/
├── app.py                      # Entrypoint: from octoprox import app
├── Dockerfile                  # Multi-stage with optional Playwright
├── requirements.txt            # Core dependencies
├── requirements-browser.txt    # Optional Playwright
└── octoprox/
    ├── __init__.py             # FastMCP app, shared helpers
    ├── auth.py                 # ManagerTokenVerifier, _require_owner
    ├── path_utils.py           # _resolve_path, _atomic_write
    ├── config.py               # Feature flags
    └── tools/
        ├── __init__.py         # Tool registration
        ├── filesystem.py       # fs_* tools
        ├── git.py              # git tools
        ├── fetch.py            # fetch_url
        ├── browser.py          # browser_* tools
        ├── readability.py      # read_page
        ├── search.py           # web_search
        ├── shell.py            # shell_exec, shell_which
        ├── database.py         # db_* tools
        ├── memory.py           # memory_* tools
        ├── time.py             # time_* tools
        ├── openapi.py          # openapi_* tools
        ├── gitlab.py           # GitLab-specific tools
        └── ssh.py              # ssh_public_key

workspace-manager/
├── app/
│   ├── main.py                 # FastAPI app with REST endpoints
│   ├── auth.py                 # Existing auth
│   ├── auth_jwt.py             # NEW: JWT functions
│   └── ...
└── tests/
    ├── test_rest_api.py        # NEW: REST API tests
    └── ...
```

---

## Tool Inventory (v1.0)

| # | Tool | Capability | Type | File |
|---|------|------------|------|------|
| 1 | `fetch_url` | 1: HTTP Fetch | Read | fetch.py |
| 2 | `browser_navigate` | 2: Browser | Read | browser.py |
| 3 | `browser_click` | 2: Browser | Write | browser.py |
| 4 | `browser_type` | 2: Browser | Write | browser.py |
| 5 | `browser_screenshot` | 2: Browser | Read | browser.py |
| 6 | `browser_get_content` | 2: Browser | Read | browser.py |
| 7 | `browser_execute_js` | 2: Browser | Write | browser.py |
| 8 | `browser_close` | 2: Browser | Write | browser.py |
| 9 | `read_page` | 3: Readability | Read | readability.py |
| 10 | `web_search` | 4: Search | Read | search.py |
| 11 | `fs_list` | 5: Filesystem | Read | filesystem.py |
| 12 | `fs_read_text` | 5: Filesystem | Read | filesystem.py |
| 13 | `fs_read_bytes` | 5: Filesystem | Read | filesystem.py |
| 14 | `fs_write_text` | 5: Filesystem | Write | filesystem.py |
| 15 | `fs_append` | 5: Filesystem | Write | filesystem.py |
| 16 | `fs_delete` | 5: Filesystem | Write | filesystem.py |
| 17 | `fs_move` | 5: Filesystem | Write | filesystem.py |
| 18 | `fs_copy` | 5: Filesystem | Write | filesystem.py |
| 19 | `fs_stat` | 5: Filesystem | Read | filesystem.py |
| 20 | `fs_glob` | 5: Filesystem | Read | filesystem.py |
| 21 | `fs_tree` | 5: Filesystem | Read | filesystem.py |
| 22 | `fs_search` | 5: Filesystem | Read | filesystem.py |
| 23 | `fs_patch` | 5: Filesystem | Write | filesystem.py |
| 24 | `git` | 6: Git | Read/Write | git.py |
| 25 | `git_status` | 6: Git | Read | git.py |
| 26 | `git_diff_structured` | 6: Git | Read | git.py |
| 27 | `git_log_structured` | 6: Git | Read | git.py |
| 28 | `git_blame` | 6: Git | Read | git.py |
| 29 | `shell_exec` | 7: Shell | Write | shell.py |
| 30 | `shell_which` | 7: Shell | Read | shell.py |
| 31 | `db_query` | 8: Database | Read | database.py |
| 32 | `db_execute` | 8: Database | Write | database.py |
| 33 | `db_schema` | 8: Database | Read | database.py |
| 34 | `db_explain` | 8: Database | Read | database.py |
| 35 | `db_connections` | 8: Database | Read | database.py |
| 36 | `memory_upsert_entities` | 9: Memory | Write | memory.py |
| 37 | `memory_add_relations` | 9: Memory | Write | memory.py |
| 38 | `memory_query` | 9: Memory | Read | memory.py |
| 39 | `memory_delete` | 9: Memory | Write | memory.py |
| 40 | `memory_list` | 9: Memory | Read | memory.py |
| 41 | `time_now` | 10: Time | Read | time.py |
| 42 | `time_convert` | 10: Time | Read | time.py |
| 43 | `time_parse` | 10: Time | Read | time.py |
| 44 | `time_diff` | 10: Time | Read | time.py |
| 45 | `time_list_timezones` | 10: Time | Read | time.py |
| 46 | `openapi_load` | 11: OpenAPI | Write | openapi.py |
| 47 | `openapi_list_endpoints` | 11: OpenAPI | Read | openapi.py |
| 48 | `openapi_get_operation` | 11: OpenAPI | Read | openapi.py |
| 49 | `openapi_call` | 11: OpenAPI | Write | openapi.py |
| 50 | `openapi_list_apis` | 11: OpenAPI | Read | openapi.py |
| 51 | `ssh_public_key` | SSH | Read | ssh.py |
| 52 | `gitlab_request` | GitLab | Write | gitlab.py |
| 53 | `gitlab_openapi_spec` | GitLab | Read | gitlab.py |
| 54 | `gitlab_openapi_paths` | GitLab | Read | gitlab.py |
| 55 | `gitlab_openapi_operation` | GitLab | Read | gitlab.py |
| 56 | `gitlab_tool_help` | GitLab | Read | gitlab.py |

---

## Implementation Order Summary

1. **Phase 0** (Foundation) → MUST be done first
2. **Phase 5** (Filesystem expansion) → High value, low risk
3. **Phase 6** (Git expansion) → High value, low risk
4. **Phase 10** (Time) → Simple, zero risk
5. **Phase 1** (HTTP Fetch) → Foundation for web retrieval
6. **Phase 3** (Readability) → Built on fetch
7. **Phase 4** (Search) → Depends on SearxNG
8. **Phase 9** (Memory) → No external deps
9. **Phase 8** (Database) → Requires PostgreSQL
10. **Phase 11** (OpenAPI Adapter) → Generalizes GitLab tools
11. **Phase 7** (Shell) → Security-sensitive
12. **Phase 2** (Playwright) → Largest footprint
13. **Phase 12** (REST API) → NEXUSGATE integration
14. **Phase 13** (Testing & Docs) → Final polish

---

## Phase 14: Production Security Hardening

> **Files:** `workspace-manager/Dockerfile`, `docker-compose.yml`  
> **Goal:** Address critical security vulnerabilities identified in security audit  
> **Dependencies:** Phase 13 (13.5.2 Security audit complete)

### Critical Issues Found

| Severity | Count | Issues |
|----------|-------|--------|
| 🔴 **CRITICAL** | 2 | Container runs as root; Docker socket access creates container escape vulnerability |
| 🟠 **HIGH** | 3 | No image digest pinning; test dependencies in production; no HEALTHCHECK |
| 🟡 **MEDIUM** | 4 | World-writable data directory; missing .dockerignore; no uvicorn limits; build deps remain |

### Required Actions

#### 14.1 Dockerfile Security Hardening

**14.1.1** Implement multi-stage build
- Create builder stage for compile-time dependencies
- Copy only necessary artifacts to runtime stage
- Remove build-essential from final image

**14.1.2** Add non-root user
- Create `appuser:appgroup` with UID/GID 1000
- Set proper ownership on /app directory
- Add `USER appuser` before CMD

**14.1.3** Pin base image
- Use specific patch version: `python:3.12.8-slim-bookworm`
- Consider using digest for reproducible builds

**14.1.4** Add HEALTHCHECK
```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1
```

**14.1.5** Secure data directory permissions
```dockerfile
RUN mkdir -p /app/data && chmod 750 /app/data
```

**14.1.6** Production uvicorn settings
- Add `--workers 4` for multi-worker setup
- Add `--proxy-headers` for Traefik compatibility
- Add `--no-server-header` to hide version
- Add `--limit-concurrency 100` for DoS protection

#### 14.2 Docker Compose Security

**14.2.1** Implement Docker Socket Proxy
- Add `tecnativa/docker-socket-proxy` service
- Limit API access to only required endpoints (containers, networks)
- Remove direct docker.sock mount from workspace-manager

**14.2.2** Add container security options
```yaml
read_only: true
tmpfs:
  - /tmp:noexec,nosuid,size=100m
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
deploy:
  resources:
    limits:
      cpus: '1.0'
      memory: 512M
```

#### 14.3 Supporting Files

**14.3.1** Create `.dockerignore`
- Exclude .env files, .git, tests, scripts
- Exclude Python cache files
- Exclude documentation

**14.3.2** Separate requirements
- Create `requirements-dev.txt` for pytest and dev tools
- Keep production `requirements.txt` minimal

### Implementation Priority

1. **CRITICAL (Deploy Blocker)**: 14.1.2 (non-root user), 14.2.1 (socket proxy)
2. **HIGH**: 14.1.1 (multi-stage), 14.1.3 (image pinning), 14.1.4 (healthcheck)
3. **MEDIUM**: 14.3.1 (.dockerignore), 14.3.2 (requirements split)

### Acceptance Criteria

- [x] Container runs as non-root user
- [x] Docker socket proxy implemented
- [x] Multi-stage build reduces image size
- [x] Healthcheck endpoint responding
- [x] No build tools in final image
- [x] `.dockerignore` excludes sensitive files

---

*End of TODO_OCTOPROX_v1.md* </replace>
