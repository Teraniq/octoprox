# Security Guide

This document describes the security measures implemented in Octoprox and provides best practices for operators.

## Overview

Octoprox implements defense in depth with multiple layers of security:

1. **Authentication & Authorization** - Token-based access control
2. **Path Security** - Filesystem isolation and traversal prevention
3. **Command Security** - Git command whitelisting and injection prevention
4. **Network Security** - SSRF protection and external request validation
5. **Resource Limits** - Timeouts and size limits on operations

---

## Authentication

### Token Introspection

Octoprox uses OAuth2 token introspection for authentication:

```
Client Request → Token Validation → User ID Check → Resource Access
                      ↓
              Introspection Endpoint
              (workspace-manager)
```

**Flow:**
1. Client presents Bearer token in `Authorization` header
2. Token is sent to `MANAGER_INTROSPECT_URL` for validation
3. Response includes `active` status and `user_id`
4. User ID is compared against `WORKSPACE_OWNER_USER_ID`
5. If mismatch, request is rejected with 403 Forbidden

**Implementation Details:**
- Tokens are cached for 60 seconds to reduce introspection load
- Cache uses TTLCache with maxsize=1000 to prevent memory exhaustion
- Singleton httpx.AsyncClient for connection reuse
- Failed introspection results in `{"active": false}`

### Owner Authorization

Every tool requires the caller to be the workspace owner:

```python
def _require_owner() -> None:
    access_token = get_access_token()
    if not access_token:
        raise RuntimeError("Unauthorized")
    if OWNER_USER_ID and access_token.client_id != OWNER_USER_ID:
        raise RuntimeError("Forbidden")
```

This ensures:
- Users can only access their own workspaces
- Compromised tokens from other users cannot access this workspace
- Clear audit trail of workspace ownership

---

## SSRF Protection

Server-Side Request Forgery (SSRF) attacks attempt to make the server send requests to internal or restricted resources.

### URL Validation

When making external HTTP requests (via `openapi_load`, `gitlab_request`, etc.):

**Scheme Restrictions:**
- Only `http://` and `https://` schemes are allowed
- File URLs, FTP, and other schemes are rejected

**Private IP Blocking:**
- Requests to private IP ranges are blocked:
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
  - `127.0.0.0/8`
  - `169.254.0.0/16` (link-local)
  - `::1/128` (IPv6 loopback)
  - `fc00::/7` (IPv6 private)

**Hostname Validation:**
- Hostnames resolving to private IPs are blocked
- DNS rebattack protection through resolution-time checks

### Implementation Example

```python
from urllib.parse import urlparse
import ipaddress

def is_private_ip(hostname: str) -> bool:
    """Check if hostname resolves to a private IP."""
    try:
        addr = ipaddress.ip_address(hostname)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        # Not an IP, try DNS resolution
        import socket
        try:
            resolved = socket.getaddrinfo(hostname, None)[0][4][0]
            addr = ipaddress.ip_address(resolved)
            return addr.is_private or addr.is_loopback
        except (socket.gaierror, ValueError):
            return False

def validate_url(url: str) -> None:
    """Validate URL for SSRF prevention."""
    parsed = urlparse(url)
    
    # Scheme check
    if parsed.scheme not in ('http', 'https'):
        raise ValueError(f"Scheme not allowed: {parsed.scheme}")
    
    # Private IP check
    if is_private_ip(parsed.hostname):
        raise ValueError("Private IP addresses not allowed")
```

---

## Command Execution Safeguards

### Git Command Whitelist

The `git` tool only allows whitelisted commands:

```python
ALLOWED_GIT_COMMANDS = {
    'clone': {'max_args': 10, 'allowed_prefixes': [...]},
    'status': {'max_args': 5, 'allowed_prefixes': [...]},
    'log': {'max_args': 10, 'allowed_prefixes': [...]},
    # ... 16 commands total
}
```

**Security Features:**
1. **Command Whitelist** - Only 16 git commands are permitted
2. **Argument Limits** - Maximum arguments per command to prevent DoS
3. **Prefix Validation** - Arguments must start with allowed prefixes
4. **No Shell Execution** - Commands run without `shell=True`

### Shell Injection Prevention

Multiple layers prevent shell injection:

```python
# Blocked characters
SHELL_INJECTION_CHARS = set(';|&$`\n\r<>!{}[]')

# Blocked patterns
if '$(' in arg or '`' in arg:
    raise ValueError("Command substitution not allowed")

# Path traversal in arguments
if '../' in arg or '..\\' in arg:
    raise ValueError("Path traversal not allowed")
```

### Git Environment Security

Git commands run with secure environment settings:

```python
env = os.environ.copy()
env["HOME"] = str(WORKSPACE_ROOT / ".home")
env["GIT_TERMINAL_PROMPT"] = "0"  # Disable interactive prompts
env["GIT_SSH_COMMAND"] = "ssh -o StrictHostKeyChecking=yes ..."
```

This prevents:
- Reading user's global git config
- Interactive credential prompts
- SSH host key bypass attacks

---

## Filesystem Security

### Path Traversal Protection

All filesystem operations use `_resolve_path()` for secure path resolution:

```python
def _resolve_path(path: str) -> pathlib.Path:
    # Validate path length
    if len(path) > 4096:
        raise ValueError("Path too long")
    
    # Check for null bytes
    if '\x00' in path:
        raise ValueError("Null bytes not allowed")
    
    # Check for control characters
    if any(ord(c) < 32 for c in path):
        raise ValueError("Control characters not allowed")
    
    # Resolve path (follows symlinks)
    target = (WORKSPACE_ROOT / path).resolve()
    
    # Ensure path is within workspace (proper path comparison)
    try:
        target.relative_to(WORKSPACE_ROOT)
    except ValueError:
        raise ValueError("Path escapes workspace root")
    
    # Additional symlink check
    if WORKSPACE_ROOT not in target.parents and target != WORKSPACE_ROOT:
        raise ValueError("Symlink escapes workspace root")
    
    return target
```

**Key Security Features:**

1. **Path Resolution** - Uses `pathlib.Path.resolve()` which follows symlinks
2. **Proper Comparison** - Uses `relative_to()` not string comparison
3. **Symlink Check** - Verifies resolved path is still within workspace
4. **Length Limits** - Prevents DoS via extremely long paths
5. **Null Byte Check** - Prevents null byte injection attacks

### Symlink Attack Prevention

Symlink attacks attempt to access files outside the workspace:

```
/workspace/symlink → /etc/passwd (created by attacker)
```

**Defense:**
- `resolve()` follows symlinks to final destination
- `relative_to()` verifies final path is within workspace
- Additional parent check catches edge cases

### Atomic Writes

File writes use atomic operations:

```python
def _atomic_write(target: pathlib.Path, text: str) -> None:
    with tempfile.NamedTemporaryFile("w", delete=False, dir=target.parent) as tmp:
        tmp.write(text)
        tmp.flush()
        os.fsync(tmp.fileno())  # Ensure data is on disk
        temp_name = tmp.name
    os.replace(temp_name, target)  # Atomic rename
```

Benefits:
- No partial writes visible to other processes
- Crash-safe (temp file cleaned up on restart)
- No race conditions during write

---

## Database Security

### Read-Only Mode

When database tools are enabled, they support read-only mode:

```python
# Connection string with read-only pragma
sqlite3.connect("file:/workspace/data.db?mode=ro")
```

### Query Sanitization

- Use parameterized queries exclusively
- No string interpolation in SQL
- Query timeouts to prevent long-running queries

### Connection Security

- Connections limited to workspace database only
- No access to external databases by default
- Connection pooling with max limits

---

## Resource Limits

### Timeout Protection

All operations have timeouts to prevent DoS:

| Operation | Default Timeout | Max Timeout |
|-----------|-----------------|-------------|
| Git commands | 120s | 300s |
| HTTP requests | 30s | 300s |
| OpenAPI calls | 30s | 300s |

### Size Limits

Response and file size limits prevent memory exhaustion:

| Resource | Default Limit |
|----------|---------------|
| File read | 200,000 bytes |
| HTTP response | 100,000 - 200,000 bytes |
| OpenAPI spec chunk | 200,000 bytes |

### Rate Limiting

MCP operations can be rate-limited:

- Per-tool rate limiting
- Per-user rate limiting
- Configurable via environment variables

---

## Best Practices for Operators

### 1. Recommended Feature Flag Settings

**Production (High Security):**
```bash
OCTOPROX_ENABLE_OPENAPI=true
OCTOPROX_ENABLE_GITLAB=true
OCTOPROX_ENABLE_FETCH=true
OCTOPROX_ENABLE_BROWSER=false      # Keep disabled unless needed
OCTOPROX_ENABLE_SHELL=false        # Never enable in production
OCTOPROX_ENABLE_DATABASE=false     # Enable only if needed
OCTOPROX_ENABLE_MEMORY=true
OCTOPROX_ENABLE_TIME=true
```

**Development Environment:**
```bash
OCTOPROX_ENABLE_BROWSER=true       # For testing web scraping
OCTOPROX_ENABLE_SHELL=true         # For debugging (isolated env)
```

### 2. Network Isolation

Use Docker networks to isolate workspaces:

```yaml
services:
  mcp-server:
    networks:
      - workspace-internal
      - external-api  # Only if external API access needed
    # No direct internet access by default
```

### 3. Token Security

- Use short-lived access tokens (15 minutes recommended)
- Rotate tokens regularly
- Monitor introspection endpoint for anomalies
- Never log full tokens (only first/last 4 chars)

### 4. Audit Logging

Enable comprehensive audit logging:

```python
# Log all tool invocations
logger.info(f"Tool: {tool_name}, User: {user_id}, Params: {redacted_params}")

# Log authentication events
logger.info(f"Auth: success, User: {user_id}, Token: {token_prefix}...")

# Log security events
logger.warning(f"Security: blocked path traversal, Path: {attempted_path}")
```

### 5. Workspace Data Protection

```bash
# Use named volumes with proper permissions
volumes:
  - workspace-data:/workspace:rw

# Set proper ownership
RUN chown -R 1000:1000 /workspace

# Use read-only root filesystem where possible
read_only: true
tmpfs:
  - /tmp
```

### 6. Secret Management

Never hardcode secrets in:
- Docker images
- Configuration files
- Environment variable defaults

Use proper secret management:
```bash
# Docker secrets (Swarm)
secrets:
  - GITLAB_TOKEN

# Kubernetes secrets
env:
  - name: GITLAB_TOKEN
    valueFrom:
      secretKeyRef:
        name: octoprox-secrets
        key: gitlab-token
```

---

## Security Checklist

Before deploying Octoprox:

- [x] `OCTOPROX_ENABLE_SHELL` is set to `false` in production
- [x] `OCTOPROX_ENABLE_BROWSER` is set to `false` unless required
- [x] `MANAGER_INTROSPECT_URL` uses HTTPS
- [x] `WORKSPACE_OWNER_USER_ID` is properly set
- [x] Workspace volumes are isolated per-user
- [x] Network policies restrict egress traffic
- [x] Audit logging is enabled
- [x] Resource limits (CPU/memory) are configured
- [x] Container runs as non-root user
- [x] Read-only root filesystem is enabled
- [x] Security scanning passes (Trivy, Snyk, etc.)

---

## Incident Response

If a security incident is suspected:

1. **Isolate** - Stop the affected workspace container
2. **Preserve** - Capture container state and logs
3. **Audit** - Review all tool invocations in the timeframe
4. **Analyze** - Check for data exfiltration or unauthorized access
5. **Remediate** - Rotate tokens, patch vulnerabilities
6. **Document** - Record incident details and lessons learned

---

## Reporting Security Issues

Security issues should be reported privately to the maintainers:

1. Email: security@example.com
2. Do not create public GitHub issues for security bugs
3. Include steps to reproduce and impact assessment
4. Allow 30 days for response before public disclosure
