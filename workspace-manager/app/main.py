from __future__ import annotations

import asyncio
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone
import ipaddress
from typing import Any
from uuid import UUID

from fastapi import Body, Depends, FastAPI, Form, Header, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from . import auth, services
from .db import SessionLocal, get_db, init_db, engine
from .db_maintenance import backup_database, test_database_connectivity, verify_database_schema
from .models import ApiKey, User, Workspace
from .provisioning import WorkspaceProvisioner
from .settings import settings


# ============================================================================
# Input Validation Helpers (Phase 8)
# ============================================================================

def validate_workspace_name_input(name: str) -> tuple[bool, str]:
    """Validate workspace name format.
    
    Args:
        name: Workspace name to validate
        
    Returns:
        Tuple of (is_valid: bool, error_message: str)
    """
    if not name:
        return False, "Workspace name is required"
    if len(name) > 128:
        return False, "Workspace name must be 128 characters or less"
    if not re.match(r'^[a-zA-Z0-9._-]+$', name):
        return False, "Workspace name can only contain alphanumeric characters, hyphens, dots, and underscores"
    return True, ""


def validate_uuid(value: str) -> bool:
    """Validate UUID format.
    
    Args:
        value: String to validate as UUID
        
    Returns:
        True if valid UUID, False otherwise
    """
    try:
        UUID(value)
        return True
    except ValueError:
        return False


def validate_nexusgate_user_id(user_id: str) -> tuple[bool, str]:
    """Validate NEXUSGATE user ID format (UUID).
    
    Args:
        user_id: NEXUSGATE user ID to validate
        
    Returns:
        Tuple of (is_valid: bool, error_message: str)
    """
    if not user_id:
        return False, "NEXUSGATE user ID is required"
    if not validate_uuid(user_id):
        return False, "NEXUSGATE user ID must be a valid UUID"
    return True, ""

# Configure logging
logger = logging.getLogger(__name__)

app = FastAPI()

# ============================================================================
# Rate Limiting Configuration (Phase 8)
# ============================================================================

# Rate limiting storage (in-memory, per-process)
rate_limit_storage: dict[str, dict] = {}

API_RATE_LIMIT = settings.api_rate_limit  # requests per minute
AUTH_RATE_LIMIT = settings.auth_rate_limit  # requests per minute for auth endpoints


def get_client_ip(request: Request) -> str:
    """Get client IP from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def check_rate_limit(ip: str, limit: int) -> tuple[bool, int]:
    """
    Check if IP has exceeded rate limit.
    Returns (allowed: bool, remaining: int)
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=1)

    if ip not in rate_limit_storage:
        rate_limit_storage[ip] = {"requests": [], "blocked_until": None}

    storage = rate_limit_storage[ip]

    # Check if currently blocked
    if storage["blocked_until"] and now < storage["blocked_until"]:
        return False, 0

    # Clean old requests outside window
    storage["requests"] = [
        req_time for req_time in storage["requests"]
        if req_time > window_start
    ]

    # Check limit
    if len(storage["requests"]) >= limit:
        storage["blocked_until"] = now + timedelta(minutes=1)
        return False, 0

    # Record request
    storage["requests"].append(now)
    remaining = limit - len(storage["requests"])
    return True, remaining


# ============================================================================
# Security Headers Middleware (Phase 8)
# ============================================================================

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)

    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"

    # XSS protection
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Strict transport security (controlled by settings)
    if settings.enforce_https:
        hsts_value = f"max-age={settings.hsts_max_age}"
        if settings.hsts_include_subdomains:
            hsts_value += "; includeSubDomains"
        response.headers["Strict-Transport-Security"] = hsts_value

    # Content security policy (basic)
    response.headers["Content-Security-Policy"] = "default-src 'self'"

    # Referrer policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    return response


# ============================================================================
# Rate Limiting Middleware (Phase 8)
# ============================================================================

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Apply rate limiting to requests."""
    # Skip rate limiting for health checks
    if request.url.path == "/api/v1/health":
        return await call_next(request)

    ip = get_client_ip(request)

    # Stricter limits for auth endpoints
    is_auth_endpoint = request.url.path in ["/login", "/logout", "/api/v1/auth/introspect"]
    limit = AUTH_RATE_LIMIT if is_auth_endpoint else API_RATE_LIMIT

    allowed, remaining = check_rate_limit(ip, limit)

    if not allowed:
        logger.warning("Rate limit exceeded for IP %s on %s", ip, request.url.path)
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded", "retry_after": 60},
            headers={"Retry-After": "60", "X-RateLimit-Limit": str(limit)}
        )

    response = await call_next(request)
    response.headers["X-RateLimit-Limit"] = str(limit)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    return response
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax")
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Internal networks that are allowed to access introspect endpoint
# Docker default networks + localhost
INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),     # Private
    ipaddress.ip_network("172.16.0.0/12"),  # Docker default
    ipaddress.ip_network("192.168.0.0/16"), # Private
    ipaddress.ip_network("127.0.0.0/8"),    # Loopback
    ipaddress.ip_network("::1/128"),        # IPv6 loopback
]

# Shared secret for introspect endpoint (should be set via env var in production)
INTROSPECT_SECRET = ""

# CSRF token storage (in session)
CSRF_TOKEN_NAME = "csrf_token"

# Graceful shutdown event
_shutdown_event = asyncio.Event()

# Background task reference for cleanup
_purge_task: asyncio.Task[Any] | None = None


def _is_internal_ip(ip_str: str) -> bool:
    """Check if an IP address is from an internal network."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in INTERNAL_NETWORKS)
    except ValueError:
        return False


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, handling proxies."""
    # Check X-Forwarded-For header first (for proxied requests)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP in the chain (closest to client)
        return forwarded.split(",")[0].strip()
    
    # Check X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Fall back to direct connection
    if request.client:
        return request.client.host
    
    return "unknown"


def _generate_csrf_token() -> str:
    """Generate a secure CSRF token."""
    return secrets.token_urlsafe(32)


def _get_csrf_token(request: Request) -> str:
    """Get or create a CSRF token for the session."""
    token = request.session.get(CSRF_TOKEN_NAME)
    if not token:
        token = _generate_csrf_token()
        request.session[CSRF_TOKEN_NAME] = token
    return token


def _validate_csrf_token(request: Request, token: str | None = Form(None, alias="csrf_token")) -> None:
    """Validate CSRF token from form submission."""
    expected = request.session.get(CSRF_TOKEN_NAME)
    if not expected or not token:
        logger.warning("CSRF token missing - request rejected")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token missing"
        )
    if not secrets.compare_digest(expected, token):
        logger.warning("CSRF token mismatch - request rejected")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token invalid"
        )


rate_limit: dict[str, list[datetime]] = {}
rate_limit_locks: dict[str, asyncio.Lock] = {}
rate_limit_global_lock = asyncio.Lock()

# Account-level rate limiting (by username)
account_rate_limit: dict[str, list[datetime]] = {}
account_rate_limit_locks: dict[str, asyncio.Lock] = {}
account_rate_limit_global_lock = asyncio.Lock()


def _clean_attempts(attempts: list[datetime], window: timedelta) -> list[datetime]:
    cutoff = datetime.now(timezone.utc) - window
    return [entry for entry in attempts if entry > cutoff]


async def _get_rate_limit_lock(ip: str) -> asyncio.Lock:
    """Get or create a per-IP lock for atomic rate limit operations."""
    async with rate_limit_global_lock:
        if ip not in rate_limit_locks:
            rate_limit_locks[ip] = asyncio.Lock()
        return rate_limit_locks[ip]


async def _get_account_rate_limit_lock(username: str) -> asyncio.Lock:
    """Get or create a per-account lock for atomic rate limit operations."""
    async with account_rate_limit_global_lock:
        if username not in account_rate_limit_locks:
            account_rate_limit_locks[username] = asyncio.Lock()
        return account_rate_limit_locks[username]


async def check_rate_limit(
    ip: str,
    max_attempts: int = 5,
    window_minutes: int = 5,
    log_violations: bool = True
) -> bool:
    """Check if request is within rate limit. Thread-safe per IP."""
    window = timedelta(minutes=window_minutes)
    
    # Get per-IP lock for atomic operations
    lock = await _get_rate_limit_lock(ip)
    
    async with lock:
        attempts = rate_limit.get(ip, [])
        attempts = _clean_attempts(attempts, window)
        
        if len(attempts) >= max_attempts:
            rate_limit[ip] = attempts
            if log_violations:
                logger.warning(
                    "Rate limit exceeded for IP %s - %d attempts in %d minutes",
                    ip, len(attempts), window_minutes
                )
            return False
        
        attempts.append(datetime.now(timezone.utc))
        rate_limit[ip] = attempts
        return True


async def check_account_rate_limit(
    username: str,
    max_attempts: int = 10,
    window_minutes: int = 15,
    log_violations: bool = True
) -> bool:
    """Check if account is within rate limit. Thread-safe per username."""
    window = timedelta(minutes=window_minutes)
    
    # Get per-account lock for atomic operations
    lock = await _get_account_rate_limit_lock(username)
    
    async with lock:
        attempts = account_rate_limit.get(username, [])
        attempts = _clean_attempts(attempts, window)
        
        if len(attempts) >= max_attempts:
            account_rate_limit[username] = attempts
            if log_violations:
                logger.warning(
                    "Account rate limit exceeded for user %s - %d attempts in %d minutes",
                    username, len(attempts), window_minutes
                )
            return False
        
        attempts.append(datetime.now(timezone.utc))
        account_rate_limit[username] = attempts
        return True


def cleanup_empty_rate_limit_entries() -> int:
    """Clean up empty IP entries from rate limit storage. Returns count removed."""
    removed = 0
    empty_ips = [ip for ip, attempts in rate_limit.items() if not attempts]
    for ip in empty_ips:
        del rate_limit[ip]
        if ip in rate_limit_locks:
            del rate_limit_locks[ip]
        removed += 1
    
    empty_accounts = [user for user, attempts in account_rate_limit.items() if not attempts]
    for user in empty_accounts:
        del account_rate_limit[user]
        if user in account_rate_limit_locks:
            del account_rate_limit_locks[user]
        removed += 1
    
    if removed > 0:
        logger.debug("Cleaned up %d empty rate limit entries", removed)
    return removed


# Keep sync version for backward compatibility in non-async contexts
def check_rate_limit_sync(ip: str, max_attempts: int = 5, window_minutes: int = 5) -> bool:
    """Synchronous version of rate limit check (not thread-safe)."""
    window = timedelta(minutes=window_minutes)
    attempts = rate_limit.get(ip, [])
    attempts = _clean_attempts(attempts, window)
    if len(attempts) >= max_attempts:
        rate_limit[ip] = attempts
        return False
    attempts.append(datetime.now(timezone.utc))
    rate_limit[ip] = attempts
    return True


def require_login(request: Request) -> dict[str, Any]:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return user


def require_admin_user(request: Request, db: Session) -> User:
    session_user = require_login(request)
    user = db.execute(select(User).where(User.id == session_user["id"])).scalar_one_or_none()
    if not user or user.status != "active":
        request.session.clear()
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    return user


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    session_user = require_login(request)
    user = db.execute(select(User).where(User.id == session_user["id"])).scalar_one_or_none()
    if not user or user.status != "active":
        request.session.clear()
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return user


async def purge_loop() -> None:
    """Background task to purge due workspaces periodically."""
    while not _shutdown_event.is_set():
        try:
            # Wait for shutdown event or next interval
            await asyncio.wait_for(
                _shutdown_event.wait(),
                timeout=settings.purge_interval_seconds
            )
        except asyncio.TimeoutError:
            # Normal interval timeout - proceed with purge
            pass
        
        if _shutdown_event.is_set():
            break
        
        try:
            with SessionLocal() as db:
                provisioner = WorkspaceProvisioner()
                services.purge_due_workspaces(db, provisioner)
        except Exception as e:
            logger.exception("Error in purge loop: %s", e)
        
        # Clean up empty rate limit entries periodically
        cleanup_empty_rate_limit_entries()


@app.on_event("startup")
async def startup_event() -> None:
    """Initialize application on startup."""
    init_db()
    with SessionLocal() as db:
        existing = db.execute(select(User).where(User.role == "admin")).scalar_one_or_none()
        if not existing:
            admin = User(
                username=settings.bootstrap_admin_username,
                password_hash=auth.hash_password(settings.bootstrap_admin_password),
                role="admin",
            )
            db.add(admin)
            db.commit()
    
    global _purge_task
    _purge_task = asyncio.create_task(purge_loop())
    logger.info("Application startup complete")


@app.on_event("shutdown")
async def shutdown_event() -> None:
    """Handle graceful shutdown."""
    logger.info("Shutting down gracefully...")
    
    # Signal all background tasks to stop
    _shutdown_event.set()
    
    # Cancel and wait for purge task
    global _purge_task
    if _purge_task and not _purge_task.done():
        _purge_task.cancel()
        try:
            await _purge_task
        except asyncio.CancelledError:
            pass
    
    # Close database connections
    engine.dispose()
    
    logger.info("Shutdown complete")


@app.get("/health")
def health_check() -> dict[str, str]:
    """Health check endpoint for load balancers."""
    if _shutdown_event.is_set():
        raise HTTPException(status_code=503, detail="Shutting down")
    return {"status": "healthy"}


@app.get("/", response_class=HTMLResponse)
def root(request: Request) -> HTMLResponse:
    require_login(request)
    return RedirectResponse("/workspaces", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    # Generate CSRF token for the login form
    csrf_token = _get_csrf_token(request)
    return templates.TemplateResponse("login.html", {"request": request, "csrf_token": csrf_token})


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str | None = Form(None, alias="csrf_token"),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    # Validate CSRF token
    try:
        _validate_csrf_token(request, csrf_token)
    except HTTPException as e:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid security token. Please refresh the page."},
            status_code=403,
        )
    
    ip = _get_client_ip(request)
    
    # Check IP-based rate limit
    if not await check_rate_limit(ip):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Too many attempts. Try again later."},
            status_code=429,
        )
    
    # Check account-based rate limit
    if not await check_account_rate_limit(username):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Too many attempts for this account. Try again later."},
            status_code=429,
        )
    
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if not user or not auth.verify_password(password, user.password_hash):
        # Audit log failed authentication
        services.audit_log(
            user_id=None,
            action="auth_failed",
            resource="authentication",
            details={"ip": ip, "reason": "invalid_credentials", "username": username}
        )
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid credentials."},
            status_code=401,
        )
    if user.status != "active":
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Account is deactivated."},
            status_code=403,
        )
    
    # Session fixation protection: regenerate session ID on login
    # Store old session data (excluding auth data)
    old_session_data = {k: v for k, v in request.session.items() if k not in ("user", CSRF_TOKEN_NAME)}
    
    # Clear the session to get a new session ID
    request.session.clear()
    
    # Restore non-auth data
    for key, value in old_session_data.items():
        request.session[key] = value
    
    # Generate new CSRF token for the new session
    new_csrf_token = _generate_csrf_token()
    request.session[CSRF_TOKEN_NAME] = new_csrf_token
    
    # Set auth data in the new session
    request.session["user"] = {"id": user.id, "username": user.username, "role": user.role}
    logger.info("User %s logged in successfully from IP %s", username, ip)
    # Audit log successful authentication
    services.audit_log(
        user_id=user.id,
        action="auth_success",
        resource="authentication",
        details={"ip": ip, "username": username}
    )
    return RedirectResponse("/workspaces", status_code=303)


@app.post("/logout")
def logout(request: Request) -> RedirectResponse:
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/workspaces", response_class=HTMLResponse)
def workspaces_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    if current_user.role == "admin":
        query = select(Workspace).where(Workspace.status == "active")
    else:
        query = select(Workspace).where(
            Workspace.user_id == current_user.id,
            Workspace.status == "active",
        )
    workspaces = db.execute(query.order_by(Workspace.created_at.desc())).scalars().all()
    csrf_token = _get_csrf_token(request)
    context = {
        "request": request,
        "user": current_user,
        "workspaces": workspaces,
        "public_base_url": settings.public_base_url,
        "message": request.session.pop("message", None),
        "token": request.session.pop("token", None),
        "csrf_token": csrf_token,
    }
    return templates.TemplateResponse("workspaces.html", context)


@app.get("/workspaces/validate", response_class=HTMLResponse)
def validate_workspace_name(
    request: Request,
    name: str,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    ok, message = services.validate_workspace_name(db, name)
    color = "green" if ok else "red"
    return HTMLResponse(f"<span style='color:{color}'>{message}</span>")


@app.post("/workspaces")
def create_workspace(
    request: Request,
    name: str = Form(...),
    csrf_token: str | None = Form(None, alias="csrf_token"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RedirectResponse:
    try:
        _validate_csrf_token(request, csrf_token)
    except HTTPException:
        request.session["message"] = "Invalid security token. Please refresh the page."
        return RedirectResponse("/workspaces", status_code=303)
    
    provisioner = WorkspaceProvisioner()
    try:
        workspace = services.create_workspace(db, provisioner, current_user, name)
        request.session["message"] = f"Workspace '{name}' created."
        # Audit log workspace creation
        services.audit_log(
            user_id=current_user.id,
            action="workspace_created",
            resource=f"workspace:{workspace.id}",
            details={"name": name}
        )
    except ValueError as exc:
        request.session["message"] = str(exc)
    return RedirectResponse("/workspaces", status_code=303)


@app.get("/workspaces/{workspace_id}/details", response_class=HTMLResponse)
def workspace_details(
    request: Request,
    workspace_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    workspace = db.execute(select(Workspace).where(Workspace.id == workspace_id)).scalar_one_or_none()
    if not workspace:
        raise HTTPException(status_code=404)
    if current_user.role != "admin" and workspace.user_id != current_user.id:
        raise HTTPException(status_code=403)
    endpoint = f"{settings.public_base_url}/ws/{workspace.name}/mcp"
    snippet = {
        "servers": {
            f"gitfs-{workspace.name}": {
                "type": "http",
                "url": endpoint,
                "headers": {"Authorization": "Bearer ${input:mcp_token}"},
            }
        },
        "inputs": [
            {
                "id": "mcp_token",
                "type": "promptString",
                "description": "Workspace MCP API token",
                "password": True,
            },
            {
                "id": "gitlab_endpoint",
                "type": "promptString",
                "description": "GitLab API base URL (e.g. https://gitlab.com/api/v4)",
                "password": False,
            },
            {
                "id": "gitlab_token",
                "type": "promptString",
                "description": "GitLab personal access token",
                "password": True,
            },
        ],
    }
    return templates.TemplateResponse(
        "workspace_details.html",
        {"request": request, "workspace": workspace, "endpoint": endpoint, "snippet": snippet},
    )


@app.post("/workspaces/{workspace_id}/delete")
def delete_workspace(
    request: Request,
    workspace_id: int,
    csrf_token: str | None = Form(None, alias="csrf_token"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RedirectResponse:
    try:
        _validate_csrf_token(request, csrf_token)
    except HTTPException:
        request.session["message"] = "Invalid security token. Please refresh the page."
        return RedirectResponse("/workspaces", status_code=303)
    
    workspace = db.execute(select(Workspace).where(Workspace.id == workspace_id)).scalar_one_or_none()
    if not workspace:
        raise HTTPException(status_code=404)
    if current_user.role != "admin" and workspace.user_id != current_user.id:
        raise HTTPException(status_code=403)
    provisioner = WorkspaceProvisioner()
    services.soft_delete_workspace(db, provisioner, workspace)
    request.session["message"] = f"Workspace '{workspace.name}' deleted (soft)."
    # Audit log workspace deletion
    services.audit_log(
        user_id=current_user.id,
        action="workspace_deleted",
        resource=f"workspace:{workspace.id}",
        details={"name": workspace.name}
    )
    return RedirectResponse("/workspaces", status_code=303)


@app.get("/keys", response_class=HTMLResponse)
def api_keys_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    if current_user.role == "admin":
        keys = db.execute(select(ApiKey).order_by(ApiKey.created_at.desc())).scalars().all()
    else:
        keys = current_user.api_keys
    csrf_token = _get_csrf_token(request)
    return templates.TemplateResponse(
        "keys.html",
        {
            "request": request,
            "user": current_user,
            "keys": keys,
            "is_admin": current_user.role == "admin",
            "token": request.session.pop("token", None),
            "message": request.session.pop("message", None),
            "csrf_token": csrf_token,
        },
    )


@app.post("/keys")
def create_api_key_route(
    request: Request,
    csrf_token: str | None = Form(None, alias="csrf_token"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RedirectResponse:
    try:
        _validate_csrf_token(request, csrf_token)
    except HTTPException:
        request.session["message"] = "Invalid security token. Please refresh the page."
        return RedirectResponse("/keys", status_code=303)
    
    api_key, token = services.create_api_key(db, current_user)
    request.session["token"] = token
    request.session["message"] = "API key created. Copy it now; it will not be shown again."
    # Audit log API key creation
    services.audit_log(
        user_id=current_user.id,
        action="api_key_created",
        resource=f"api_key:{api_key.id}",
        details={"target_user_id": current_user.id, "key_prefix": api_key.key_prefix}
    )
    return RedirectResponse("/keys", status_code=303)


@app.post("/keys/{key_id}/delete")
def delete_api_key(
    request: Request,
    key_id: int,
    csrf_token: str | None = Form(None, alias="csrf_token"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RedirectResponse:
    try:
        _validate_csrf_token(request, csrf_token)
    except HTTPException:
        request.session["message"] = "Invalid security token. Please refresh the page."
        return RedirectResponse("/keys", status_code=303)
    
    if current_user.role == "admin":
        key = db.execute(select(ApiKey).where(ApiKey.id == key_id)).scalar_one_or_none()
    else:
        key = next((item for item in current_user.api_keys if item.id == key_id), None)
    if key is None:
        raise HTTPException(status_code=404)
    db.delete(key)
    db.commit()
    request.session["message"] = "API key deleted."
    # Audit log API key deletion
    services.audit_log(
        user_id=current_user.id,
        action="api_key_deleted",
        resource=f"api_key:{key_id}",
        details={"target_user_id": key.user_id if hasattr(key, 'user_id') else None}
    )
    return RedirectResponse("/keys", status_code=303)


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users_page(
    request: Request,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    session_user = require_admin_user(request, db)
    users = db.execute(select(User).order_by(User.created_at.desc())).scalars().all()
    csrf_token = _get_csrf_token(request)
    return templates.TemplateResponse(
        "admin_users.html",
        {
            "request": request,
            "user": session_user,
            "users": users,
            "message": request.session.pop("message", None),
            "csrf_token": csrf_token,
        },
    )


@app.post("/admin/users")
def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("user"),
    csrf_token: str | None = Form(None, alias="csrf_token"),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    try:
        _validate_csrf_token(request, csrf_token)
    except HTTPException:
        request.session["message"] = "Invalid security token. Please refresh the page."
        return RedirectResponse("/admin/users", status_code=303)
    
    require_admin_user(request, db)
    existing = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if existing:
        request.session["message"] = "User already exists."
        return RedirectResponse("/admin/users", status_code=303)
    user = User(username=username, password_hash=auth.hash_password(password), role=role)
    db.add(user)
    db.commit()
    request.session["message"] = f"User '{username}' created."
    # Audit log user creation
    services.audit_log(
        user_id=require_admin_user(request, db).id,
        action="user_created",
        resource=f"user:{user.id}",
        details={"target_username": username, "target_role": role}
    )
    return RedirectResponse("/admin/users", status_code=303)


@app.post("/admin/users/{user_id}/deactivate")
def deactivate_user(
    request: Request,
    user_id: int,
    csrf_token: str | None = Form(None, alias="csrf_token"),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    try:
        _validate_csrf_token(request, csrf_token)
    except HTTPException:
        request.session["message"] = "Invalid security token. Please refresh the page."
        return RedirectResponse("/admin/users", status_code=303)
    
    current_admin = require_admin_user(request, db)
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404)
    if user.id == current_admin.id:
        raise HTTPException(status_code=400, detail="Admins cannot deactivate their own account.")
    if user.role == "admin":
        remaining_admin = db.execute(
            select(User).where(
                User.role == "admin",
                User.status == "active",
                User.id != user.id,
            )
        ).scalar_one_or_none()
        if not remaining_admin:
            raise HTTPException(status_code=400, detail="Cannot deactivate the last active admin.")
    provisioner = WorkspaceProvisioner()
    services.deactivate_user(db, provisioner, user)
    request.session["message"] = f"User '{user.username}' deactivated."
    # Audit log user deactivation
    services.audit_log(
        user_id=current_admin.id,
        action="user_deactivated",
        resource=f"user:{user_id}",
        details={"target_username": user.username, "target_role": user.role}
    )
    return RedirectResponse("/admin/users", status_code=303)


@app.post("/internal/auth/introspect")
def introspect(
    request: Request,
    payload: dict[str, str],
    db: Session = Depends(get_db),
    x_introspect_secret: str | None = Header(None, alias="X-Introspect-Secret"),
) -> dict[str, Any]:
    """Introspect an API token. Only accessible from internal networks.
    
    Security: Requires request from internal IP and optional secret header.
    """
    client_ip = _get_client_ip(request)
    
    # Check if request is from internal network
    if not _is_internal_ip(client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: external source"
        )
    
    # If INTROSPECT_SECRET is configured, require it
    global INTROSPECT_SECRET
    if INTROSPECT_SECRET and x_introspect_secret != INTROSPECT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing introspect secret"
        )
    
    token = payload.get("token", "")
    return services.introspect_token(db, token)


# ============================================================================
# API v1 Endpoints
# ============================================================================

def api_response(data: Any, meta: dict | None = None) -> dict:
    """Create a wrapped API response with data and optional metadata.
    
    Args:
        data: The response data
        meta: Optional metadata (pagination, etc.)
        
    Returns:
        Wrapped response dictionary
    """
    response: dict[str, Any] = {"data": data}
    if meta:
        response["meta"] = meta
    return response


# ----------------------------------------------------------------------------
# User Endpoints
# ----------------------------------------------------------------------------

@app.get("/api/v1/users")
async def list_users_endpoint(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: str | None = None,
    role: str | None = None,
    current_user: User = Depends(auth.get_current_user_unified),
    db: Session = Depends(get_db),
) -> dict:
    """List users with pagination and filtering.
    
    - Admin sees all users
    - Regular user sees only self
    """
    if current_user.role == "admin":
        users, total = services.list_users(db, page=page, per_page=per_page, status=status, role=role)
    else:
        # Regular user only sees themselves
        users = [current_user]
        total = 1
    
    # Serialize user data
    user_list = []
    for user in users:
        user_data = {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "status": user.status,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "updated_at": user.updated_at.isoformat() if user.updated_at else None,
            "nexusgate_user_id": user.nexusgate_user_id,
            "nexusgate_role": user.nexusgate_role,
        }
        user_list.append(user_data)
    
    # Build pagination metadata
    meta = {
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": (total + per_page - 1) // per_page,
        }
    }
    
    return api_response({"users": user_list}, meta)


@app.get("/api/v1/users/{user_id}")
async def get_user_endpoint(
    user_id: int,
    current_user: User = Depends(auth.get_current_user_unified),
    db: Session = Depends(get_db),
) -> dict:
    """Get a specific user by ID.
    
    - Admin or self can access
    - Includes workspaces list and api_keys list (prefix only)
    """
    # Check permissions: admin or self
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Build workspaces list
    workspaces = []
    for ws in user.workspaces:
        workspaces.append({
            "id": ws.id,
            "name": ws.name,
            "status": ws.status,
            "created_at": ws.created_at.isoformat() if ws.created_at else None,
            "nexusgate_service_id": ws.nexusgate_service_id,
        })
    
    # Build API keys list (prefix only, never expose hash)
    api_keys = []
    for key in user.api_keys:
        api_keys.append({
            "id": key.id,
            "prefix": key.key_prefix,
            "name": key.name,
            "created_at": key.created_at.isoformat() if key.created_at else None,
            "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
            "nexusgate_token_id": key.nexusgate_token_id,
        })
    
    user_data = {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "status": user.status,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
        "nexusgate_user_id": user.nexusgate_user_id,
        "nexusgate_role": user.nexusgate_role,
        "workspaces": workspaces,
        "api_keys": api_keys,
    }
    
    return api_response(user_data)


@app.put("/api/v1/users/{user_id}")
async def update_user_endpoint(
    user_id: int,
    data: dict = Body(...),
    current_user: User = Depends(auth.require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """Update a user.
    
    - Admin only
    - Prevent self-demotion from admin
    - Check for last admin before deactivation
    """
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    new_role = data.get("role")
    new_status = data.get("status")
    
    # Prevent self-demotion from admin
    if user.id == current_user.id and new_role is not None and new_role != "admin":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot demote yourself from admin"
        )
    
    # Check for last admin before deactivation or role change
    if new_status == "inactive" or (new_role is not None and new_role != "admin"):
        if user.role == "admin":
            remaining_admin = db.execute(
                select(User).where(
                    User.role == "admin",
                    User.status == "active",
                    User.id != user.id,
                )
            ).scalar_one_or_none()
            if not remaining_admin:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot deactivate or demote the last active admin"
                )
    
    # Update user
    updated_user = services.update_user(
        db,
        user,
        role=new_role,
        status=new_status,
        nexusgate_user_id=data.get("nexusgate_user_id"),
    )
    
    user_data = {
        "id": updated_user.id,
        "username": updated_user.username,
        "role": updated_user.role,
        "status": updated_user.status,
        "updated_at": updated_user.updated_at.isoformat() if updated_user.updated_at else None,
        "nexusgate_user_id": updated_user.nexusgate_user_id,
    }
    
    return api_response(user_data)


@app.delete("/api/v1/users/{user_id}")
async def delete_user_endpoint(
    user_id: int,
    current_user: User = Depends(auth.require_admin),
    db: Session = Depends(get_db),
) -> dict:
    """Deactivate (soft delete) a user.
    
    - Admin only
    - Prevent self-deactivation
    """
    # Prevent self-deactivation
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account"
        )
    
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check for last admin
    if user.role == "admin":
        remaining_admin = db.execute(
            select(User).where(
                User.role == "admin",
                User.status == "active",
                User.id != user.id,
            )
        ).scalar_one_or_none()
        if not remaining_admin:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot deactivate the last active admin"
            )
    
    provisioner = WorkspaceProvisioner()
    services.deactivate_user(db, provisioner, user)
    
    # Audit log user deactivation via API
    services.audit_log(
        user_id=current_user.id,
        action="user_deactivated",
        resource=f"user:{user_id}",
        details={"target_username": user.username, "via": "api_v1"}
    )
    
    return api_response({"message": f"User '{user.username}' deactivated"})


# ----------------------------------------------------------------------------
# Workspace Endpoints
# ----------------------------------------------------------------------------

@app.get("/api/v1/workspaces")
async def list_workspaces_endpoint(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: str | None = None,
    user_id: int | None = None,
    current_user: User = Depends(auth.get_current_user_unified),
    db: Session = Depends(get_db),
) -> dict:
    """List workspaces with pagination and filtering.
    
    - Admin sees all workspaces
    - Regular user sees only own workspaces
    - Deleted workspaces are filtered out by default
    """
    # Non-admin can only filter by own user_id
    if current_user.role != "admin":
        user_id = current_user.id
    elif user_id is not None:
        # Admin can filter by specific user
        pass
    
    # Filter out deleted by default
    include_deleted = False
    
    workspaces, total = services.list_workspaces(
        db,
        user_id=user_id,
        page=page,
        per_page=per_page,
        include_deleted=include_deleted,
    )
    
    # Build workspace list with endpoint_url
    workspace_list = []
    for ws in workspaces:
        if status and ws.status != status:
            continue
        ws_data = {
            "id": ws.id,
            "name": ws.name,
            "status": ws.status,
            "user_id": ws.user_id,
            "created_at": ws.created_at.isoformat() if ws.created_at else None,
            "updated_at": ws.updated_at.isoformat() if ws.updated_at else None,
            "endpoint_url": f"{settings.public_base_url}/ws/{ws.name}/mcp",
            "nexusgate_service_id": ws.nexusgate_service_id,
            "metadata": ws.metadata,
        }
        workspace_list.append(ws_data)
    
    # Recalculate total after status filter
    if status:
        total = len(workspace_list)
    
    meta = {
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": (total + per_page - 1) // per_page,
        }
    }
    
    return api_response({"workspaces": workspace_list}, meta)


@app.post("/api/v1/workspaces", status_code=status.HTTP_201_CREATED)
async def create_workspace_endpoint(
    request: Request,
    data: dict = Body(...),
    current_user: User = Depends(auth.get_current_user_unified),
    db: Session = Depends(get_db),
) -> dict:
    """Create a new workspace.
    
    - Body: name (required), metadata (optional)
    - Validates name format (alphanumeric, hyphens)
    """
    name = data.get("name", "").strip()
    metadata = data.get("metadata")
    
    if not name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Workspace name is required"
        )
    
    # Validate name format
    import re
    if not re.match(r'^[a-zA-Z0-9._-]{1,128}$', name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Name must match pattern: alphanumeric, hyphens, dots, underscores (1-128 chars)"
        )
    
    provisioner = WorkspaceProvisioner()
    
    try:
        workspace = services.create_workspace_api(
            db, provisioner, current_user, name, metadata=metadata
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    
    workspace_data = {
        "id": workspace.id,
        "name": workspace.name,
        "status": workspace.status,
        "user_id": workspace.user_id,
        "created_at": workspace.created_at.isoformat() if workspace.created_at else None,
        "updated_at": workspace.updated_at.isoformat() if workspace.updated_at else None,
        "metadata": workspace.metadata,
        "nexusgate_service_id": workspace.nexusgate_service_id,
        "endpoint_url": f"{settings.public_base_url}/ws/{workspace.name}/mcp",
    }
    
    # Audit log workspace creation via API
    services.audit_log(
        user_id=current_user.id,
        action="workspace_created",
        resource=f"workspace:{workspace.id}",
        details={"name": name, "via": "api_v1"}
    )
    
    return api_response(workspace_data)


@app.get("/api/v1/workspaces/{workspace_id}")
async def get_workspace_endpoint(
    workspace_id: int,
    current_user: User = Depends(auth.get_current_user_unified),
    db: Session = Depends(get_db),
) -> dict:
    """Get a specific workspace by ID.
    
    - Admin or owner access
    - Includes metadata and nexusgate_service_id
    """
    workspace = db.execute(
        select(Workspace).where(Workspace.id == workspace_id)
    ).scalar_one_or_none()
    
    if not workspace:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workspace not found"
        )
    
    # Check permissions: admin or owner
    if current_user.role != "admin" and workspace.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    workspace_data = {
        "id": workspace.id,
        "name": workspace.name,
        "status": workspace.status,
        "user_id": workspace.user_id,
        "created_at": workspace.created_at.isoformat() if workspace.created_at else None,
        "updated_at": workspace.updated_at.isoformat() if workspace.updated_at else None,
        "deleted_at": workspace.deleted_at.isoformat() if workspace.deleted_at else None,
        "metadata": workspace.metadata,
        "nexusgate_service_id": workspace.nexusgate_service_id,
        "container_id": workspace.container_id,
        "container_status": workspace.container_status,
        "endpoint_url": f"{settings.public_base_url}/ws/{workspace.name}/mcp",
    }
    
    return api_response(workspace_data)


@app.delete("/api/v1/workspaces/{workspace_id}")
async def delete_workspace_endpoint(
    workspace_id: int,
    current_user: User = Depends(auth.get_current_user_unified),
    db: Session = Depends(get_db),
) -> dict:
    """Soft delete a workspace.
    
    - Admin or owner access
    """
    workspace = db.execute(
        select(Workspace).where(Workspace.id == workspace_id)
    ).scalar_one_or_none()
    
    if not workspace:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workspace not found"
        )
    
    # Check permissions: admin or owner
    if current_user.role != "admin" and workspace.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    provisioner = WorkspaceProvisioner()
    services.soft_delete_workspace(db, provisioner, workspace)
    
    # Audit log workspace deletion via API
    services.audit_log(
        user_id=current_user.id,
        action="workspace_deleted",
        resource=f"workspace:{workspace_id}",
        details={"name": workspace.name, "via": "api_v1"}
    )
    
    return api_response({"message": f"Workspace '{workspace.name}' deleted"})


# ----------------------------------------------------------------------------
# API Key Endpoints
# ----------------------------------------------------------------------------

@app.get("/api/v1/api-keys")
async def list_api_keys_endpoint(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    user_id: int | None = None,
    current_user: User = Depends(auth.get_current_user_unified),
    db: Session = Depends(get_db),
) -> dict:
    """List API keys with pagination.
    
    - Admin sees all API keys
    - Regular user sees only own keys
    - Includes last_used_at, nexusgate_token_id
    """
    # Non-admin can only see own keys
    if current_user.role != "admin":
        user_id = current_user.id
    
    api_keys, total = services.list_api_keys(
        db, user_id=user_id, page=page, per_page=per_page
    )
    
    # Build API key list (never expose full key hash)
    key_list = []
    for key in api_keys:
        key_data = {
            "id": key.id,
            "prefix": key.key_prefix,
            "name": key.name,
            "user_id": key.user_id,
            "created_at": key.created_at.isoformat() if key.created_at else None,
            "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
            "nexusgate_token_id": key.nexusgate_token_id,
            "expires_at": key.expires_at.isoformat() if key.expires_at else None,
        }
        key_list.append(key_data)
    
    meta = {
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": (total + per_page - 1) // per_page,
        }
    }
    
    return api_response({"api_keys": key_list}, meta)


@app.post("/api/v1/api-keys", status_code=status.HTTP_201_CREATED)
async def create_api_key_endpoint(
    request: Request,
    data: dict = Body(...),
    current_user: User = Depends(auth.get_current_user_unified),
    db: Session = Depends(get_db),
) -> dict:
    """Create a new API key.
    
    - Body: name (optional), user_id (optional, admin only)
    - Non-admin can only create for self
    - Returns full key (shown once) with warning
    """
    name = data.get("name")
    target_user_id = data.get("user_id")
    
    # Determine target user
    if target_user_id is not None:
        if current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admins can create API keys for other users"
            )
        target_user = db.execute(
            select(User).where(User.id == target_user_id)
        ).scalar_one_or_none()
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target user not found"
            )
    else:
        target_user = current_user
    
    api_key, raw_token = services.create_api_key(db, target_user, name=name)
    
    # Audit log API key creation via API
    services.audit_log(
        user_id=current_user.id,
        action="api_key_created",
        resource=f"api_key:{api_key.id}",
        details={"target_user_id": target_user.id, "via": "api_v1", "name": name}
    )
    
    key_data = {
        "id": api_key.id,
        "prefix": api_key.key_prefix,
        "name": api_key.name,
        "user_id": api_key.user_id,
        "created_at": api_key.created_at.isoformat() if api_key.created_at else None,
        "token": raw_token,  # Full token shown once
        "warning": "This token will not be shown again. Store it securely.",
    }
    
    return api_response(key_data)


@app.delete("/api/v1/api-keys/{key_id}")
async def delete_api_key_endpoint(
    key_id: int,
    current_user: User = Depends(auth.get_current_user_unified),
    db: Session = Depends(get_db),
) -> dict:
    """Revoke (delete) an API key.
    
    - Admin or owner access
    """
    # Find the key
    if current_user.role == "admin":
        api_key = db.execute(
            select(ApiKey).where(ApiKey.id == key_id)
        ).scalar_one_or_none()
    else:
        api_key = db.execute(
            select(ApiKey).where(
                ApiKey.id == key_id,
                ApiKey.user_id == current_user.id,
            )
        ).scalar_one_or_none()
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )
    
    services.revoke_api_key(db, api_key)
    
    # Audit log API key deletion via API
    services.audit_log(
        user_id=current_user.id,
        action="api_key_deleted",
        resource=f"api_key:{key_id}",
        details={"target_user_id": api_key.user_id, "via": "api_v1"}
    )
    
    return api_response({"message": "API key revoked"})


# ----------------------------------------------------------------------------
# Authentication Endpoints
# ----------------------------------------------------------------------------

@app.post("/api/v1/auth/introspect")
async def introspect_endpoint(
    payload: dict = Body(...),
    x_introspect_secret: str | None = Header(None, alias="X-Introspect-Secret"),
    db: Session = Depends(get_db),
) -> dict:
    """Introspect an API token.
    
    - Validates optional introspect_secret if configured
    - Tries API key introspection (mcp_* prefix)
    - Tries JWT introspection
    - Returns RFC 7662 compliant response
    """
    # If introspect_secret is configured, validate it
    if settings.introspect_secret and x_introspect_secret != settings.introspect_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing introspect secret"
        )
    
    token = payload.get("token", "")
    if not token:
        return {"active": False}
    
    # Try API key introspection (mcp_* prefix)
    if token.startswith("mcp_"):
        result = services.introspect_token(db, token)
        if result.get("active"):
            return {
                "active": True,
                "sub": result.get("user_id"),
                "username": db.execute(
                    select(User).where(User.id == int(result.get("user_id", 0)))
                ).scalar_one_or_none().username if result.get("user_id") else None,
                "role": result.get("role"),
                "token_type": "api_key",
            }
    
    # Try JWT introspection
    try:
        jwt_payload = auth.verify_access_token(token)
        return {
            "active": True,
            "sub": jwt_payload.get("sub"),
            "username": jwt_payload.get("username"),
            "role": jwt_payload.get("role"),
            "token_type": "jwt",
            "exp": jwt_payload.get("exp"),
        }
    except HTTPException:
        pass
    
    return {"active": False}


# ----------------------------------------------------------------------------
# Health Endpoint
# ----------------------------------------------------------------------------

@app.get("/api/v1/health")
async def health_endpoint(
    db: Session = Depends(get_db),
) -> dict:
    """Health check endpoint.
    
    - No authentication required
    - Checks database connectivity and measures response time
    - Checks Docker daemon connectivity and gets version
    - Gets workspace statistics
    - Returns status: healthy/degraded/unhealthy
    """
    from sqlalchemy import text
    import docker
    import time
    
    checks = {
        "database": {"healthy": False, "response_time_ms": None},
        "docker": {"healthy": False, "version": None},
    }
    workspace_stats = {
        "total": 0,
        "active": 0,
    }
    
    # Check database connectivity and measure response time
    try:
        start_time = time.time()
        db.execute(text("SELECT 1"))
        db_response_time = round((time.time() - start_time) * 1000, 2)  # Convert to ms, round to 2 decimals
        checks["database"]["healthy"] = True
        checks["database"]["response_time_ms"] = db_response_time
        
        # Get workspace statistics
        workspace_stats["total"] = db.execute(
            select(func.count(Workspace.id))
        ).scalar_one()
        workspace_stats["active"] = db.execute(
            select(func.count(Workspace.id)).where(Workspace.status == "active")
        ).scalar_one()
    except Exception as e:
        logger.warning("Health check: Database query failed: %s", e)
    
    # Check Docker daemon connectivity and get version
    try:
        docker_client = docker.from_env()
        version_info = docker_client.version()
        checks["docker"]["healthy"] = True
        # Extract version from version info (format varies by Docker API version)
        if isinstance(version_info, dict):
            checks["docker"]["version"] = version_info.get("Version") or version_info.get("version")
        else:
            checks["docker"]["version"] = str(version_info)
    except Exception as e:
        logger.warning("Health check: Docker connection failed: %s", e)
    
    # Determine overall status
    db_healthy = checks["database"]["healthy"]
    docker_healthy = checks["docker"]["healthy"]
    
    if db_healthy and docker_healthy:
        status_str = "healthy"
        status_code = status.HTTP_200_OK
    elif db_healthy:  # Database is critical
        status_str = "degraded"
        status_code = status.HTTP_200_OK
    else:
        status_str = "unhealthy"
        status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    
    response = {
        "status": status_str,
        "checks": checks,
        "workspaces": workspace_stats,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    
    return JSONResponse(content=response, status_code=status_code)


# ----------------------------------------------------------------------------
# MCP Bridge Endpoints
# ----------------------------------------------------------------------------

# Static list of available MCP tools
MCP_TOOLS = [
    {"name": "list_repositories", "description": "List available repositories in the workspace"},
    {"name": "read_file", "description": "Read a file from the workspace"},
    {"name": "write_file", "description": "Write a file to the workspace"},
    {"name": "search_code", "description": "Search for code patterns in the workspace"},
    {"name": "execute_command", "description": "Execute a command in the workspace context"},
    {"name": "git_status", "description": "Get git status for the workspace"},
    {"name": "git_clone", "description": "Clone a git repository into the workspace"},
]


@app.get("/api/v1/mcp/tools")
async def list_mcp_tools(
    workspace_id: int | None = None,
    current_user: User = Depends(auth.get_current_user_unified),
    db: Session = Depends(get_db),
) -> dict:
    """List available MCP tools.
    
    - Query param: workspace_id (optional)
    - Returns static list of available MCP tools
    """
    # If workspace_id is provided, verify access
    if workspace_id is not None:
        workspace = db.execute(
            select(Workspace).where(Workspace.id == workspace_id)
        ).scalar_one_or_none()
        
        if not workspace:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Workspace not found"
            )
        
        if current_user.role != "admin" and workspace.user_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )
    
    return api_response({"tools": MCP_TOOLS})


@app.post("/api/v1/mcp/invoke")
async def invoke_mcp_tool(
    data: dict = Body(...),
    current_user: User = Depends(auth.get_current_user_unified),
    db: Session = Depends(get_db),
) -> dict:
    """Invoke an MCP tool.
    
    - Body: workspace_id (required), tool (required)
    - Validates workspace exists
    - Checks permissions (admin or owner)
    - Returns placeholder result for now
    """
    workspace_id = data.get("workspace_id")
    tool = data.get("tool")
    params = data.get("params", {})
    
    if not workspace_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="workspace_id is required"
        )
    
    if not tool:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="tool is required"
        )
    
    # Validate workspace exists
    workspace = db.execute(
        select(Workspace).where(Workspace.id == workspace_id)
    ).scalar_one_or_none()
    
    if not workspace:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workspace not found"
        )
    
    # Check permissions: admin or owner
    if current_user.role != "admin" and workspace.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Validate tool exists
    if tool not in [t["name"] for t in MCP_TOOLS]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown tool: {tool}"
        )
    
    # Placeholder implementation - actual implementation would route to workspace MCP
    result = {
        "tool": tool,
        "workspace_id": workspace_id,
        "status": "pending",
        "message": "Tool invocation is handled by the workspace MCP server. Use the workspace endpoint directly.",
        "endpoint": f"{settings.public_base_url}/ws/{workspace.name}/mcp",
        "params_received": params,
    }
    
    return api_response(result)


# ----------------------------------------------------------------------------
# Admin Database Management Endpoints
# ----------------------------------------------------------------------------

@app.post("/api/v1/admin/database/backup")
async def admin_database_backup(
    current_user: User = Depends(auth.require_admin),
) -> dict:
    """Trigger a database backup.
    
    - Admin access only
    - Creates a timestamped backup of the SQLite database
    - Returns the path to the created backup file
    """
    try:
        backup_path = backup_database()
        
        # Audit log backup creation
        services.audit_log(
            user_id=current_user.id,
            action="database_backup_created",
            resource="database",
            details={"backup_path": str(backup_path)}
        )
        
        return api_response({
            "message": "Database backup created successfully",
            "backup_path": str(backup_path),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Database file not found: {e}"
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.exception("Failed to create database backup")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create backup: {str(e)}"
        )


@app.get("/api/v1/admin/database/verify")
async def admin_database_verify(
    current_user: User = Depends(auth.require_admin),
) -> dict:
    """Verify database schema integrity.
    
    - Admin access only
    - Checks that all expected tables exist
    - Verifies required columns are present in each table
    - Returns validation results
    """
    try:
        result = verify_database_schema()
        
        # Audit log verification
        services.audit_log(
            user_id=current_user.id,
            action="database_schema_verified",
            resource="database",
            details={
                "valid": result.get("valid"),
                "tables_checked": len(result.get("tables_checked", [])),
                "issues_found": len(result.get("issues", [])),
            }
        )
        
        return api_response({
            "valid": result.get("valid"),
            "issues": result.get("issues", []),
            "tables_checked": result.get("tables_checked", []),
            "tables_found": result.get("tables_found", []),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as e:
        logger.exception("Failed to verify database schema")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to verify schema: {str(e)}"
        )


@app.get("/api/v1/admin/database/health")
async def admin_database_health(
    current_user: User = Depends(auth.require_admin),
) -> dict:
    """Check database connectivity and health.
    
    - Admin access only
    - Tests database connection
    - Measures response time
    - Returns connectivity status
    """
    try:
        result = test_database_connectivity()
        
        # Audit log health check
        services.audit_log(
            user_id=current_user.id,
            action="database_health_checked",
            resource="database",
            details={
                "connected": result.get("connected"),
                "response_time_ms": result.get("response_time_ms"),
            }
        )
        
        response_data = {
            "connected": result.get("connected"),
            "response_time_ms": result.get("response_time_ms"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        if result.get("error"):
            response_data["error"] = result.get("error")
        
        return api_response(response_data)
    except Exception as e:
        logger.exception("Failed to check database health")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to check health: {str(e)}"
        )
