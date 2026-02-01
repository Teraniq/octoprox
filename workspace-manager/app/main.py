from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime, timedelta, timezone
import ipaddress
from typing import Any

from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from . import auth, services
from .db import SessionLocal, get_db, init_db, engine
from .models import ApiKey, User, Workspace
from .provisioning import WorkspaceProvisioner
from .settings import settings

# Configure logging
logger = logging.getLogger(__name__)

app = FastAPI()
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
        services.create_workspace(db, provisioner, current_user, name)
        request.session["message"] = f"Workspace '{name}' created."
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
    
    _, token = services.create_api_key(db, current_user)
    request.session["token"] = token
    request.session["message"] = "API key created. Copy it now; it will not be shown again."
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
