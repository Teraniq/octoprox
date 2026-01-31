from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import Any

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from . import auth, services
from .db import SessionLocal, get_db, init_db
from .models import ApiKey, User, Workspace
from .provisioning import WorkspaceProvisioner
from .settings import settings

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax")
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

rate_limit: dict[str, list[datetime]] = {}


def _clean_attempts(attempts: list[datetime], window: timedelta) -> list[datetime]:
    cutoff = datetime.utcnow() - window
    return [entry for entry in attempts if entry > cutoff]


def check_rate_limit(ip: str, max_attempts: int = 5, window_minutes: int = 5) -> bool:
    window = timedelta(minutes=window_minutes)
    attempts = rate_limit.get(ip, [])
    attempts = _clean_attempts(attempts, window)
    if len(attempts) >= max_attempts:
        rate_limit[ip] = attempts
        return False
    attempts.append(datetime.utcnow())
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
    while True:
        await asyncio.sleep(settings.purge_interval_seconds)
        with SessionLocal() as db:
            provisioner = WorkspaceProvisioner()
            services.purge_due_workspaces(db, provisioner)


@app.on_event("startup")
async def startup_event() -> None:
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
    asyncio.create_task(purge_loop())


@app.get("/", response_class=HTMLResponse)
def root(request: Request) -> HTMLResponse:
    require_login(request)
    return RedirectResponse("/workspaces", status_code=302)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    ip = request.client.host if request.client else "unknown"
    if not check_rate_limit(ip):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Too many attempts. Try again later."},
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
    request.session["user"] = {"id": user.id, "username": user.username, "role": user.role}
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
    context = {
        "request": request,
        "user": current_user,
        "workspaces": workspaces,
        "public_base_url": settings.public_base_url,
        "message": request.session.pop("message", None),
        "token": request.session.pop("token", None),
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
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RedirectResponse:
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
            }
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
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RedirectResponse:
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
    return templates.TemplateResponse(
        "keys.html",
        {
            "request": request,
            "user": current_user,
            "keys": keys,
            "is_admin": current_user.role == "admin",
            "token": request.session.pop("token", None),
            "message": request.session.pop("message", None),
        },
    )


@app.post("/keys")
def create_api_key_route(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RedirectResponse:
    _, token = services.create_api_key(db, current_user)
    request.session["token"] = token
    request.session["message"] = "API key created. Copy it now; it will not be shown again."
    return RedirectResponse("/keys", status_code=303)


@app.post("/keys/{key_id}/delete")
def delete_api_key(
    request: Request,
    key_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RedirectResponse:
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
    return templates.TemplateResponse(
        "admin_users.html",
        {
            "request": request,
            "user": session_user,
            "users": users,
            "message": request.session.pop("message", None),
        },
    )


@app.post("/admin/users")
def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("user"),
    db: Session = Depends(get_db),
) -> RedirectResponse:
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
    db: Session = Depends(get_db),
) -> RedirectResponse:
    require_admin_user(request, db)
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404)
    provisioner = WorkspaceProvisioner()
    services.deactivate_user(db, provisioner, user)
    request.session["message"] = f"User '{user.username}' deactivated."
    return RedirectResponse("/admin/users", status_code=303)


@app.post("/internal/auth/introspect")
def introspect(
    payload: dict[str, str],
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    token = payload.get("token", "")
    return services.introspect_token(db, token)
