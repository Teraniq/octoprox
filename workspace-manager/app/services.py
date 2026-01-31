from __future__ import annotations

from datetime import datetime, timedelta
import re
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth
from .models import ApiKey, User, Workspace
from .provisioning import WorkspaceProvisioner

WORKSPACE_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")


def validate_workspace_name(db: Session, name: str) -> tuple[bool, str]:
    if not WORKSPACE_NAME_RE.match(name):
        return False, "Name must match ^[a-zA-Z0-9._-]{1,128}$"
    exists = db.execute(select(Workspace).where(Workspace.name == name)).scalar_one_or_none()
    if exists:
        return False, "Name already exists"
    return True, "Name is available"


def create_api_key(db: Session, user: User) -> tuple[ApiKey, str]:
    payload = auth.generate_api_key()
    key = ApiKey(user_id=user.id, key_prefix=payload.prefix, key_hash=payload.hash)
    db.add(key)
    db.commit()
    db.refresh(key)
    return key, payload.token


def create_workspace(
    db: Session,
    provisioner: WorkspaceProvisioner,
    user: User,
    name: str,
) -> Workspace:
    ok, message = validate_workspace_name(db, name)
    if not ok:
        raise ValueError(message)
    workspace = Workspace(user_id=user.id, name=name, status="active")
    db.add(workspace)
    db.commit()
    db.refresh(workspace)
    try:
        provisioner.create_workspace(workspace)
    except Exception:
        db.delete(workspace)
        db.commit()
        raise
    return workspace


def soft_delete_workspace(
    db: Session,
    provisioner: WorkspaceProvisioner,
    workspace: Workspace,
    purge_after_hours: int = 24,
) -> None:
    if workspace.status == "deleted":
        return
    workspace.status = "deleted"
    workspace.deleted_at = datetime.utcnow()
    workspace.purge_after = datetime.utcnow() + timedelta(hours=purge_after_hours)
    db.add(workspace)
    db.commit()
    provisioner.delete_workspace(workspace)


def purge_due_workspaces(
    db: Session,
    provisioner: WorkspaceProvisioner,
    now: datetime | None = None,
) -> list[str]:
    now = now or datetime.utcnow()
    due = db.execute(
        select(Workspace).where(
            Workspace.status == "deleted",
            Workspace.purge_after.is_not(None),
            Workspace.purge_after <= now,
        )
    ).scalars()
    removed: list[str] = []
    for workspace in list(due):
        provisioner.purge_workspace(workspace)
        removed.append(workspace.name)
        db.delete(workspace)
    if removed:
        db.commit()
    return removed


def delete_user(
    db: Session,
    provisioner: WorkspaceProvisioner,
    user: User,
) -> None:
    raise NotImplementedError("Users are no longer deleted; use deactivate_user.")


def deactivate_user(
    db: Session,
    provisioner: WorkspaceProvisioner,
    user: User,
) -> None:
    workspaces: Iterable[Workspace] = list(user.workspaces)
    for workspace in workspaces:
        if workspace.status == "active":
            workspace.status = "inactive"
            workspace.deleted_at = datetime.utcnow()
        provisioner.delete_workspace(workspace)
    user.status = "inactive"
    db.add(user)
    db.commit()


def introspect_token(db: Session, token: str) -> dict:
    prefix = auth.extract_prefix(token)
    if not prefix:
        return {"active": False}
    keys = db.execute(select(ApiKey).where(ApiKey.key_prefix == prefix)).scalars().all()
    for key in keys:
        if auth.verify_api_key(token, key.key_hash):
            if key.user.status != "active":
                return {"active": False}
            return {"active": True, "user_id": str(key.user_id), "role": key.user.role}
    return {"active": False}
