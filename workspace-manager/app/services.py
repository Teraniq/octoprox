from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
import re
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth
from .models import ApiKey, User, Workspace
from .provisioning import WorkspaceProvisioner

logger = logging.getLogger(__name__)

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
    try:
        db.commit()
        db.refresh(key)
    except Exception:
        db.rollback()
        raise
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
    try:
        db.commit()
        db.refresh(workspace)
    except Exception:
        db.rollback()
        raise
    
    try:
        provisioner.create_workspace(workspace)
    except Exception:
        # Rollback on provisioning failure
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
    workspace.deleted_at = datetime.now(timezone.utc)
    workspace.purge_after = datetime.now(timezone.utc) + timedelta(hours=purge_after_hours)
    db.add(workspace)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    try:
        provisioner.delete_workspace(workspace)
    except Exception as e:
        # Log but don't re-raise - workspace is already marked deleted
        # The purge job will retry cleanup later
        logger.warning(
            "Failed to delete workspace container %s during soft delete: %s",
            workspace.name, str(e)
        )


def purge_due_workspaces(
    db: Session,
    provisioner: WorkspaceProvisioner,
    now: datetime | None = None,
) -> list[str]:
    now = now or datetime.now(timezone.utc)
    due = db.execute(
        select(Workspace).where(
            Workspace.status == "deleted",
            Workspace.purge_after.is_not(None),
            Workspace.purge_after <= now,
        )
    ).scalars()
    removed: list[str] = []
    for workspace in list(due):
        try:
            provisioner.purge_workspace(workspace)
            removed.append(workspace.name)
            db.delete(workspace)
        except Exception as e:
            # Continue with other workspaces even if one fails
            # The workspace will be retried on next purge cycle
            logger.exception(
                "Failed to purge workspace %s: %s",
                workspace.name, str(e)
            )
            db.rollback()
            continue
    if removed:
        try:
            db.commit()
        except Exception:
            db.rollback()
            raise
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
    """Deactivate a user and their workspaces.
    
    This function deactivates the user account and attempts to delete all
    associated workspace containers. Exceptions during workspace deletion
    are logged but do not block the deactivation process.
    """
    workspaces: Iterable[Workspace] = list(user.workspaces)
    for workspace in workspaces:
        if workspace.status == "active":
            workspace.status = "inactive"
            workspace.deleted_at = datetime.now(timezone.utc)
    user.status = "inactive"
    db.add(user)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    
    # Attempt to delete workspaces - failures are logged but don't block deactivation
    failures: list[tuple[str, str]] = []
    for workspace in workspaces:
        try:
            provisioner.delete_workspace(workspace)
            logger.info(
                "Successfully deleted workspace %s during user deactivation",
                workspace.name
            )
        except Exception as e:
            # Log and continue - workspace containers may already be stopped
            logger.exception(
                "Failed to delete workspace %s during user deactivation: %s",
                workspace.name, str(e)
            )
            failures.append((workspace.name, str(e)))
    
    if failures:
        logger.error(
            "User deactivation completed with %d workspace deletion failures: %s",
            len(failures),
            ", ".join(name for name, _ in failures)
        )
    else:
        logger.info(
            "User deactivation completed successfully for user %s (%d workspaces processed)",
            user.username, len(workspaces)
        )


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
