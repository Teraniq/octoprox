from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import auth
from .models import ApiKey, User, Workspace
from .provisioning import WorkspaceProvisioner

logger = logging.getLogger(__name__)

WORKSPACE_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")


def validate_workspace_name(db: Session, name: str) -> tuple[bool, str]:
    if not WORKSPACE_NAME_RE.match(name):
        return False, "Name must match ^[a-zA-Z0-9._-]{1,128}$"
    exists = db.execute(
        select(Workspace).where(Workspace.name == name)
    ).scalar_one_or_none()
    if exists:
        return False, "Name already exists"
    return True, "Name is available"


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
    workspace.purge_after = datetime.now(timezone.utc) + timedelta(
        hours=purge_after_hours
    )
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
            workspace.name,
            str(e),
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
            logger.exception("Failed to purge workspace %s: %s", workspace.name, str(e))
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
                workspace.name,
            )
        except Exception as e:
            # Log and continue - workspace containers may already be stopped
            logger.exception(
                "Failed to delete workspace %s during user deactivation: %s",
                workspace.name,
                str(e),
            )
            failures.append((workspace.name, str(e)))

    if failures:
        logger.error(
            "User deactivation completed with %d workspace deletion failures: %s",
            len(failures),
            ", ".join(name for name, _ in failures),
        )
    else:
        logger.info(
            "User deactivation completed successfully for user %s (%d workspaces processed)",
            user.username,
            len(workspaces),
        )


def introspect_token(db: Session, token: str) -> dict:
    prefix = auth.extract_prefix(token)
    if not prefix:
        return {"active": False}
    keys = db.execute(select(ApiKey).where(ApiKey.key_prefix == prefix)).scalars().all()
    for key in keys:
        if auth.verify_api_key_hash(token, key.key_hash):
            if key.user.status != "active":
                return {"active": False}
            return {"active": True, "user_id": str(key.user_id), "role": key.user.role}
    return {"active": False}


# ============================================================================
# User Services
# ============================================================================


def list_users(
    db: Session,
    page: int = 1,
    per_page: int = 20,
    status: str | None = None,
    role: str | None = None,
) -> tuple[list[User], int]:
    """List users with optional filtering and pagination.

    Args:
        db: Database session
        page: Page number (1-indexed)
        per_page: Number of items per page
        status: Optional filter by user status
        role: Optional filter by user role

    Returns:
        Tuple of (users list, total count)
    """
    # Build base query
    query = select(User)
    count_query = select(func.count(User.id))

    # Apply filters
    if status is not None:
        query = query.where(User.status == status)
        count_query = count_query.where(User.status == status)
    if role is not None:
        query = query.where(User.role == role)
        count_query = count_query.where(User.role == role)

    # Get total count
    total = db.execute(count_query).scalar_one()

    # Apply pagination
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page)

    # Execute query
    users = list(db.execute(query).scalars().all())

    return users, total


def update_user(
    db: Session,
    user: User,
    role: str | None = None,
    status: str | None = None,
    nexusgate_user_id: str | None = None,
) -> User:
    """Update user fields.

    Args:
        db: Database session
        user: User to update
        role: Optional new role
        status: Optional new status
        nexusgate_user_id: Optional NEXUSGATE user ID

    Returns:
        Updated user
    """
    if role is not None:
        user.role = role
    if status is not None:
        user.status = status
    if nexusgate_user_id is not None:
        user.nexusgate_user_id = nexusgate_user_id

    user.updated_at = datetime.now(timezone.utc)

    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except Exception:
        db.rollback()
        raise

    return user


# ============================================================================
# Workspace Services
# ============================================================================


def list_workspaces(
    db: Session,
    user_id: int | None = None,
    page: int = 1,
    per_page: int = 20,
    include_deleted: bool = False,
) -> tuple[list[Workspace], int]:
    """List workspaces with optional filtering and pagination.

    Args:
        db: Database session
        user_id: Optional filter by user ID
        page: Page number (1-indexed)
        per_page: Number of items per page
        include_deleted: Whether to include deleted workspaces

    Returns:
        Tuple of (workspaces list, total count)
    """
    # Build base query
    query = select(Workspace)
    count_query = select(func.count(Workspace.id))

    # Apply user filter
    if user_id is not None:
        query = query.where(Workspace.user_id == user_id)
        count_query = count_query.where(Workspace.user_id == user_id)

    # Filter out deleted workspaces by default
    if not include_deleted:
        query = query.where(Workspace.deleted_at.is_(None))
        count_query = count_query.where(Workspace.deleted_at.is_(None))

    # Get total count
    total = db.execute(count_query).scalar_one()

    # Apply pagination
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page)

    # Execute query
    workspaces = list(db.execute(query).scalars().all())

    return workspaces, total


def create_workspace_api(
    db: Session,
    provisioner: WorkspaceProvisioner,
    user: User,
    name: str,
    metadata: dict | None = None,
) -> Workspace:
    """Create a new workspace with optional metadata.

    Args:
        db: Database session
        provisioner: Workspace provisioner instance
        user: User creating the workspace
        name: Workspace name
        metadata: Optional metadata dictionary

    Returns:
        Created workspace
    """
    # Call existing create_workspace function
    workspace = create_workspace(db, provisioner, user, name)

    # Set metadata if provided
    if metadata is not None:
        workspace.metadata_json = metadata
        db.add(workspace)
        try:
            db.commit()
            db.refresh(workspace)
        except Exception:
            db.rollback()
            raise

    return workspace


# ============================================================================
# API Key Services
# ============================================================================


def list_api_keys(
    db: Session,
    user_id: int | None = None,
    page: int = 1,
    per_page: int = 20,
) -> tuple[list[ApiKey], int]:
    """List API keys with optional filtering and pagination.

    Args:
        db: Database session
        user_id: Optional filter by user ID
        page: Page number (1-indexed)
        per_page: Number of items per page

    Returns:
        Tuple of (api keys list, total count)
    """
    # Build base query
    query = select(ApiKey)
    count_query = select(func.count(ApiKey.id))

    # Apply user filter
    if user_id is not None:
        query = query.where(ApiKey.user_id == user_id)
        count_query = count_query.where(ApiKey.user_id == user_id)

    # Get total count
    total = db.execute(count_query).scalar_one()

    # Apply pagination
    offset = (page - 1) * per_page
    query = query.offset(offset).limit(per_page)

    # Execute query
    api_keys = list(db.execute(query).scalars().all())

    return api_keys, total


def create_api_key(
    db: Session,
    user: User,
    name: str | None = None,
    nexusgate_token_id: str | None = None,
) -> tuple[ApiKey, str]:
    """Create a new API key for a user.

    Args:
        db: Database session
        user: User to create key for
        name: Optional name for the API key
        nexusgate_token_id: Optional NEXUSGATE token ID

    Returns:
        Tuple of (ApiKey, raw_token)
    """
    payload = auth.generate_api_key()
    key = ApiKey(
        user_id=user.id,
        key_prefix=payload.prefix,
        key_hash=payload.hash,
    )

    # Set optional fields if provided
    if name is not None:
        key.name = name
    if nexusgate_token_id is not None:
        key.nexusgate_token_id = nexusgate_token_id

    db.add(key)
    try:
        db.commit()
        db.refresh(key)
    except Exception:
        db.rollback()
        raise
    return key, payload.token


def revoke_api_key(db: Session, api_key: ApiKey) -> None:
    """Revoke (delete) an API key.

    Args:
        db: Database session
        api_key: API key to revoke
    """
    db.delete(api_key)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise


# ============================================================================
# Audit Logging
# ============================================================================


def audit_log(
    user_id: int | None,
    action: str,
    resource: str,
    details: dict | None = None,
) -> None:
    """Create a structured audit log entry.

    Args:
        user_id: ID of the user performing the action, or None
        action: Action being performed (e.g., 'create', 'delete', 'update')
        resource: Resource being acted upon (e.g., 'workspace', 'api_key')
        details: Optional additional details as a dictionary
    """
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
        "action": action,
        "resource": resource,
        "details": details or {},
    }
    logger.info("AUDIT: %s", log_entry)
