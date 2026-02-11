from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import SessionLocal
from .models import ApiKey, User
from .settings import settings

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# FastAPI security scheme for bearer token authentication
security = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class ApiKeyPayload:
    token: str
    prefix: str
    hash: str


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def generate_api_key() -> ApiKeyPayload:
    prefix = secrets.token_hex(4)
    random_part = secrets.token_urlsafe(24)
    token = f"mcp_{prefix}_{random_part}"
    return ApiKeyPayload(token=token, prefix=prefix, hash=pwd_context.hash(token))


def verify_api_key_hash(token: str, hashed: str) -> bool:
    """Verify an API key against its hash."""
    return pwd_context.verify(token, hashed)


def extract_prefix(token: str) -> str | None:
    """Extract prefix from API key (e.g., 'mcp_abc123_xyz' -> 'abc123')."""
    if not token.startswith("mcp_"):
        return None
    parts = token.split("_", 2)
    if len(parts) < 3:
        return None
    return parts[1]


def create_access_token(sub: str, username: str, role: str) -> str:
    """Create a JWT access token.

    Args:
        sub: Subject (user ID)
        username: User's username
        role: User's role (admin/user)

    Returns:
        Encoded JWT token string
    """
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": sub,
        "username": username,
        "role": role,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_access_token_expire_minutes),
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(
        payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
    )


def verify_access_token(token: str) -> dict[str, Any]:
    """Verify and decode a JWT access token.

    Args:
        token: JWT token string

    Returns:
        Decoded token payload

    Raises:
        HTTPException: If token is expired or invalid
    """
    try:
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


def verify_api_key(db: Session, api_key: str) -> ApiKey | None:
    """Verify an API key against the database.

    Args:
        db: Database session
        api_key: The API key to verify

    Returns:
        ApiKey object if valid, None otherwise
    """
    # Extract prefix from API key
    prefix = extract_prefix(api_key)
    if prefix is None:
        return None

    # Query database for API key with matching prefix
    stmt = select(ApiKey).where(ApiKey.key_prefix == prefix)
    db_api_key = db.execute(stmt).scalar_one_or_none()

    if db_api_key is None:
        return None

    # Verify the full key against stored hash
    if not verify_api_key_hash(api_key, db_api_key.key_hash):
        return None

    # Update last_used_at timestamp
    db_api_key.last_used_at = datetime.now(timezone.utc)
    db.commit()

    return db_api_key


def get_db() -> Session:
    """Get a database session."""
    db = SessionLocal()
    try:
        return db
    finally:
        db.close()


async def get_current_user_unified(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> User:
    """Unified authentication handler supporting session, API key, and JWT.

    Attempts authentication in the following order:
    1. Session-based auth (for web UI)
    2. API key auth (mcp_* prefix)
    3. JWT Bearer token auth

    Args:
        request: FastAPI request object
        credentials: HTTP Authorization credentials

    Returns:
        Authenticated User object

    Raises:
        HTTPException: If authentication fails (401)
    """
    # First, check session-based auth
    session_user = request.session.get("user")
    if session_user:
        db = get_db()
        try:
            stmt = select(User).where(
                User.username == session_user.get("username"),
                User.status == "active",
            )
            user = db.execute(stmt).scalar_one_or_none()
            if user:
                return user
        finally:
            db.close()

    # If no session and no credentials, unauthorized
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    db = get_db()
    try:
        # Check if it's an API key (mcp_* prefix)
        if token.startswith("mcp_"):
            api_key = verify_api_key(db, token)
            if api_key and api_key.user.status == "active":
                return api_key.user
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Otherwise, treat as JWT
        try:
            payload = verify_access_token(token)
            sub = payload.get("sub")
            if not sub:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token payload",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            # Look up user by ID (sub)
            stmt = select(User).where(
                User.id == int(sub),
                User.status == "active",
            )
            user = db.execute(stmt).scalar_one_or_none()
            if user:
                return user
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
    finally:
        db.close()


async def require_admin(
    current_user: User = Depends(get_current_user_unified),
) -> User:
    """Require the current user to have admin role.

    Args:
        current_user: The authenticated user from get_current_user_unified

    Returns:
        The authenticated admin user

    Raises:
        HTTPException: If user is not an admin (403)
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user
