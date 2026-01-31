from __future__ import annotations

import secrets
from dataclasses import dataclass

from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


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


def verify_api_key(token: str, hashed: str) -> bool:
    return pwd_context.verify(token, hashed)


def extract_prefix(token: str) -> str | None:
    if not token.startswith("mcp_"):
        return None
    parts = token.split("_", 2)
    if len(parts) < 3:
        return None
    return parts[1]
