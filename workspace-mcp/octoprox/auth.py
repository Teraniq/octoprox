"""Authentication and authorization utilities."""

from __future__ import annotations

from collections.abc import Mapping
import os
import time
from typing import cast, override

import httpx
from cachetools import TTLCache
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier

from .config import INTROSPECT_URL

# Bounded caches with TTL and maxsize to prevent unbounded growth
# Max 1000 tokens cached, TTL 60 seconds
Payload = dict[str, object]

_token_cache: TTLCache[str, Payload] = TTLCache(maxsize=1000, ttl=60)

# Legacy dict cache (deprecated, use TTLCache versions above)
_cache: dict[str, tuple[Payload, float]] = {}

# Cache TTL constants
CACHE_TTL_SECONDS = 60
SUPPORTED_CLAIMS_SCHEMA_VERSIONS = frozenset({"v1"})

# Singleton httpx.AsyncClient for connection reuse
# Initialized lazily and closed on module cleanup
_httpx_client: httpx.AsyncClient | None = None


def _now() -> float:
    """Get current time as float."""
    return time.time()


def _cache_get(token: str) -> Payload | None:
    """Get token from cache (uses TTLCache for bounded memory)."""
    # Prefer TTLCache, fallback to legacy dict for compatibility
    cached = _token_cache.get(token)
    if cached is not None:
        return cached

    # Legacy fallback
    entry = _cache.get(token)
    if not entry:
        return None
    payload, expires_at = entry
    if _now() > expires_at:
        _ = _cache.pop(token, None)
        return None
    return payload


def _cache_set(token: str, payload: Payload) -> None:
    """Set token in cache (uses TTLCache for bounded memory)."""
    # Set in both caches for compatibility
    _token_cache[token] = payload
    _cache[token] = (payload, _now() + CACHE_TTL_SECONDS)


def _get_httpx_client() -> httpx.AsyncClient:
    """Get or create the singleton httpx.AsyncClient."""
    global _httpx_client
    if _httpx_client is None:
        _httpx_client = httpx.AsyncClient(
            timeout=httpx.Timeout(5.0, connect=2.0),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )
    return _httpx_client


async def _close_httpx_client() -> None:
    """Close the singleton httpx.AsyncClient."""
    global _httpx_client
    if _httpx_client is not None:
        await _httpx_client.aclose()
        _httpx_client = None


async def introspect_token(token: str) -> Payload:
    """Introspect a token with the manager service."""
    cached = _cache_get(token)
    if cached:
        return cached
    if not INTROSPECT_URL:
        return {"active": False}

    # Use singleton client instead of creating new one each time
    client = _get_httpx_client()
    try:
        response = await client.post(INTROSPECT_URL, json={"token": token})
    except httpx.RequestError:
        return {"active": False}

    if response.status_code != 200:
        return {"active": False}
    raw_payload = cast(object, response.json())
    payload = _mapping_to_payload(raw_payload)
    if payload is None:
        return {"active": False}
    _cache_set(token, payload)
    return payload


def _mapping_to_payload(value: object) -> Payload | None:
    if not isinstance(value, Mapping):
        return None

    typed_value = cast(Mapping[object, object], value)
    payload: Payload = {}
    for raw_key, item in typed_value.items():
        if not isinstance(raw_key, str):
            return None
        key = raw_key
        payload[key] = item
    return payload


def _claims_payload(payload: Payload) -> Payload | None:
    claims = payload.get("claims")
    if claims is None:
        return None
    return _mapping_to_payload(claims)


def _claims_schema_supported(payload: Payload) -> bool:
    claims = _claims_payload(payload)
    if claims is None:
        return payload.get("claims") is None

    schema_version = claims.get("schema_version")
    if schema_version is None:
        return True
    return schema_version in SUPPORTED_CLAIMS_SCHEMA_VERSIONS


def _resolve_client_id(payload: Payload) -> str:
    user_id = payload.get("user_id")
    if isinstance(user_id, str):
        return user_id
    if user_id is not None:
        return str(user_id)

    claims = _claims_payload(payload)
    if claims is None:
        return ""

    subject = claims.get("subject")
    subject_payload = _mapping_to_payload(subject)
    if subject_payload is None:
        return ""

    subject_id = subject_payload.get("id")
    if isinstance(subject_id, str):
        return subject_id
    if subject_id is None:
        return ""
    return str(subject_id)


def _resolve_role(payload: Payload) -> str:
    role = payload.get("role")
    if isinstance(role, str):
        return role.strip().lower()

    claims = _claims_payload(payload)
    if claims is None:
        return ""

    subject = _mapping_to_payload(claims.get("subject"))
    if subject is None:
        return ""

    subject_role = subject.get("role")
    if isinstance(subject_role, str):
        return subject_role.strip().lower()
    return ""


class ManagerTokenVerifier(TokenVerifier):
    """Token verifier that uses the workspace-manager introspection endpoint."""

    @override
    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a token and return an AccessToken if valid."""
        payload = await introspect_token(token)
        if not payload.get("active"):
            return None
        if not _claims_schema_supported(payload):
            return None
        scopes = ["mcp"]
        role = _resolve_role(payload)
        if role:
            scopes.append(f"role:{role}")
        return AccessToken(
            token=token,
            client_id=_resolve_client_id(payload),
            scopes=scopes,
        )


def _require_owner() -> None:
    access_token = get_access_token()
    if not access_token:
        raise RuntimeError("Unauthorized")
    if "role:admin" in access_token.scopes:
        return
    from .config import OWNER_USER_ID

    owner_user_id = os.getenv("WORKSPACE_OWNER_USER_ID") or OWNER_USER_ID
    if owner_user_id and access_token.client_id != owner_user_id:
        raise RuntimeError("Forbidden")


__all__ = [
    "ManagerTokenVerifier",
    "introspect_token",
    "_require_owner",
    "_cache_get",
    "_cache_set",
    "_get_httpx_client",
    "_close_httpx_client",
    "_claims_payload",
    "_claims_schema_supported",
    "_resolve_client_id",
    "_resolve_role",
]
