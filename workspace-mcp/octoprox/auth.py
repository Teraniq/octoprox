"""Authentication and authorization utilities."""
from __future__ import annotations

import time
from typing import Any

import httpx
from cachetools import TTLCache
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier

from .config import INTROSPECT_URL

# Bounded caches with TTL and maxsize to prevent unbounded growth
# Max 1000 tokens cached, TTL 60 seconds
_token_cache: TTLCache[str, dict[str, Any]] = TTLCache(maxsize=1000, ttl=60)

# Legacy dict cache (deprecated, use TTLCache versions above)
_cache: dict[str, tuple[dict[str, Any], float]] = {}

# Cache TTL constants
CACHE_TTL_SECONDS = 60

# Singleton httpx.AsyncClient for connection reuse
# Initialized lazily and closed on module cleanup
_httpx_client: httpx.AsyncClient | None = None


def _now() -> float:
    """Get current time as float."""
    return time.time()


def _cache_get(token: str) -> dict[str, Any] | None:
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
        _cache.pop(token, None)
        return None
    return payload


def _cache_set(token: str, payload: dict[str, Any]) -> None:
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


async def introspect_token(token: str) -> dict[str, Any]:
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
    payload = response.json()
    _cache_set(token, payload)
    return payload


class ManagerTokenVerifier(TokenVerifier):
    """Token verifier that uses the workspace-manager introspection endpoint."""

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a token and return an AccessToken if valid."""
        payload = await introspect_token(token)
        if not payload.get("active"):
            return None
        return AccessToken(
            token=token,
            client_id=payload.get("user_id", ""),
            scopes=["mcp"],
        )


def _require_owner() -> None:
    """Require the current user to be the workspace owner."""
    access_token = get_access_token()
    if not access_token:
        raise RuntimeError("Unauthorized")
    from .config import OWNER_USER_ID
    if OWNER_USER_ID and access_token.client_id != OWNER_USER_ID:
        raise RuntimeError("Forbidden")


__all__ = [
    "ManagerTokenVerifier",
    "introspect_token",
    "_require_owner",
    "_cache_get",
    "_cache_set",
    "_get_httpx_client",
    "_close_httpx_client",
]