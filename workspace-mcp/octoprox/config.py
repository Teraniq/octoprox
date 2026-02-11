"""Configuration and feature flags for octoprox."""
from __future__ import annotations

import os

# Feature flags
ENABLE_OPENAPI = os.getenv("ENABLE_OPENAPI", "true").lower() in ("true", "1", "yes", "on")

# Environment variables
OWNER_USER_ID = os.getenv("WORKSPACE_OWNER_USER_ID", "")
INTROSPECT_URL = os.getenv("MANAGER_INTROSPECT_URL", "")
MCP_PORT = int(os.getenv("MCP_PORT", "7000"))
MCP_BIND_HOST = os.getenv("MCP_BIND_HOST", "0.0.0.0")

# GitLab configuration
GITLAB_BASE_URL = os.getenv("GITLAB_BASE_URL", "https://gitlab.com").rstrip("/")
GITLAB_OPENAPI_URL = os.getenv("GITLAB_OPENAPI_URL", f"{GITLAB_BASE_URL}/api/v4/openapi")
GITLAB_TOKEN = (
    os.getenv("GITLAB_TOKEN")
    or os.getenv("GITLAB_PRIVATE_TOKEN")
    or os.getenv("GITLAB_BEARER_TOKEN")
)

# Cache configuration
CACHE_TTL_SECONDS = 60
OPENAPI_CACHE_TTL_SECONDS = 3600
GITLAB_SPEC_CACHE_TTL_SECONDS = 3600

__all__ = [
    "ENABLE_OPENAPI",
    "OWNER_USER_ID",
    "INTROSPECT_URL",
    "MCP_PORT",
    "MCP_BIND_HOST",
    "GITLAB_BASE_URL",
    "GITLAB_OPENAPI_URL",
    "GITLAB_TOKEN",
    "CACHE_TTL_SECONDS",
    "OPENAPI_CACHE_TTL_SECONDS",
    "GITLAB_SPEC_CACHE_TTL_SECONDS",
]