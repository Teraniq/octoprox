from __future__ import annotations

from dataclasses import dataclass
import os
import secrets


@dataclass(frozen=True)
class Settings:
    secret_key: str
    database_url: str
    public_base_url: str
    bootstrap_admin_username: str
    bootstrap_admin_password: str
    purge_interval_seconds: int
    workspace_image: str
    docker_network: str


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _get_required(name: str, default: str | None = None) -> str:
    """Get a required environment variable, failing fast if not set."""
    value = os.getenv(name, default)
    if value is None or value == "":
        raise ValueError(
            f"CRITICAL SECURITY ERROR: Environment variable '{name}' must be set. "
            f"Please configure this before starting the application. "
            f"See README.md for configuration instructions."
        )
    return value


def _get_secure_default(name: str, default: str | None = None) -> str:
    """Get environment variable with secure fallback (generates random if not set)."""
    value = os.getenv(name)
    if value is None or value == "":
        if default is not None:
            return default
        # Generate a secure random value
        generated = secrets.token_urlsafe(32)
        import logging
        logging.warning(
            f"SECURITY WARNING: '{name}' not set. Generated random value. "
            f"Set this explicitly in production to avoid unexpected behavior."
        )
        return generated
    return value


# Validate critical settings at import time
_secret_key = _get_secure_default("SECRET_KEY")
_bootstrap_admin_username = _get_required("BOOTSTRAP_ADMIN_USERNAME")
_bootstrap_admin_password = _get_required("BOOTSTRAP_ADMIN_PASSWORD")

settings = Settings(
    secret_key=_secret_key,
    database_url=os.getenv("DATABASE_URL", "sqlite:///./data/manager.db"),
    public_base_url=os.getenv("PUBLIC_BASE_URL", "http://localhost:8080"),
    bootstrap_admin_username=_bootstrap_admin_username,
    bootstrap_admin_password=_bootstrap_admin_password,
    purge_interval_seconds=_get_int("PURGE_INTERVAL_SECONDS", 300),
    workspace_image=os.getenv("WORKSPACE_IMAGE", "mcp-gitfs:latest"),
    docker_network=os.getenv("DOCKER_NETWORK", "mcpnet"),
)
