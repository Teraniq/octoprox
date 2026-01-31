from __future__ import annotations

from dataclasses import dataclass
import os


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


settings = Settings(
    secret_key=os.getenv("SECRET_KEY", "change-me"),
    database_url=os.getenv("DATABASE_URL", "sqlite:///./data/manager.db"),
    public_base_url=os.getenv("PUBLIC_BASE_URL", "http://localhost:8080"),
    bootstrap_admin_username=os.getenv("BOOTSTRAP_ADMIN_USERNAME", "admin"),
    bootstrap_admin_password=os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "admin"),
    purge_interval_seconds=_get_int("PURGE_INTERVAL_SECONDS", 300),
    workspace_image=os.getenv("WORKSPACE_IMAGE", "mcp-gitfs:latest"),
    docker_network=os.getenv("DOCKER_NETWORK", "mcpnet"),
)
