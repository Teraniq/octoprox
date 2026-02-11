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
    # JWT Configuration for NEXUSGATE integration
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 15
    nexusgate_integration_enabled: bool = False
    introspect_secret: str | None = None
    # Rate limiting configuration
    api_rate_limit: int = 200  # requests per minute
    auth_rate_limit: int = 60  # requests per minute for auth endpoints
    # HTTPS Enforcement configuration
    enforce_https: bool = False  # Enable HSTS header and HTTPS-only features
    hsts_max_age: int = 31536000  # HSTS max-age in seconds (1 year)
    hsts_include_subdomains: bool = True  # Include subdomains in HSTS

    def __post_init__(self) -> None:
        """Validate JWT configuration after initialization."""
        if len(self.jwt_secret_key) < 32:
            raise ValueError(
                f"JWT_SECRET_KEY must be at least 32 characters long. "
                f"Current length: {len(self.jwt_secret_key)}"
            )


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _get_bool(name: str, default: bool = False) -> bool:
    """Get a boolean environment variable."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.lower() in ("true", "1", "yes", "on")


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
_jwt_secret_key = _get_secure_default("JWT_SECRET_KEY")

settings = Settings(
    secret_key=_secret_key,
    database_url=os.getenv("DATABASE_URL", "sqlite:///./data/manager.db"),
    public_base_url=os.getenv("PUBLIC_BASE_URL", "http://localhost:8080"),
    bootstrap_admin_username=_bootstrap_admin_username,
    bootstrap_admin_password=_bootstrap_admin_password,
    purge_interval_seconds=_get_int("PURGE_INTERVAL_SECONDS", 300),
    workspace_image=os.getenv("WORKSPACE_IMAGE", "mcp-gitfs:latest"),
    docker_network=os.getenv("DOCKER_NETWORK", "mcpnet"),
    # JWT Configuration
    jwt_secret_key=_jwt_secret_key,
    jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
    jwt_access_token_expire_minutes=_get_int("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 15),
    nexusgate_integration_enabled=_get_bool("NEXUSGATE_INTEGRATION_ENABLED", False),
    introspect_secret=os.getenv("INTROSPECT_SECRET"),
    # Rate limiting
    api_rate_limit=_get_int("API_RATE_LIMIT", 200),  # requests per minute
    auth_rate_limit=_get_int("AUTH_RATE_LIMIT", 60),  # requests per minute for auth endpoints
    # HTTPS Enforcement
    enforce_https=_get_bool("ENFORCE_HTTPS", False),
    hsts_max_age=_get_int("HSTS_MAX_AGE", 31536000),
    hsts_include_subdomains=_get_bool("HSTS_INCLUDE_SUBDOMAINS", True),
)
