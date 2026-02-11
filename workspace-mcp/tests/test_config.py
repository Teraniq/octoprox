"""Tests for feature flag configuration in octoprox.config module."""
from __future__ import annotations

import importlib
import os
from typing import Generator
from unittest.mock import patch

import pytest


@pytest.fixture
def reload_config() -> Generator[None, None, None]:
    """Reload config module after environment changes."""
    yield
    # Reload module to pick up new env vars
    import octoprox.config
    importlib.reload(octoprox.config)


class TestFeatureFlags:
    """Test feature flag configuration loading."""

    def test_enable_openapi_default_true(self, reload_config):
        """Test ENABLE_OPENAPI defaults to True."""
        # Remove env var to test default
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ENABLE_OPENAPI", None)
            import octoprox.config as config
            importlib.reload(config)
            assert config.ENABLE_OPENAPI is True

    def test_enable_openapi_true_values(self, reload_config):
        """Test ENABLE_OPENAPI accepts true-like values."""
        true_values = ["true", "True", "TRUE", "1", "yes", "YES", "on", "ON"]
        
        for value in true_values:
            with patch.dict(os.environ, {"ENABLE_OPENAPI": value}):
                import octoprox.config as config
                importlib.reload(config)
                assert config.ENABLE_OPENAPI is True, f"Expected True for value: {value}"

    def test_enable_openapi_false_values(self, reload_config):
        """Test ENABLE_OPENAPI accepts false-like values."""
        false_values = ["false", "False", "FALSE", "0", "no", "NO", "off", "OFF"]
        
        for value in false_values:
            with patch.dict(os.environ, {"ENABLE_OPENAPI": value}):
                import octoprox.config as config
                importlib.reload(config)
                assert config.ENABLE_OPENAPI is False, f"Expected False for value: {value}"


class TestEnvironmentVariables:
    """Test environment variable configuration."""

    def test_owner_user_id_default_empty(self, reload_config):
        """Test OWNER_USER_ID defaults to empty string."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WORKSPACE_OWNER_USER_ID", None)
            import octoprox.config as config
            importlib.reload(config)
            assert config.OWNER_USER_ID == ""

    def test_owner_user_id_custom_value(self, reload_config):
        """Test OWNER_USER_ID accepts custom value."""
        with patch.dict(os.environ, {"WORKSPACE_OWNER_USER_ID": "user123"}):
            import octoprox.config as config
            importlib.reload(config)
            assert config.OWNER_USER_ID == "user123"

    def test_introspect_url_default_empty(self, reload_config):
        """Test INTROSPECT_URL defaults to empty string."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MANAGER_INTROSPECT_URL", None)
            import octoprox.config as config
            importlib.reload(config)
            assert config.INTROSPECT_URL == ""

    def test_introspect_url_custom_value(self, reload_config):
        """Test INTROSPECT_URL accepts custom value."""
        custom_url = "http://manager:8000/internal/auth/introspect"
        with patch.dict(os.environ, {"MANAGER_INTROSPECT_URL": custom_url}):
            import octoprox.config as config
            importlib.reload(config)
            assert config.INTROSPECT_URL == custom_url

    def test_mcp_port_default_7000(self, reload_config):
        """Test MCP_PORT defaults to 7000."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MCP_PORT", None)
            import octoprox.config as config
            importlib.reload(config)
            assert config.MCP_PORT == 7000

    def test_mcp_port_custom_value(self, reload_config):
        """Test MCP_PORT accepts custom value."""
        with patch.dict(os.environ, {"MCP_PORT": "8080"}):
            import octoprox.config as config
            importlib.reload(config)
            assert config.MCP_PORT == 8080

    def test_mcp_bind_host_default(self, reload_config):
        """Test MCP_BIND_HOST defaults to 0.0.0.0."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MCP_BIND_HOST", None)
            import octoprox.config as config
            importlib.reload(config)
            assert config.MCP_BIND_HOST == "0.0.0.0"

    def test_mcp_bind_host_custom_value(self, reload_config):
        """Test MCP_BIND_HOST accepts custom value."""
        with patch.dict(os.environ, {"MCP_BIND_HOST": "127.0.0.1"}):
            import octoprox.config as config
            importlib.reload(config)
            assert config.MCP_BIND_HOST == "127.0.0.1"


class TestGitLabConfiguration:
    """Test GitLab-related configuration."""

    def test_gitlab_base_url_default(self, reload_config):
        """Test GITLAB_BASE_URL defaults to https://gitlab.com."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GITLAB_BASE_URL", None)
            import octoprox.config as config
            importlib.reload(config)
            assert config.GITLAB_BASE_URL == "https://gitlab.com"

    def test_gitlab_base_url_custom_with_trailing_slash(self, reload_config):
        """Test GITLAB_BASE_URL strips trailing slash."""
        with patch.dict(os.environ, {"GITLAB_BASE_URL": "https://gitlab.example.com/"}):
            import octoprox.config as config
            importlib.reload(config)
            assert config.GITLAB_BASE_URL == "https://gitlab.example.com"

    def test_gitlab_openapi_url_derived_from_base(self, reload_config):
        """Test GITLAB_OPENAPI_URL is derived from base URL."""
        with patch.dict(os.environ, {"GITLAB_BASE_URL": "https://gitlab.example.com"}):
            import octoprox.config as config
            importlib.reload(config)
            assert config.GITLAB_OPENAPI_URL == "https://gitlab.example.com/api/v4/openapi"

    def test_gitlab_openapi_url_custom_override(self, reload_config):
        """Test GITLAB_OPENAPI_URL can be overridden."""
        custom_url = "https://custom.gitlab.com/openapi.yaml"
        with patch.dict(os.environ, {"GITLAB_OPENAPI_URL": custom_url}):
            import octoprox.config as config
            importlib.reload(config)
            assert config.GITLAB_OPENAPI_URL == custom_url

    def test_gitlab_token_from_primary_env(self, reload_config):
        """Test GITLAB_TOKEN from primary env var."""
        with patch.dict(os.environ, {"GITLAB_TOKEN": "my-token"}):
            import octoprox.config as config
            importlib.reload(config)
            assert config.GITLAB_TOKEN == "my-token"

    def test_gitlab_token_from_private_token(self, reload_config):
        """Test GITLAB_TOKEN from GITLAB_PRIVATE_TOKEN fallback."""
        with patch.dict(os.environ, {"GITLAB_PRIVATE_TOKEN": "private-token"}):
            import octoprox.config as config
            importlib.reload(config)
            assert config.GITLAB_TOKEN == "private-token"

    def test_gitlab_token_from_bearer_token(self, reload_config):
        """Test GITLAB_TOKEN from GITLAB_BEARER_TOKEN fallback."""
        with patch.dict(os.environ, {"GITLAB_BEARER_TOKEN": "bearer-token"}):
            import octoprox.config as config
            importlib.reload(config)
            assert config.GITLAB_TOKEN == "bearer-token"

    def test_gitlab_token_priority_order(self, reload_config):
        """Test GITLAB_TOKEN env var takes priority over fallbacks."""
        with patch.dict(os.environ, {
            "GITLAB_TOKEN": "primary-token",
            "GITLAB_PRIVATE_TOKEN": "private-token",
            "GITLAB_BEARER_TOKEN": "bearer-token",
        }):
            import octoprox.config as config
            importlib.reload(config)
            assert config.GITLAB_TOKEN == "primary-token"

    def test_gitlab_token_none_when_not_set(self, reload_config):
        """Test GITLAB_TOKEN is None when no env var is set."""
        with patch.dict(os.environ, {}, clear=False):
            for key in ["GITLAB_TOKEN", "GITLAB_PRIVATE_TOKEN", "GITLAB_BEARER_TOKEN"]:
                os.environ.pop(key, None)
            import octoprox.config as config
            importlib.reload(config)
            assert config.GITLAB_TOKEN is None


class TestCacheConfiguration:
    """Test cache-related configuration."""

    def test_cache_ttl_seconds_default(self, reload_config):
        """Test CACHE_TTL_SECONDS defaults to 60."""
        import octoprox.config as config
        importlib.reload(config)
        assert config.CACHE_TTL_SECONDS == 60

    def test_openapi_cache_ttl_seconds_default(self, reload_config):
        """Test OPENAPI_CACHE_TTL_SECONDS defaults to 3600."""
        import octoprox.config as config
        importlib.reload(config)
        assert config.OPENAPI_CACHE_TTL_SECONDS == 3600

    def test_gitlab_spec_cache_ttl_seconds_default(self, reload_config):
        """Test GITLAB_SPEC_CACHE_TTL_SECONDS defaults to 3600."""
        import octoprox.config as config
        importlib.reload(config)
        assert config.GITLAB_SPEC_CACHE_TTL_SECONDS == 3600


class TestExports:
    """Test that all expected variables are exported."""

    def test_all_exports_present(self):
        """Test that __all__ includes all expected exports."""
        import octoprox.config as config
        
        expected_exports = [
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
        
        for export in expected_exports:
            assert export in config.__all__, f"Expected {export} in __all__"
            assert hasattr(config, export), f"Expected {export} to be accessible"
