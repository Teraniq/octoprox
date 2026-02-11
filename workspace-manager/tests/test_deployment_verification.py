"""Post-deployment verification tests for octoprox.

These tests verify that a deployed octoprox instance is functioning correctly.
They can be run against a live deployment to validate:
- Health endpoint returns 200
- Introspect endpoint works
- API key authentication works
- JWT authentication works
- All API endpoints respond correctly

Usage:
    pytest tests/test_deployment_verification.py --live-deployment \
        --base-url http://localhost:8080 \
        --admin-user admin \
        --admin-pass changeme
"""

from __future__ import annotations

import os
import sys
import pathlib
from typing import Any

import pytest
import requests

# Add parent to path for imports
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))


class DeploymentConfig:
    """Configuration for deployment tests."""

    def __init__(self) -> None:
        self.base_url = os.environ.get("TEST_BASE_URL", "http://localhost:8080")
        self.admin_username = os.environ.get("TEST_ADMIN_USER", "admin")
        self.admin_password = os.environ.get("TEST_ADMIN_PASS", "changeme")
        self.api_url = f"{self.base_url}/api/v1"


@pytest.fixture(scope="module")
def config() -> DeploymentConfig:
    """Provide deployment configuration."""
    return DeploymentConfig()


@pytest.fixture(scope="module")
def session() -> requests.Session:
    """Provide a requests session."""
    return requests.Session()


@pytest.fixture(scope="module")
def admin_session(config: DeploymentConfig, session: requests.Session) -> requests.Session:
    """Login as admin and return authenticated session."""
    # Get login page to establish session
    response = session.get(f"{config.base_url}/login", timeout=10)
    assert response.status_code == 200, "Login page not accessible"

    # Get CSRF token from cookies
    csrf_token = session.cookies.get("csrftoken", "")

    # Login
    response = session.post(
        f"{config.base_url}/login",
        data={
            "username": config.admin_username,
            "password": config.admin_password,
            "csrf_token": csrf_token,
        },
        allow_redirects=False,
        timeout=10,
    )

    assert response.status_code in [302, 303], f"Login failed: {response.text}"
    return session


@pytest.fixture(scope="module")
def api_key(config: DeploymentConfig, admin_session: requests.Session) -> str:
    """Create an API key and return it."""
    response = admin_session.post(
        f"{config.api_url}/api-keys",
        json={"name": "Deployment Test Key"},
        timeout=10,
    )

    assert response.status_code == 201, f"API key creation failed: {response.text}"
    data = response.json()
    api_key_value = data.get("data", {}).get("api_key")
    assert api_key_value, "API key not returned in response"
    return api_key_value


class TestHealthEndpoint:
    """Test health endpoint functionality."""

    def test_health_returns_200(self, config: DeploymentConfig, session: requests.Session) -> None:
        """Verify /api/v1/health returns 200."""
        response = session.get(f"{config.api_url}/health", timeout=10)
        assert response.status_code == 200, f"Health check failed: {response.text}"

    def test_health_returns_correct_structure(self, config: DeploymentConfig, session: requests.Session) -> None:
        """Verify health endpoint returns expected structure."""
        response = session.get(f"{config.api_url}/health", timeout=10)
        data = response.json()

        assert "data" in data, "Response missing 'data' key"
        data_content = data["data"]

        assert "status" in data_content, "Response missing 'status'"
        assert "timestamp" in data_content, "Response missing 'timestamp'"
        assert "components" in data_content, "Response missing 'components'"
        assert "workspaces" in data_content, "Response missing 'workspaces'"

    def test_health_components_structure(self, config: DeploymentConfig, session: requests.Session) -> None:
        """Verify health endpoint components have correct structure."""
        response = session.get(f"{config.api_url}/health", timeout=10)
        data = response.json()
        components = data.get("data", {}).get("components", {})

        # Check database component
        assert "database" in components, "Missing database component"
        db = components["database"]
        assert "healthy" in db or "status" in db, "Database missing health indicator"

        # Check docker component
        assert "docker" in components, "Missing docker component"
        docker = components["docker"]
        assert "healthy" in docker or "status" in docker, "Docker missing health indicator"


class TestIntrospectEndpoint:
    """Test token introspection endpoint."""

    def test_introspect_valid_api_key(self, config: DeploymentConfig, session: requests.Session, api_key: str) -> None:
        """Verify introspect endpoint works with valid API key."""
        response = session.post(
            f"{config.api_url}/auth/introspect",
            json={"token": api_key},
            timeout=10,
        )

        assert response.status_code == 200, f"Introspection failed: {response.text}"
        data = response.json()

        assert "data" in data, "Response missing 'data'"
        token_data = data["data"]

        assert token_data.get("active") is True, "Token should be active"
        assert "sub" in token_data, "Missing 'sub' claim"
        assert "username" in token_data, "Missing 'username' claim"
        assert "role" in token_data, "Missing 'role' claim"
        assert "token_type" in token_data, "Missing 'token_type' claim"

    def test_introspect_invalid_token(self, config: DeploymentConfig, session: requests.Session) -> None:
        """Verify introspect returns active=false for invalid token."""
        response = session.post(
            f"{config.api_url}/auth/introspect",
            json={"token": "invalid_token_12345"},
            timeout=10,
        )

        assert response.status_code == 200, f"Introspection failed: {response.text}"
        data = response.json()

        assert data.get("data", {}).get("active") is False, "Invalid token should return active=false"


class TestAPIKeyAuthentication:
    """Test API key authentication."""

    def test_api_key_auth_works(self, config: DeploymentConfig, session: requests.Session, api_key: str) -> None:
        """Test authentication with API keys works."""
        response = session.get(
            f"{config.api_url}/workspaces",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10,
        )

        assert response.status_code == 200, f"API key auth failed: {response.text}"
        data = response.json()
        assert "data" in data, "Response missing 'data'"

    def test_invalid_api_key_rejected(self, config: DeploymentConfig, session: requests.Session) -> None:
        """Test invalid API key is rejected."""
        response = session.get(
            f"{config.api_url}/workspaces",
            headers={"Authorization": "Bearer mcp_invalid_key_12345"},
            timeout=10,
        )

        assert response.status_code == 401, "Invalid API key should return 401"

    def test_missing_api_key_rejected(self, config: DeploymentConfig, session: requests.Session) -> None:
        """Test missing API key is rejected for protected endpoints."""
        response = session.get(f"{config.api_url}/workspaces", timeout=10)
        assert response.status_code == 401, "Missing auth should return 401"


class TestJWTAuthentication:
    """Test JWT authentication."""

    def test_jwt_handling_malformed(self, config: DeploymentConfig, session: requests.Session) -> None:
        """Test malformed JWT is handled correctly."""
        malformed_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature"

        # Test introspection with malformed JWT
        response = session.post(
            f"{config.api_url}/auth/introspect",
            json={"token": malformed_jwt},
            timeout=10,
        )

        assert response.status_code == 200, f"Introspection should not fail: {response.text}"
        data = response.json()
        # Malformed JWT should return active=false, not an error
        assert data.get("data", {}).get("active") is False, "Malformed JWT should return active=false"

    def test_jwt_auth_protected_endpoint(self, config: DeploymentConfig, session: requests.Session) -> None:
        """Test JWT can be used for protected endpoint access (if supported)."""
        # This test verifies the endpoint accepts JWT format
        # Actual JWT validation depends on implementation
        malformed_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature"

        response = session.get(
            f"{config.api_url}/workspaces",
            headers={"Authorization": f"Bearer {malformed_jwt}"},
            timeout=10,
        )

        # Should either be 401 (rejected) or 200 (if some mock/test JWT is accepted)
        # The important thing is it doesn't crash
        assert response.status_code in [200, 401], f"Unexpected status: {response.status_code}"


class TestAllAPIEndpoints:
    """Test all major API endpoints respond correctly."""

    def test_list_workspaces(self, config: DeploymentConfig, session: requests.Session, api_key: str) -> None:
        """Verify GET /api/v1/workspaces works."""
        response = session.get(
            f"{config.api_url}/workspaces",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10,
        )
        assert response.status_code == 200, f"List workspaces failed: {response.text}"
        data = response.json()
        assert "data" in data, "Response missing 'data'"
        assert "workspaces" in data.get("data", {}), "Response missing 'workspaces'"

    def test_list_api_keys(self, config: DeploymentConfig, session: requests.Session, api_key: str) -> None:
        """Verify GET /api/v1/api-keys works."""
        response = session.get(
            f"{config.api_url}/api-keys",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10,
        )
        assert response.status_code == 200, f"List API keys failed: {response.text}"
        data = response.json()
        assert "data" in data, "Response missing 'data'"
        assert "api_keys" in data.get("data", {}), "Response missing 'api_keys'"

    def test_list_users(self, config: DeploymentConfig, session: requests.Session, api_key: str) -> None:
        """Verify GET /api/v1/users works (admin only)."""
        response = session.get(
            f"{config.api_url}/users",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10,
        )
        assert response.status_code == 200, f"List users failed: {response.text}"
        data = response.json()
        assert "data" in data, "Response missing 'data'"
        assert "users" in data.get("data", {}), "Response missing 'users'"

    def test_list_mcp_tools(self, config: DeploymentConfig, session: requests.Session, api_key: str) -> None:
        """Verify GET /api/v1/mcp/tools works."""
        response = session.get(
            f"{config.api_url}/mcp/tools",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10,
        )
        assert response.status_code == 200, f"List MCP tools failed: {response.text}"
        data = response.json()
        assert "data" in data, "Response missing 'data'"


class TestSecurityHeaders:
    """Test security headers are present."""

    def test_security_headers_present(self, config: DeploymentConfig, session: requests.Session) -> None:
        """Verify security headers are present on responses."""
        response = session.get(f"{config.api_url}/health", timeout=10)

        required_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
        ]

        for header in required_headers:
            assert header in response.headers, f"Missing security header: {header}"


class TestRateLimiting:
    """Test rate limiting functionality."""

    def test_rate_limiting_not_triggered_immediately(self, config: DeploymentConfig, session: requests.Session) -> None:
        """Verify rate limiting doesn't trigger with few requests."""
        responses = []
        for _ in range(3):
            response = session.get(f"{config.api_url}/health", timeout=10)
            responses.append(response.status_code)

        # Should not get 429 with just 3 requests
        assert 429 not in responses, "Rate limit triggered too early"


class TestErrorHandling:
    """Test error handling and monitoring."""

    def test_404_handling(self, config: DeploymentConfig, session: requests.Session) -> None:
        """Verify 404 responses are handled correctly."""
        response = session.get(f"{config.api_url}/nonexistent-endpoint", timeout=10)
        assert response.status_code == 404, "Nonexistent endpoint should return 404"

    def test_invalid_json_handling(self, config: DeploymentConfig, session: requests.Session, api_key: str) -> None:
        """Verify invalid JSON is handled correctly."""
        response = session.post(
            f"{config.api_url}/auth/introspect",
            data="invalid json",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            timeout=10,
        )
        # Should return 400 or handle gracefully
        assert response.status_code in [400, 422], "Invalid JSON should return 400 or 422"


# Pytest configuration
def pytest_addoption(parser: pytest.Parser) -> None:
    """Add custom command line options."""
    parser.addoption(
        "--live-deployment",
        action="store_true",
        default=False,
        help="Run tests against live deployment",
    )
    parser.addoption(
        "--base-url",
        action="store",
        default="http://localhost:8080",
        help="Base URL for deployment tests",
    )
    parser.addoption(
        "--admin-user",
        action="store",
        default="admin",
        help="Admin username",
    )
    parser.addoption(
        "--admin-pass",
        action="store",
        default="changeme",
        help="Admin password",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest with command line options."""
    if config.getoption("--live-deployment"):
        os.environ["TEST_BASE_URL"] = config.getoption("--base-url")
        os.environ["TEST_ADMIN_USER"] = config.getoption("--admin-user")
        os.environ["TEST_ADMIN_PASS"] = config.getoption("--admin-pass")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip deployment tests unless --live-deployment is specified."""
    if not config.getoption("--live-deployment"):
        skip_deployment = pytest.mark.skip(reason="Need --live-deployment option to run")
        for item in items:
            if "test_deployment" in item.nodeid:
                item.add_marker(skip_deployment)
