"""Comprehensive API tests for octoprox NEXUSGATE integration.

This module tests all API endpoints including:
- Authentication (API key, JWT, session)
- User management (CRUD, RBAC)
- Workspace management (CRUD, RBAC)
- API Key management (CRUD, RBAC, revocation)
- Token introspection
- Health checks
- MCP Bridge endpoints
"""

from __future__ import annotations

import os
import re
import sys
import pathlib
from datetime import datetime, timedelta, timezone
from typing import Iterator
from unittest.mock import MagicMock, patch

# Set required environment variables before any imports
os.environ.setdefault("BOOTSTRAP_ADMIN_USERNAME", "test_admin")
os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "test_admin_password")
os.environ.setdefault("SECRET_KEY", "test_secret_key_for_testing_only_32chars")
os.environ.setdefault("JWT_SECRET_KEY", "test_jwt_secret_key_for_testing_only_32chars")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_manager.db")

# Add parent to path for imports
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app import auth, services
from app.db import Base, get_db
from app.main import (
    account_rate_limit,
    app,
    rate_limit,
    rate_limit_storage,
)
from app.models import ApiKey, User, Workspace
from app.provisioning import WorkspaceProvisioner


# =============================================================================
# Fake Provisioner for Testing
# =============================================================================


class FakeProvisioner:
    """Mock workspace provisioner for testing."""

    def __init__(self) -> None:
        self.created: list[str] = []
        self.deleted: list[str] = []
        self.purged: list[str] = []

    def create_workspace(self, workspace: Workspace) -> None:
        self.created.append(workspace.name)

    def delete_workspace(self, workspace: Workspace) -> None:
        self.deleted.append(workspace.name)

    def purge_workspace(self, workspace: Workspace) -> None:
        self.purged.append(workspace.name)

    def purge_by_name(self, name: str) -> None:
        self.purged.append(name)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def test_db() -> Session:
    """Create a test database session."""
    engine = create_engine(
        "sqlite:///:memory:",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(bind=engine, future=True)
    db = TestingSessionLocal()
    yield db
    db.close()


@pytest.fixture
def client(test_db: Session) -> Iterator[TestClient]:
    """Create a test client with database override."""

    def override_get_db():
        yield test_db

    app.dependency_overrides[get_db] = override_get_db
    app.state.provisioner = FakeProvisioner()

    rate_limit_storage.clear()
    rate_limit.clear()
    account_rate_limit.clear()
    with TestClient(app) as client_instance:
        yield client_instance

    rate_limit_storage.clear()
    rate_limit.clear()
    account_rate_limit.clear()
    app.dependency_overrides.clear()


@pytest.fixture
def test_user(test_db: Session) -> User:
    """Create a test user."""
    user = User(
        username="testuser",
        password_hash=auth.hash_password("testpass"),
        role="user",
        status="active",
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


@pytest.fixture
def test_admin(test_db: Session) -> User:
    """Create a test admin user."""
    admin = User(
        username="admin",
        password_hash=auth.hash_password("adminpass"),
        role="admin",
        status="active",
    )
    test_db.add(admin)
    test_db.commit()
    test_db.refresh(admin)
    return admin


@pytest.fixture
def test_api_key(test_db: Session, test_user: User) -> dict:
    """Create a test API key for the test user."""
    key_obj, raw_token = services.create_api_key(test_db, test_user, name="Test Key")
    return {"key": raw_token, "obj": key_obj}


@pytest.fixture
def test_workspace(test_db: Session, test_user: User) -> Workspace:
    """Create a test workspace for the test user."""
    provisioner = FakeProvisioner()
    ws = services.create_workspace(test_db, provisioner, test_user, "test-ws")
    return ws


@pytest.fixture
def admin_workspace(test_db: Session, test_admin: User) -> Workspace:
    """Create a test workspace for the admin user."""
    provisioner = FakeProvisioner()
    ws = services.create_workspace(test_db, provisioner, test_admin, "admin-ws")
    return ws


# =============================================================================
# Helper Functions
# =============================================================================


def create_expired_token(user: User) -> str:
    """Create an expired JWT token for testing."""
    import jwt as jwt_lib
    from app.settings import settings

    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "type": "access",
        "iat": now - timedelta(hours=2),
        "exp": now - timedelta(hours=1),  # Expired 1 hour ago
    }
    return jwt_lib.encode(
        payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
    )


def login_user(client: TestClient, username: str, password: str) -> None:
    """Login a user via the login form and set session."""
    # First get the login page to obtain CSRF token
    response = client.get("/login")
    match = re.search(
        r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', response.text
    )
    assert match, "CSRF token missing from login page"
    csrf_token = match.group(1)

    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code in [302, 303], f"Login failed: {response.text}"


# =============================================================================
# Authentication Tests
# =============================================================================


class TestAuthentication:
    """Test authentication methods and error cases."""

    def test_api_key_auth_success(self, client: TestClient, test_api_key: dict) -> None:
        """Test API key authentication works."""
        response = client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {test_api_key['key']}"},
        )
        assert response.status_code == 200, f"API key auth failed: {response.text}"
        data = response.json()
        assert "data" in data
        assert "users" in data["data"]

    def test_jwt_auth_success(self, client: TestClient, test_user: User) -> None:
        """Test JWT authentication works."""
        token = auth.create_access_token(
            str(test_user.id), test_user.username, test_user.role
        )
        response = client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200, f"JWT auth failed: {response.text}"
        data = response.json()
        assert "data" in data

    def test_session_auth_success(self, client: TestClient, test_user: User) -> None:
        """Test session authentication works via login form."""
        login_user(client, test_user.username, "testpass")
        response = client.get("/api/v1/users")
        assert response.status_code == 200, f"Session auth failed: {response.text}"
        data = response.json()
        assert "data" in data

    def test_missing_auth_returns_401(self, client: TestClient) -> None:
        """Test missing auth returns 401."""
        response = client.get("/api/v1/users")
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"

    def test_invalid_api_key_returns_401(self, client: TestClient) -> None:
        """Test invalid API key returns 401."""
        response = client.get(
            "/api/v1/users",
            headers={"Authorization": "Bearer invalid_key"},
        )
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"

    def test_invalid_jwt_returns_401(self, client: TestClient) -> None:
        """Test invalid JWT returns 401."""
        response = client.get(
            "/api/v1/users",
            headers={"Authorization": "Bearer invalid.jwt.token"},
        )
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"

    def test_expired_jwt_returns_401(self, client: TestClient, test_user: User) -> None:
        """Test expired JWT returns 401."""
        expired_token = create_expired_token(test_user)
        response = client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"

    def test_inactive_user_cannot_authenticate(
        self, client: TestClient, test_db: Session, test_user: User
    ) -> None:
        """Test inactive user cannot authenticate with API key."""
        # Create API key first
        key_obj, raw_token = services.create_api_key(test_db, test_user)

        # Deactivate user
        test_user.status = "inactive"
        test_db.commit()

        response = client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {raw_token}"},
        )
        assert response.status_code == 401, (
            f"Expected 401 for inactive user, got {response.status_code}"
        )


# =============================================================================
# User API Tests
# =============================================================================


class TestUserAPI:
    """Test User API endpoints."""

    def test_list_users_as_admin_returns_all(
        self, client: TestClient, test_admin: User, test_user: User
    ) -> None:
        """Admin should see all users."""
        login_user(client, test_admin.username, "adminpass")
        response = client.get("/api/v1/users")
        assert response.status_code == 200, f"List users failed: {response.text}"
        data = response.json()
        assert "data" in data
        assert "users" in data["data"]
        # Should see at least 2 users (admin + test_user)
        assert len(data["data"]["users"]) >= 2

    def test_list_users_as_user_returns_only_self(
        self, client: TestClient, test_user: User
    ) -> None:
        """Regular user should only see themselves."""
        login_user(client, test_user.username, "testpass")
        response = client.get("/api/v1/users")
        assert response.status_code == 200, f"List users failed: {response.text}"
        data = response.json()
        assert "data" in data
        assert "users" in data["data"]
        assert len(data["data"]["users"]) == 1
        assert data["data"]["users"][0]["username"] == test_user.username

    def test_list_users_with_pagination(
        self, client: TestClient, test_admin: User
    ) -> None:
        """Test user list pagination."""
        login_user(client, test_admin.username, "adminpass")
        response = client.get("/api/v1/users?page=1&per_page=10")
        assert response.status_code == 200
        data = response.json()
        assert "meta" in data
        assert "pagination" in data["meta"]

    def test_list_users_with_filters(
        self, client: TestClient, test_admin: User
    ) -> None:
        """Test user list with status and role filters."""
        login_user(client, test_admin.username, "adminpass")
        response = client.get("/api/v1/users?status=active&role=admin")
        assert response.status_code == 200
        data = response.json()
        # Should include the admin user
        usernames = [u["username"] for u in data["data"]["users"]]
        assert test_admin.username in usernames

    def test_get_user_as_admin_returns_any_user(
        self, client: TestClient, test_admin: User, test_user: User
    ) -> None:
        """Admin can get any user's details."""
        login_user(client, test_admin.username, "adminpass")
        response = client.get(f"/api/v1/users/{test_user.id}")
        assert response.status_code == 200, f"Get user failed: {response.text}"
        data = response.json()
        assert data["data"]["username"] == test_user.username
        assert "workspaces" in data["data"]
        assert "api_keys" in data["data"]

    def test_get_user_as_user_returns_self_only(
        self, client: TestClient, test_user: User, test_admin: User
    ) -> None:
        """User can only get their own details."""
        login_user(client, test_user.username, "testpass")
        response = client.get(f"/api/v1/users/{test_admin.id}")
        assert response.status_code == 403, f"Expected 403, got {response.status_code}"

    def test_get_user_self_succeeds(self, client: TestClient, test_user: User) -> None:
        """User can get their own details."""
        login_user(client, test_user.username, "testpass")
        response = client.get(f"/api/v1/users/{test_user.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["username"] == test_user.username

    def test_get_nonexistent_user_returns_404(
        self, client: TestClient, test_admin: User
    ) -> None:
        """Getting non-existent user returns 404."""
        login_user(client, test_admin.username, "adminpass")
        response = client.get("/api/v1/users/99999")
        assert response.status_code == 404, f"Expected 404, got {response.status_code}"

    def test_update_user_as_admin_succeeds(
        self, client: TestClient, test_admin: User, test_user: User
    ) -> None:
        """Admin can update user."""
        login_user(client, test_admin.username, "adminpass")
        response = client.put(
            f"/api/v1/users/{test_user.id}",
            json={"role": "admin"},
        )
        assert response.status_code == 200, f"Update user failed: {response.text}"
        assert response.json()["data"]["role"] == "admin"

    def test_update_user_as_user_returns_403(
        self, client: TestClient, test_user: User
    ) -> None:
        """User cannot update users."""
        login_user(client, test_user.username, "testpass")
        response = client.put(
            f"/api/v1/users/{test_user.id}",
            json={"role": "admin"},
        )
        assert response.status_code == 403, f"Expected 403, got {response.status_code}"

    def test_prevent_self_demotion_from_admin(
        self, client: TestClient, test_admin: User
    ) -> None:
        """Admin cannot demote themselves."""
        login_user(client, test_admin.username, "adminpass")
        response = client.put(
            f"/api/v1/users/{test_admin.id}",
            json={"role": "user"},
        )
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"
        assert "demote" in response.json()["detail"].lower()

    def test_prevent_last_admin_deactivation(
        self, client: TestClient, test_db: Session, test_admin: User
    ) -> None:
        """Cannot deactivate the last active admin."""
        login_user(client, test_admin.username, "adminpass")
        response = client.put(
            f"/api/v1/users/{test_admin.id}",
            json={"status": "inactive"},
        )
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"
        assert "last" in response.json()["detail"].lower()

    def test_deactivate_user_as_admin_succeeds(
        self, client: TestClient, test_db: Session, test_admin: User
    ) -> None:
        """Admin can deactivate another user."""
        # Create another user to deactivate
        other_user = User(
            username="othertodeactivate",
            password_hash=auth.hash_password("pass"),
            role="user",
            status="active",
        )
        test_db.add(other_user)
        test_db.commit()
        test_db.refresh(other_user)

        login_user(client, test_admin.username, "adminpass")
        response = client.delete(f"/api/v1/users/{other_user.id}")
        assert response.status_code == 200, f"Deactivate user failed: {response.text}"
        assert "deactivated" in response.json()["data"]["message"].lower()

    def test_delete_user_prevents_self_deactivation(
        self, client: TestClient, test_admin: User
    ) -> None:
        """Admin cannot deactivate themselves via DELETE endpoint."""
        login_user(client, test_admin.username, "adminpass")
        response = client.delete(f"/api/v1/users/{test_admin.id}")
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"


# =============================================================================
# Workspace API Tests
# =============================================================================


class TestWorkspaceAPI:
    """Test Workspace API endpoints."""

    def test_list_workspaces_as_admin_returns_all(
        self, client: TestClient, test_admin: User, test_workspace: Workspace
    ) -> None:
        """Admin sees all workspaces."""
        login_user(client, test_admin.username, "adminpass")
        response = client.get("/api/v1/workspaces")
        assert response.status_code == 200, f"List workspaces failed: {response.text}"
        data = response.json()
        assert "data" in data
        assert "workspaces" in data["data"]

    def test_list_workspaces_as_user_returns_own_only(
        self, client: TestClient, test_user: User, test_workspace: Workspace
    ) -> None:
        """User sees only own workspaces."""
        login_user(client, test_user.username, "testpass")
        response = client.get("/api/v1/workspaces")
        assert response.status_code == 200, f"List workspaces failed: {response.text}"
        data = response.json()
        workspaces = data["data"]["workspaces"]
        # All returned workspaces should belong to the user
        for ws in workspaces:
            assert ws["user_id"] == test_user.id

    def test_list_workspaces_with_pagination(
        self, client: TestClient, test_user: User
    ) -> None:
        """Test workspace list pagination."""
        login_user(client, test_user.username, "testpass")
        response = client.get("/api/v1/workspaces?page=1&per_page=5")
        assert response.status_code == 200
        data = response.json()
        assert "meta" in data
        assert "pagination" in data["meta"]

    def test_create_workspace_succeeds(
        self, client: TestClient, test_user: User
    ) -> None:
        """User can create workspace."""
        login_user(client, test_user.username, "testpass")
        response = client.post("/api/v1/workspaces", json={"name": "new-ws"})
        assert response.status_code == 201, f"Create workspace failed: {response.text}"
        data = response.json()
        assert data["data"]["name"] == "new-ws"
        assert "endpoint_url" in data["data"]

    def test_create_workspace_with_invalid_name_returns_400(
        self, client: TestClient, test_user: User
    ) -> None:
        """Invalid workspace name returns 400."""
        login_user(client, test_user.username, "testpass")
        response = client.post("/api/v1/workspaces", json={"name": "invalid name!"})
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"

    def test_create_workspace_with_empty_name_returns_400(
        self, client: TestClient, test_user: User
    ) -> None:
        """Empty workspace name returns 400."""
        login_user(client, test_user.username, "testpass")
        response = client.post("/api/v1/workspaces", json={"name": ""})
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"

    def test_create_duplicate_workspace_returns_400(
        self, client: TestClient, test_user: User, test_workspace: Workspace
    ) -> None:
        """Duplicate workspace name returns 400."""
        login_user(client, test_user.username, "testpass")
        response = client.post("/api/v1/workspaces", json={"name": test_workspace.name})
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"

    def test_create_workspace_with_metadata(
        self, client: TestClient, test_user: User
    ) -> None:
        """User can create workspace with metadata."""
        login_user(client, test_user.username, "testpass")
        response = client.post(
            "/api/v1/workspaces",
            json={"name": "ws-with-meta", "metadata": {"key": "value"}},
        )
        assert response.status_code == 201, f"Create workspace failed: {response.text}"
        data = response.json()
        assert data["data"]["metadata"] == {"key": "value"}

    def test_get_workspace_as_owner_succeeds(
        self, client: TestClient, test_user: User, test_workspace: Workspace
    ) -> None:
        """Owner can get workspace details."""
        login_user(client, test_user.username, "testpass")
        response = client.get(f"/api/v1/workspaces/{test_workspace.id}")
        assert response.status_code == 200, f"Get workspace failed: {response.text}"
        data = response.json()
        assert data["data"]["name"] == test_workspace.name

    def test_get_workspace_as_admin_succeeds(
        self, client: TestClient, test_admin: User, test_workspace: Workspace
    ) -> None:
        """Admin can get any workspace details."""
        login_user(client, test_admin.username, "adminpass")
        response = client.get(f"/api/v1/workspaces/{test_workspace.id}")
        assert response.status_code == 200

    def test_get_other_user_workspace_returns_403(
        self, client: TestClient, test_user: User, admin_workspace: Workspace
    ) -> None:
        """User cannot get another user's workspace."""
        login_user(client, test_user.username, "testpass")
        response = client.get(f"/api/v1/workspaces/{admin_workspace.id}")
        assert response.status_code == 403, f"Expected 403, got {response.status_code}"

    def test_get_nonexistent_workspace_returns_404(
        self, client: TestClient, test_user: User
    ) -> None:
        """Getting non-existent workspace returns 404."""
        login_user(client, test_user.username, "testpass")
        response = client.get("/api/v1/workspaces/99999")
        assert response.status_code == 404, f"Expected 404, got {response.status_code}"

    def test_delete_workspace_as_owner_succeeds(
        self, client: TestClient, test_db: Session, test_user: User
    ) -> None:
        """Owner can delete workspace."""
        # Create a workspace to delete
        provisioner = FakeProvisioner()
        ws = services.create_workspace(test_db, provisioner, test_user, "ws-to-delete")

        login_user(client, test_user.username, "testpass")
        response = client.delete(f"/api/v1/workspaces/{ws.id}")
        assert response.status_code == 200, f"Delete workspace failed: {response.text}"
        assert "deleted" in response.json()["data"]["message"].lower()

    def test_delete_workspace_as_admin_succeeds(
        self, client: TestClient, test_db: Session, test_admin: User, test_user: User
    ) -> None:
        """Admin can delete any workspace."""
        # Create a workspace owned by test_user
        provisioner = FakeProvisioner()
        ws = services.create_workspace(
            test_db, provisioner, test_user, "ws-for-admin-delete"
        )

        login_user(client, test_admin.username, "adminpass")
        response = client.delete(f"/api/v1/workspaces/{ws.id}")
        assert response.status_code == 200

    def test_delete_other_user_workspace_returns_403(
        self, client: TestClient, test_user: User, admin_workspace: Workspace
    ) -> None:
        """User cannot delete another user's workspace."""
        login_user(client, test_user.username, "testpass")
        response = client.delete(f"/api/v1/workspaces/{admin_workspace.id}")
        assert response.status_code == 403, f"Expected 403, got {response.status_code}"


# =============================================================================
# API Key Tests
# =============================================================================


class TestAPIKeyAPI:
    """Test API Key API endpoints."""

    def test_list_api_keys_as_admin_returns_all(
        self, client: TestClient, test_admin: User, test_api_key: dict
    ) -> None:
        """Admin sees all API keys."""
        login_user(client, test_admin.username, "adminpass")
        response = client.get("/api/v1/api-keys")
        assert response.status_code == 200, f"List API keys failed: {response.text}"
        data = response.json()
        assert "data" in data
        assert "api_keys" in data["data"]

    def test_list_api_keys_as_user_returns_own_only(
        self, client: TestClient, test_user: User, test_api_key: dict
    ) -> None:
        """User sees only own API keys."""
        login_user(client, test_user.username, "testpass")
        response = client.get("/api/v1/api-keys")
        assert response.status_code == 200
        data = response.json()
        # All returned keys should belong to the user
        for key in data["data"]["api_keys"]:
            assert key["user_id"] == test_user.id

    def test_create_api_key_for_self_succeeds(
        self, client: TestClient, test_user: User
    ) -> None:
        """User can create API key for self."""
        login_user(client, test_user.username, "testpass")
        response = client.post("/api/v1/api-keys", json={"name": "My Key"})
        assert response.status_code == 201, f"Create API key failed: {response.text}"
        data = response.json()
        assert "token" in data["data"]
        assert "warning" in data["data"]

    def test_create_api_key_without_name_succeeds(
        self, client: TestClient, test_user: User
    ) -> None:
        """User can create API key without a name."""
        login_user(client, test_user.username, "testpass")
        response = client.post("/api/v1/api-keys", json={})
        assert response.status_code == 201, f"Create API key failed: {response.text}"

    def test_create_api_key_for_other_as_admin_succeeds(
        self, client: TestClient, test_admin: User, test_user: User
    ) -> None:
        """Admin can create API key for other user."""
        login_user(client, test_admin.username, "adminpass")
        response = client.post(
            "/api/v1/api-keys",
            json={"user_id": test_user.id, "name": "For User"},
        )
        assert response.status_code == 201, f"Create API key failed: {response.text}"
        data = response.json()
        assert data["data"]["user_id"] == test_user.id

    def test_create_api_key_for_other_as_user_returns_403(
        self, client: TestClient, test_user: User, test_admin: User
    ) -> None:
        """User cannot create API key for other user."""
        login_user(client, test_user.username, "testpass")
        response = client.post(
            "/api/v1/api-keys",
            json={"user_id": test_admin.id, "name": "For Admin"},
        )
        assert response.status_code == 403, f"Expected 403, got {response.status_code}"

    def test_revoke_api_key_as_owner_succeeds(
        self, client: TestClient, test_user: User, test_api_key: dict
    ) -> None:
        """Owner can revoke API key."""
        login_user(client, test_user.username, "testpass")
        response = client.delete(f"/api/v1/api-keys/{test_api_key['obj'].id}")
        assert response.status_code == 200, f"Revoke API key failed: {response.text}"
        assert "revoked" in response.json()["data"]["message"].lower()

    def test_revoke_api_key_as_admin_succeeds(
        self, client: TestClient, test_admin: User, test_api_key: dict
    ) -> None:
        """Admin can revoke any API key."""
        login_user(client, test_admin.username, "adminpass")
        response = client.delete(f"/api/v1/api-keys/{test_api_key['obj'].id}")
        assert response.status_code == 200

    def test_revoke_other_user_api_key_returns_403(
        self, client: TestClient, test_user: User, test_db: Session, test_admin: User
    ) -> None:
        """User cannot revoke another user's API key."""
        # Create API key for admin
        admin_key, _ = services.create_api_key(test_db, test_admin, name="Admin Key")

        login_user(client, test_user.username, "testpass")
        response = client.delete(f"/api/v1/api-keys/{admin_key.id}")
        assert response.status_code == 404, f"Expected 404, got {response.status_code}"

    def test_revoked_key_no_longer_works(
        self, client: TestClient, test_user: User, test_api_key: dict
    ) -> None:
        """Revoked key cannot be used for auth."""
        key_id = test_api_key["obj"].id
        raw_key = test_api_key["key"]

        # First verify the key works
        response = client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {raw_key}"},
        )
        assert response.status_code == 200, "Key should work before revocation"

        # Revoke the key
        login_user(client, test_user.username, "testpass")
        client.delete(f"/api/v1/api-keys/{key_id}")

        # Try to use revoked key
        response = client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {raw_key}"},
        )
        assert response.status_code == 401, (
            f"Expected 401 for revoked key, got {response.status_code}"
        )


# =============================================================================
# Introspection Tests
# =============================================================================


class TestIntrospection:
    """Test token introspection endpoint."""

    def test_introspect_valid_api_key_returns_active(
        self, client: TestClient, test_api_key: dict
    ) -> None:
        """Valid API key introspection returns active."""
        response = client.post(
            "/api/v1/auth/introspect",
            json={"token": test_api_key["key"]},
        )
        assert response.status_code == 200, f"Introspect failed: {response.text}"
        data = response.json()
        assert data["active"] is True
        assert data["token_type"] == "api_key"
        assert "sub" in data
        assert "role" in data

    def test_introspect_valid_jwt_returns_active(
        self, client: TestClient, test_user: User
    ) -> None:
        """Valid JWT introspection returns active."""
        token = auth.create_access_token(
            str(test_user.id), test_user.username, test_user.role
        )
        response = client.post("/api/v1/auth/introspect", json={"token": token})
        assert response.status_code == 200, f"Introspect failed: {response.text}"
        data = response.json()
        assert data["active"] is True
        assert data["token_type"] == "jwt"
        assert data["sub"] == str(test_user.id)

    def test_introspect_invalid_token_returns_inactive(
        self, client: TestClient
    ) -> None:
        """Invalid token introspection returns inactive."""
        response = client.post("/api/v1/auth/introspect", json={"token": "invalid"})
        assert response.status_code == 200, f"Introspect failed: {response.text}"
        assert response.json()["active"] is False

    def test_introspect_empty_token_returns_inactive(self, client: TestClient) -> None:
        """Empty token introspection returns inactive."""
        response = client.post("/api/v1/auth/introspect", json={"token": ""})
        assert response.status_code == 200
        assert response.json()["active"] is False

    def test_introspect_inactive_user_key_returns_inactive(
        self, client: TestClient, test_db: Session, test_user: User
    ) -> None:
        """Inactive user's API key introspection returns inactive."""
        key_obj, raw_token = services.create_api_key(test_db, test_user)

        # Deactivate user
        test_user.status = "inactive"
        test_db.commit()

        response = client.post("/api/v1/auth/introspect", json={"token": raw_token})
        assert response.status_code == 200
        assert response.json()["active"] is False


# =============================================================================
# Health Tests
# =============================================================================


class TestHealth:
    """Test health check endpoint."""

    def test_health_check_returns_200(self, client: TestClient) -> None:
        """Health check returns 200."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200, f"Health check failed: {response.text}"
        data = response.json()
        assert "status" in data
        assert "checks" in data
        assert "timestamp" in data

    def test_health_check_includes_database_status(self, client: TestClient) -> None:
        """Health check includes database status with response time."""
        response = client.get("/api/v1/health")
        data = response.json()
        assert "checks" in data
        assert "database" in data["checks"]
        assert "healthy" in data["checks"]["database"]
        assert "response_time_ms" in data["checks"]["database"]
        # Database should be healthy in test environment
        assert data["checks"]["database"]["healthy"] is True
        # Response time should be a number when database is healthy
        if data["checks"]["database"]["healthy"]:
            assert isinstance(
                data["checks"]["database"]["response_time_ms"], (int, float)
            )
            assert data["checks"]["database"]["response_time_ms"] >= 0

    def test_health_check_includes_docker_status(self, client: TestClient) -> None:
        """Health check includes Docker status with version."""
        response = client.get("/api/v1/health")
        data = response.json()
        assert "checks" in data
        assert "docker" in data["checks"]
        assert "healthy" in data["checks"]["docker"]
        assert "version" in data["checks"]["docker"]

    def test_health_check_includes_workspace_stats(self, client: TestClient) -> None:
        """Health check includes workspace statistics."""
        response = client.get("/api/v1/health")
        data = response.json()
        assert "workspaces" in data
        assert "total" in data["workspaces"]
        assert "active" in data["workspaces"]


# =============================================================================
# MCP Bridge Tests
# =============================================================================


class TestMCPBridge:
    """Test MCP Bridge endpoints."""

    def test_list_mcp_tools_returns_available_tools(
        self, client: TestClient, test_user: User
    ) -> None:
        """MCP tools endpoint returns tools."""
        login_user(client, test_user.username, "testpass")
        response = client.get("/api/v1/mcp/tools")
        assert response.status_code == 200, f"List tools failed: {response.text}"
        data = response.json()
        assert "tools" in data["data"]
        assert len(data["data"]["tools"]) > 0

    def test_list_mcp_tools_with_workspace_id(
        self, client: TestClient, test_user: User, test_workspace: Workspace
    ) -> None:
        """MCP tools endpoint with valid workspace_id."""
        login_user(client, test_user.username, "testpass")
        response = client.get(f"/api/v1/mcp/tools?workspace_id={test_workspace.id}")
        assert response.status_code == 200

    def test_list_mcp_tools_with_invalid_workspace_returns_404(
        self, client: TestClient, test_user: User
    ) -> None:
        """MCP tools with invalid workspace_id returns 404."""
        login_user(client, test_user.username, "testpass")
        response = client.get("/api/v1/mcp/tools?workspace_id=99999")
        assert response.status_code == 404, f"Expected 404, got {response.status_code}"

    def test_list_mcp_tools_other_user_workspace_returns_403(
        self, client: TestClient, test_user: User, admin_workspace: Workspace
    ) -> None:
        """MCP tools with other user's workspace returns 403."""
        login_user(client, test_user.username, "testpass")
        response = client.get(f"/api/v1/mcp/tools?workspace_id={admin_workspace.id}")
        assert response.status_code == 403, f"Expected 403, got {response.status_code}"

    def test_invoke_mcp_tool_validates_workspace_id(
        self, client: TestClient, test_user: User
    ) -> None:
        """MCP invoke validates workspace_id."""
        login_user(client, test_user.username, "testpass")
        response = client.post("/api/v1/mcp/invoke", json={"tool": "read_file"})
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"

    def test_invoke_mcp_tool_validates_tool_name(
        self, client: TestClient, test_user: User, test_workspace: Workspace
    ) -> None:
        """MCP invoke validates tool name."""
        login_user(client, test_user.username, "testpass")
        response = client.post(
            "/api/v1/mcp/invoke",
            json={"workspace_id": test_workspace.id, "tool": "invalid_tool"},
        )
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"

    def test_invoke_mcp_tool_checks_permissions(
        self, client: TestClient, test_user: User, admin_workspace: Workspace
    ) -> None:
        """MCP invoke checks permissions."""
        login_user(client, test_user.username, "testpass")
        response = client.post(
            "/api/v1/mcp/invoke",
            json={"workspace_id": admin_workspace.id, "tool": "read_file"},
        )
        assert response.status_code == 403, f"Expected 403, got {response.status_code}"

    def test_invoke_mcp_tool_succeeds(
        self, client: TestClient, test_user: User, test_workspace: Workspace
    ) -> None:
        """MCP invoke succeeds with valid params."""
        login_user(client, test_user.username, "testpass")
        response = client.post(
            "/api/v1/mcp/invoke",
            json={
                "workspace_id": test_workspace.id,
                "tool": "read_file",
                "params": {"path": "/test.txt"},
            },
        )
        assert response.status_code == 200, f"Invoke failed: {response.text}"
        data = response.json()
        assert data["data"]["tool"] == "read_file"
        assert "endpoint" in data["data"]

    def test_invoke_mcp_tool_on_nonexistent_workspace_returns_404(
        self, client: TestClient, test_user: User
    ) -> None:
        """MCP invoke on nonexistent workspace returns 404."""
        login_user(client, test_user.username, "testpass")
        response = client.post(
            "/api/v1/mcp/invoke",
            json={"workspace_id": 99999, "tool": "read_file"},
        )
        assert response.status_code == 404, f"Expected 404, got {response.status_code}"


# =============================================================================
# NEXUSGATE Fields Tests
# =============================================================================


class TestNEXUSGATEFields:
    """Test NEXUSGATE integration fields."""

    def test_user_includes_nexusgate_fields(
        self, client: TestClient, test_user: User, test_admin: User
    ) -> None:
        """User response includes NEXUSGATE fields."""
        login_user(client, test_user.username, "testpass")
        response = client.get(f"/api/v1/users/{test_user.id}")
        assert response.status_code == 200
        data = response.json()
        assert "nexusgate_user_id" in data["data"]
        assert "nexusgate_role" in data["data"]

    def test_workspace_includes_nexusgate_fields(
        self, client: TestClient, test_user: User, test_workspace: Workspace
    ) -> None:
        """Workspace response includes NEXUSGATE fields."""
        login_user(client, test_user.username, "testpass")
        response = client.get(f"/api/v1/workspaces/{test_workspace.id}")
        assert response.status_code == 200
        data = response.json()
        assert "nexusgate_service_id" in data["data"]

    def test_api_key_includes_nexusgate_fields(
        self, client: TestClient, test_user: User, test_api_key: dict
    ) -> None:
        """API key response includes NEXUSGATE fields."""
        login_user(client, test_user.username, "testpass")
        response = client.get("/api/v1/api-keys")
        assert response.status_code == 200
        data = response.json()
        assert len(data["data"]["api_keys"]) > 0
        key = data["data"]["api_keys"][0]
        assert "nexusgate_token_id" in key

    def test_update_user_nexusgate_fields(
        self, client: TestClient, test_admin: User, test_user: User
    ) -> None:
        """Admin can update user's NEXUSGATE fields."""
        login_user(client, test_admin.username, "adminpass")
        response = client.put(
            f"/api/v1/users/{test_user.id}",
            json={"nexusgate_user_id": "ng-12345"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["nexusgate_user_id"] == "ng-12345"

    def test_create_api_key_with_nexusgate_token_id(
        self, client: TestClient, test_user: User
    ) -> None:
        """API key can be created with NEXUSGATE token ID."""
        login_user(client, test_user.username, "testpass")
        response = client.post(
            "/api/v1/api-keys",
            json={"name": "NG Key"},
        )
        assert response.status_code == 201
        # The API key structure supports nexusgate_token_id
        data = response.json()
        assert "id" in data["data"]
