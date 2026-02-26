"""Comprehensive REST API tests for workspace-manager.

This module tests all REST API v1 endpoints including:
- User management (CRUD, RBAC)
- Workspace management (CRUD, RBAC)
- API Key management (CRUD, RBAC, revocation)
- Token introspection
- Authentication flows (session, API key, JWT)
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
# User Endpoint Tests (12.10.2)
# =============================================================================


class TestUserEndpoints:
    """Test User API endpoints."""

    def test_list_users_as_admin_returns_all(
        self, client: TestClient, test_admin: User, test_user: User
    ) -> None:
        """GET /api/v1/users - Admin should see all users with pagination."""
        login_user(client, test_admin.username, "adminpass")
        response = client.get("/api/v1/users")
        assert response.status_code == 200, f"List users failed: {response.text}"
        data = response.json()
        assert "data" in data
        assert "users" in data["data"]
        # Should see at least 2 users (admin + test_user)
        assert len(data["data"]["users"]) >= 2
        # Check pagination meta
        assert "meta" in data
        assert "pagination" in data["meta"]

    def test_list_users_as_user_returns_only_self(
        self, client: TestClient, test_user: User
    ) -> None:
        """GET /api/v1/users - Regular user should only see themselves."""
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
        """GET /api/v1/users - Test user list pagination."""
        login_user(client, test_admin.username, "adminpass")
        response = client.get("/api/v1/users?page=1&per_page=10")
        assert response.status_code == 200
        data = response.json()
        assert "meta" in data
        assert "pagination" in data["meta"]
        pagination = data["meta"]["pagination"]
        assert "page" in pagination
        assert "per_page" in pagination
        assert "total" in pagination
        assert "total_pages" in pagination

    def test_list_users_with_filters(
        self, client: TestClient, test_admin: User
    ) -> None:
        """GET /api/v1/users - Test user list with status and role filters."""
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
        """GET /api/v1/users/{id} - Admin can get any user's details."""
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
        """GET /api/v1/users/{id} - User can only get their own details."""
        login_user(client, test_user.username, "testpass")
        response = client.get(f"/api/v1/users/{test_admin.id}")
        assert response.status_code == 403, f"Expected 403, got {response.status_code}"

    def test_get_user_self_succeeds(self, client: TestClient, test_user: User) -> None:
        """GET /api/v1/users/{id} - User can get their own details."""
        login_user(client, test_user.username, "testpass")
        response = client.get(f"/api/v1/users/{test_user.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["data"]["username"] == test_user.username

    def test_get_nonexistent_user_returns_404(
        self, client: TestClient, test_admin: User
    ) -> None:
        """GET /api/v1/users/{id} - Getting non-existent user returns 404."""
        login_user(client, test_admin.username, "adminpass")
        response = client.get("/api/v1/users/99999")
        assert response.status_code == 404, f"Expected 404, got {response.status_code}"

    def test_update_user_as_admin_succeeds(
        self, client: TestClient, test_admin: User, test_user: User
    ) -> None:
        """PUT /api/v1/users/{id} - Admin can update user (admin only)."""
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
        """PUT /api/v1/users/{id} - User cannot update users."""
        login_user(client, test_user.username, "testpass")
        response = client.put(
            f"/api/v1/users/{test_user.id}",
            json={"role": "admin"},
        )
        assert response.status_code == 403, f"Expected 403, got {response.status_code}"

    def test_prevent_self_demotion_from_admin(
        self, client: TestClient, test_admin: User
    ) -> None:
        """PUT /api/v1/users/{id} - Admin cannot demote themselves."""
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
        """PUT /api/v1/users/{id} - Cannot deactivate the last active admin."""
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
        """DELETE /api/v1/users/{id} - Admin can deactivate another user."""
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
        """DELETE /api/v1/users/{id} - Admin cannot deactivate themselves via DELETE endpoint."""
        login_user(client, test_admin.username, "adminpass")
        response = client.delete(f"/api/v1/users/{test_admin.id}")
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"


# =============================================================================
# Workspace Endpoint Tests (12.10.3)
# =============================================================================


class TestWorkspaceEndpoints:
    """Test Workspace API endpoints."""

    def test_list_workspaces_as_admin_returns_all(
        self, client: TestClient, test_admin: User, test_workspace: Workspace
    ) -> None:
        """GET /api/v1/workspaces - Admin sees all workspaces."""
        login_user(client, test_admin.username, "adminpass")
        response = client.get("/api/v1/workspaces")
        assert response.status_code == 200, f"List workspaces failed: {response.text}"
        data = response.json()
        assert "data" in data
        assert "workspaces" in data["data"]

    def test_list_workspaces_as_user_returns_own_only(
        self, client: TestClient, test_user: User, test_workspace: Workspace
    ) -> None:
        """GET /api/v1/workspaces - User sees only own workspaces."""
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
        """GET /api/v1/workspaces - Test workspace list pagination."""
        login_user(client, test_user.username, "testpass")
        response = client.get("/api/v1/workspaces?page=1&per_page=5")
        assert response.status_code == 200
        data = response.json()
        assert "meta" in data
        assert "pagination" in data["meta"]

    def test_create_workspace_succeeds(
        self, client: TestClient, test_user: User
    ) -> None:
        """POST /api/v1/workspaces - User can create workspace."""
        login_user(client, test_user.username, "testpass")
        response = client.post("/api/v1/workspaces", json={"name": "new-ws"})
        assert response.status_code == 201, f"Create workspace failed: {response.text}"
        data = response.json()
        assert data["data"]["name"] == "new-ws"
        assert "endpoint_url" in data["data"]

    def test_create_workspace_with_invalid_name_returns_400(
        self, client: TestClient, test_user: User
    ) -> None:
        """POST /api/v1/workspaces - Invalid workspace name returns 400."""
        login_user(client, test_user.username, "testpass")
        response = client.post("/api/v1/workspaces", json={"name": "invalid name!"})
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"

    def test_create_workspace_with_empty_name_returns_400(
        self, client: TestClient, test_user: User
    ) -> None:
        """POST /api/v1/workspaces - Empty workspace name returns 400."""
        login_user(client, test_user.username, "testpass")
        response = client.post("/api/v1/workspaces", json={"name": ""})
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"

    def test_create_duplicate_workspace_returns_400(
        self, client: TestClient, test_user: User, test_workspace: Workspace
    ) -> None:
        """POST /api/v1/workspaces - Duplicate workspace name returns 400."""
        login_user(client, test_user.username, "testpass")
        response = client.post("/api/v1/workspaces", json={"name": test_workspace.name})
        assert response.status_code == 400, f"Expected 400, got {response.status_code}"

    def test_create_workspace_with_metadata(
        self, client: TestClient, test_user: User
    ) -> None:
        """POST /api/v1/workspaces - User can create workspace with metadata."""
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
        """GET /api/v1/workspaces/{id} - Owner can get workspace details."""
        login_user(client, test_user.username, "testpass")
        response = client.get(f"/api/v1/workspaces/{test_workspace.id}")
        assert response.status_code == 200, f"Get workspace failed: {response.text}"
        data = response.json()
        assert data["data"]["name"] == test_workspace.name

    def test_get_workspace_as_admin_succeeds(
        self, client: TestClient, test_admin: User, test_workspace: Workspace
    ) -> None:
        """GET /api/v1/workspaces/{id} - Admin can get any workspace details."""
        login_user(client, test_admin.username, "adminpass")
        response = client.get(f"/api/v1/workspaces/{test_workspace.id}")
        assert response.status_code == 200

    def test_get_other_user_workspace_returns_403(
        self, client: TestClient, test_user: User, admin_workspace: Workspace
    ) -> None:
        """GET /api/v1/workspaces/{id} - User cannot get another user's workspace."""
        login_user(client, test_user.username, "testpass")
        response = client.get(f"/api/v1/workspaces/{admin_workspace.id}")
        assert response.status_code == 403, f"Expected 403, got {response.status_code}"

    def test_get_nonexistent_workspace_returns_404(
        self, client: TestClient, test_user: User
    ) -> None:
        """GET /api/v1/workspaces/{id} - Getting non-existent workspace returns 404."""
        login_user(client, test_user.username, "testpass")
        response = client.get("/api/v1/workspaces/99999")
        assert response.status_code == 404, f"Expected 404, got {response.status_code}"

    def test_delete_workspace_as_owner_succeeds(
        self, client: TestClient, test_db: Session, test_user: User
    ) -> None:
        """DELETE /api/v1/workspaces/{id} - Owner can delete (soft-delete) workspace."""
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
        """DELETE /api/v1/workspaces/{id} - Admin can delete any workspace."""
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
        """DELETE /api/v1/workspaces/{id} - User cannot delete another user's workspace."""
        login_user(client, test_user.username, "testpass")
        response = client.delete(f"/api/v1/workspaces/{admin_workspace.id}")
        assert response.status_code == 403, f"Expected 403, got {response.status_code}"


# =============================================================================
# API Key Endpoint Tests (12.10.4)
# =============================================================================


class TestAPIKeyEndpoints:
    """Test API Key API endpoints."""

    def test_list_api_keys_as_admin_returns_all(
        self, client: TestClient, test_admin: User, test_api_key: dict
    ) -> None:
        """GET /api/v1/api-keys - Admin sees all API keys."""
        login_user(client, test_admin.username, "adminpass")
        response = client.get("/api/v1/api-keys")
        assert response.status_code == 200, f"List API keys failed: {response.text}"
        data = response.json()
        assert "data" in data
        assert "api_keys" in data["data"]

    def test_list_api_keys_as_user_returns_own_only(
        self, client: TestClient, test_user: User, test_api_key: dict
    ) -> None:
        """GET /api/v1/api-keys - User sees only own API keys."""
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
        """POST /api/v1/api-keys - User can create API key for self."""
        login_user(client, test_user.username, "testpass")
        response = client.post("/api/v1/api-keys", json={"name": "My Key"})
        assert response.status_code == 201, f"Create API key failed: {response.text}"
        data = response.json()
        assert "token" in data["data"]
        assert "warning" in data["data"]

    def test_create_api_key_without_name_succeeds(
        self, client: TestClient, test_user: User
    ) -> None:
        """POST /api/v1/api-keys - User can create API key without a name."""
        login_user(client, test_user.username, "testpass")
        response = client.post("/api/v1/api-keys", json={})
        assert response.status_code == 201, f"Create API key failed: {response.text}"

    def test_create_api_key_for_other_as_admin_succeeds(
        self, client: TestClient, test_admin: User, test_user: User
    ) -> None:
        """POST /api/v1/api-keys - Admin can create API key for other user."""
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
        """POST /api/v1/api-keys - User cannot create API key for other user."""
        login_user(client, test_user.username, "testpass")
        response = client.post(
            "/api/v1/api-keys",
            json={"user_id": test_admin.id, "name": "For Admin"},
        )
        assert response.status_code == 403, f"Expected 403, got {response.status_code}"

    def test_revoke_api_key_as_owner_succeeds(
        self, client: TestClient, test_user: User, test_api_key: dict
    ) -> None:
        """DELETE /api/v1/api-keys/{id} - Owner can revoke API key."""
        login_user(client, test_user.username, "testpass")
        response = client.delete(f"/api/v1/api-keys/{test_api_key['obj'].id}")
        assert response.status_code == 200, f"Revoke API key failed: {response.text}"
        assert "revoked" in response.json()["data"]["message"].lower()

    def test_revoke_api_key_as_admin_succeeds(
        self, client: TestClient, test_admin: User, test_api_key: dict
    ) -> None:
        """DELETE /api/v1/api-keys/{id} - Admin can revoke any API key."""
        login_user(client, test_admin.username, "adminpass")
        response = client.delete(f"/api/v1/api-keys/{test_api_key['obj'].id}")
        assert response.status_code == 200

    def test_revoke_other_user_api_key_returns_404(
        self, client: TestClient, test_user: User, test_db: Session, test_admin: User
    ) -> None:
        """DELETE /api/v1/api-keys/{id} - User cannot revoke another user's API key."""
        # Create API key for admin
        admin_key, _ = services.create_api_key(test_db, test_admin, name="Admin Key")

        login_user(client, test_user.username, "testpass")
        response = client.delete(f"/api/v1/api-keys/{admin_key.id}")
        assert response.status_code == 404, f"Expected 404, got {response.status_code}"


# =============================================================================
# Token Introspection Tests (12.10.5)
# =============================================================================


class TestTokenIntrospection:
    """Test token introspection endpoint."""

    def test_introspect_valid_api_key_returns_active(
        self, client: TestClient, test_api_key: dict
    ) -> None:
        """POST /api/v1/auth/introspect - Valid API key introspection returns active."""
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
        """POST /api/v1/auth/introspect - Valid JWT introspection returns active."""
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
        """POST /api/v1/auth/introspect - Invalid token introspection returns inactive."""
        response = client.post("/api/v1/auth/introspect", json={"token": "invalid"})
        assert response.status_code == 200, f"Introspect failed: {response.text}"
        assert response.json()["active"] is False

    def test_introspect_empty_token_returns_inactive(self, client: TestClient) -> None:
        """POST /api/v1/auth/introspect - Empty token introspection returns inactive."""
        response = client.post("/api/v1/auth/introspect", json={"token": ""})
        assert response.status_code == 200
        assert response.json()["active"] is False

    def test_introspect_with_secret_header(
        self, client: TestClient, test_api_key: dict
    ) -> None:
        """POST /api/v1/auth/introspect - Test with optional secret header."""
        # This test validates the endpoint accepts the header
        response = client.post(
            "/api/v1/auth/introspect",
            json={"token": test_api_key["key"]},
            headers={"X-Introspect-Secret": "some-secret"},
        )
        # Should work with or without valid secret (depends on settings)
        assert response.status_code in [200, 401]


# =============================================================================
# Authentication Flow Tests (12.10.7)
# =============================================================================


class TestAuthenticationFlows:
    """Test different authentication methods."""

    def test_session_based_authentication(
        self, client: TestClient, test_user: User
    ) -> None:
        """Test session-based authentication via login form."""
        # Login first
        login_user(client, test_user.username, "testpass")

        # Access protected endpoint
        response = client.get("/api/v1/users")
        assert response.status_code == 200, f"Session auth failed: {response.text}"
        data = response.json()
        assert "data" in data

    def test_api_key_authentication(
        self, client: TestClient, test_api_key: dict
    ) -> None:
        """Test API key authentication (mcp_* prefix)."""
        response = client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {test_api_key['key']}"},
        )
        assert response.status_code == 200, f"API key auth failed: {response.text}"
        data = response.json()
        assert "data" in data
        assert "users" in data["data"]

    def test_jwt_bearer_authentication(
        self, client: TestClient, test_user: User
    ) -> None:
        """Test JWT Bearer authentication."""
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

    def test_missing_auth_returns_401(self, client: TestClient) -> None:
        """Test 401 when all authentication methods fail."""
        # Clear any existing session/cookies
        client.cookies.clear()

        response = client.get("/api/v1/users")
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"
        assert "WWW-Authenticate" in response.headers

    def test_invalid_api_key_returns_401(self, client: TestClient) -> None:
        """Test invalid API key returns 401."""
        response = client.get(
            "/api/v1/users",
            headers={"Authorization": "Bearer mcp_invalid_key_12345"},
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
        import jwt as jwt_lib
        from app.settings import settings

        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(test_user.id),
            "username": test_user.username,
            "role": test_user.role,
            "type": "access",
            "iat": now - timedelta(hours=2),
            "exp": now - timedelta(hours=1),  # Expired 1 hour ago
        }
        expired_token = jwt_lib.encode(
            payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
        )

        response = client.get(
            "/api/v1/users",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert response.status_code == 401, f"Expected 401, got {response.status_code}"

    def test_inactive_user_api_key_returns_401(
        self, client: TestClient, test_db: Session, test_user: User
    ) -> None:
        """Test inactive user's API key returns 401."""
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
# Health Endpoint Tests
# =============================================================================


class TestHealthEndpoint:
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

    def test_health_check_includes_workspace_stats(self, client: TestClient) -> None:
        """Health check includes workspace statistics."""
        response = client.get("/api/v1/health")
        data = response.json()
        assert "workspaces" in data
        assert "total" in data["workspaces"]
        assert "active" in data["workspaces"]


# =============================================================================
# Additional Edge Case Tests
# =============================================================================


class TestEdgeCases:
    """Test edge cases and error scenarios."""

    def test_api_response_structure(self, client: TestClient, test_user: User) -> None:
        """Test that all API responses have consistent structure."""
        login_user(client, test_user.username, "testpass")

        # Test various endpoints for consistent response structure
        endpoints = [
            "/api/v1/users",
            "/api/v1/workspaces",
            "/api/v1/api-keys",
        ]

        for endpoint in endpoints:
            response = client.get(endpoint)
            assert response.status_code == 200, f"{endpoint} failed"
            data = response.json()
            assert "data" in data, f"{endpoint} missing 'data' field"

    def test_pagination_bounds(self, client: TestClient, test_admin: User) -> None:
        """Test pagination with boundary values."""
        login_user(client, test_admin.username, "adminpass")

        # Test with page=0 (should still work or return error gracefully)
        response = client.get("/api/v1/users?page=0&per_page=10")
        assert response.status_code in [200, 422]  # Either success or validation error

    def test_pagination_max_per_page(
        self, client: TestClient, test_admin: User
    ) -> None:
        """Test pagination max per_page limit."""
        login_user(client, test_admin.username, "adminpass")

        # Test with very high per_page
        response = client.get("/api/v1/users?page=1&per_page=1000")
        # Should either cap at max or return validation error
        assert response.status_code in [200, 422]

    def test_concurrent_api_key_creation(
        self, client: TestClient, test_user: User
    ) -> None:
        """Test creating multiple API keys for same user."""
        login_user(client, test_user.username, "testpass")

        # Create multiple keys
        for i in range(3):
            response = client.post("/api/v1/api-keys", json={"name": f"Key {i}"})
            assert response.status_code == 201

        # Verify all keys are listed
        response = client.get("/api/v1/api-keys")
        data = response.json()
        # Should have at least 3 keys (plus any from fixtures)
        assert len(data["data"]["api_keys"]) >= 3

    def test_workspace_name_validation_edge_cases(
        self, client: TestClient, test_user: User
    ) -> None:
        """Test workspace name validation with edge cases."""
        login_user(client, test_user.username, "testpass")

        # Test various invalid names
        invalid_names = [
            "a" * 129,  # Too long
            "test/name",  # Invalid character
            "test.name!",  # Invalid character
            " test",  # Leading space
            "test ",  # Trailing space
        ]

        for name in invalid_names:
            response = client.post("/api/v1/workspaces", json={"name": name})
            assert response.status_code == 400, f"Expected 400 for name: {name}"

    def test_special_characters_in_workspace_name(
        self, client: TestClient, test_user: User
    ) -> None:
        """Test valid special characters in workspace name."""
        login_user(client, test_user.username, "testpass")

        # Valid names with special characters
        valid_names = [
            "test-name",
            "test_name",
            "test.name",
            "test123",
            "TestName",
        ]

        for i, name in enumerate(valid_names):
            # Add suffix to avoid conflicts
            unique_name = f"{name}-{i}"
            response = client.post("/api/v1/workspaces", json={"name": unique_name})
            assert response.status_code == 201, f"Expected 201 for name: {unique_name}"
