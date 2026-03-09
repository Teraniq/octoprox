from __future__ import annotations

from collections.abc import Iterator
import importlib
import json
import os
import pathlib
import sys

_ = os.environ.setdefault("BOOTSTRAP_ADMIN_USERNAME", "test_admin")
_ = os.environ.setdefault("BOOTSTRAP_ADMIN_PASSWORD", "test_admin_password")
_ = os.environ.setdefault("SECRET_KEY", "test_secret_key_for_testing_only_32chars")
_ = os.environ.setdefault(
    "JWT_SECRET_KEY", "test_jwt_secret_key_for_testing_only_32chars"
)
_ = os.environ.setdefault("DATABASE_URL", "sqlite:///./test_manager.db")

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

auth = importlib.import_module("app.auth")
services = importlib.import_module("app.services")
db_module = importlib.import_module("app.db")
main_module = importlib.import_module("app.main")
models = importlib.import_module("app.models")

Base = db_module.Base
get_db = db_module.get_db
app = main_module.app
account_rate_limit = main_module.account_rate_limit
rate_limit = main_module.rate_limit
rate_limit_storage = main_module.rate_limit_storage
User = models.User


class FakeProvisioner:
    def create_workspace(self, workspace: object) -> None:
        return None

    def delete_workspace(self, workspace: object) -> None:
        return None

    def purge_workspace(self, workspace: object) -> None:
        return None

    def purge_by_name(self, name: str) -> None:
        return None


@pytest.fixture
def test_db() -> Iterator[Session]:
    engine = create_engine(
        "sqlite:///:memory:",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session_local = sessionmaker(bind=engine, future=True)
    db = testing_session_local()
    yield db
    db.close()


@pytest.fixture
def client(test_db: Session) -> Iterator[TestClient]:
    def override_get_db() -> Iterator[Session]:
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
    user = User(
        username="claimsuser",
        password_hash=auth.hash_password("testpass"),
        role="user",
        status="active",
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


@pytest.fixture
def test_api_key(test_db: Session, test_user: User) -> dict[str, str]:
    _, raw_token = services.create_api_key(test_db, test_user, name="Claims Key")
    return {"token": raw_token}


def assert_claims_shape(claims: dict[str, object], user_id: str, username: str) -> None:
    assert claims["schema_version"] == "v1"
    assert claims["subject"] == {"kind": "user", "id": user_id, "name": username}
    assert claims["group_ids"] == []
    assert claims["role_template_keys"] == []
    assert claims["policy_version"] == 0
    assert claims["snapshot_id"] is None
    assert claims["provider_bindings"] == []
    assert claims["gitlab_identity"] == {
        "user_id": None,
        "username": None,
        "auth_ref": None,
    }
    assert claims["trace_defaults"] == {
        "policy_authority": None,
        "attributes": {},
    }


def test_internal_introspection_claims_contract_preserves_compatibility_keys(
    client: TestClient,
    test_user: User,
    test_api_key: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main_module, "INTROSPECT_SECRET", "internal-secret")

    response = client.post(
        "/internal/auth/introspect",
        json={"token": test_api_key["token"]},
        headers={
            "X-Forwarded-For": "127.0.0.1",
            "X-Introspect-Secret": "internal-secret",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["active"] is True
    assert data["user_id"] == str(test_user.id)
    assert data["role"] == test_user.role
    assert_claims_shape(data["claims"], str(test_user.id), test_user.username)
    assert test_api_key["token"] not in json.dumps(data)


def test_internal_introspect_rejects_external_source(
    client: TestClient,
    test_api_key: dict[str, str],
) -> None:
    response = client.post(
        "/internal/auth/introspect",
        json={"token": test_api_key["token"]},
        headers={"X-Forwarded-For": "8.8.8.8"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Access denied: external source"


def test_public_introspection_claims_contract_for_api_key(
    client: TestClient,
    test_user: User,
    test_api_key: dict[str, str],
) -> None:
    response = client.post(
        "/api/v1/auth/introspect",
        json={"token": test_api_key["token"]},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["active"] is True
    assert data["user_id"] == str(test_user.id)
    assert data["sub"] == str(test_user.id)
    assert data["username"] == test_user.username
    assert data["role"] == test_user.role
    assert data["token_type"] == "api_key"
    assert_claims_shape(data["claims"], str(test_user.id), test_user.username)
    assert test_api_key["token"] not in json.dumps(data)


def test_public_introspect_jwt_includes_claims_contract(
    client: TestClient,
    test_user: User,
) -> None:
    token = auth.create_access_token(
        str(test_user.id), test_user.username, test_user.role
    )

    response = client.post("/api/v1/auth/introspect", json={"token": token})

    assert response.status_code == 200
    data = response.json()
    assert data["active"] is True
    assert data["user_id"] == str(test_user.id)
    assert data["sub"] == str(test_user.id)
    assert data["username"] == test_user.username
    assert data["role"] == test_user.role
    assert data["token_type"] == "jwt"
    assert "exp" in data
    assert_claims_shape(data["claims"], str(test_user.id), test_user.username)
    assert token not in json.dumps(data)


def test_public_introspect_invalid_token_fails_closed(client: TestClient) -> None:
    response = client.post("/api/v1/auth/introspect", json={"token": "invalid"})

    assert response.status_code == 200
    assert response.json() == {"active": False}
