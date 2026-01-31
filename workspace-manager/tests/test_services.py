from __future__ import annotations

import pathlib
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))

from app import auth, services
from app.db import Base
from app.models import ApiKey, User, Workspace


class FakeProvisioner:
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


def build_session() -> Session:
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, future=True)()


def test_duplicate_workspace_rejected() -> None:
    db = build_session()
    user = User(username="user1", password_hash=auth.hash_password("pass"), role="user")
    db.add(user)
    db.commit()
    provisioner = FakeProvisioner()
    services.create_workspace(db, provisioner, user, "alpha")
    try:
        services.create_workspace(db, provisioner, user, "alpha")
    except ValueError as exc:
        assert "already exists" in str(exc)
    else:
        raise AssertionError("Expected duplicate workspace to fail")


def test_api_key_hash_verification() -> None:
    db = build_session()
    user = User(username="user2", password_hash=auth.hash_password("pass"), role="user")
    db.add(user)
    db.commit()
    key, token = services.create_api_key(db, user)
    assert auth.verify_api_key(token, key.key_hash)


def test_introspection_denies_invalid_tokens() -> None:
    db = build_session()
    result = services.introspect_token(db, "invalid_token")
    assert result == {"active": False}


def test_introspection_denies_deactivated_user() -> None:
    db = build_session()
    user = User(username="user4", password_hash=auth.hash_password("pass"), role="user")
    db.add(user)
    db.commit()
    _, token = services.create_api_key(db, user)
    provisioner = FakeProvisioner()
    services.deactivate_user(db, provisioner, user)
    result = services.introspect_token(db, token)
    assert result == {"active": False}


def test_user_deactivation_stops_workspaces_and_hides_them() -> None:
    db = build_session()
    user = User(username="user3", password_hash=auth.hash_password("pass"), role="user")
    db.add(user)
    db.commit()
    services.create_api_key(db, user)
    ws1 = Workspace(user_id=user.id, name="ws1")
    ws2 = Workspace(user_id=user.id, name="ws2")
    db.add_all([ws1, ws2])
    db.commit()
    provisioner = FakeProvisioner()
    services.deactivate_user(db, provisioner, user)
    assert provisioner.deleted == ["ws1", "ws2"]
    assert provisioner.purged == []
    db.refresh(user)
    assert user.status == "inactive"
    statuses = [ws.status for ws in db.query(Workspace).all()]
    assert statuses == ["inactive", "inactive"]
