from __future__ import annotations

import asyncio
import importlib
import os
import sys
import tempfile
import types
from typing import Protocol, cast
from pathlib import Path

import pytest

workspace_root = Path(tempfile.mkdtemp(prefix="octoprox-auth-tests-"))
workspace_root.mkdir(parents=True, exist_ok=True)
_ = os.environ.setdefault("WORKSPACE_ROOT", str(workspace_root))

sys.path.insert(0, str(Path(__file__).parent.parent))


def _install_mcp_stubs() -> None:
    if "mcp" in sys.modules:
        return

    mcp_module = types.ModuleType("mcp")
    server_module = types.ModuleType("mcp.server")
    auth_module = types.ModuleType("mcp.server.auth")
    provider_module = types.ModuleType("mcp.server.auth.provider")
    settings_module = types.ModuleType("mcp.server.auth.settings")
    fastmcp_module = types.ModuleType("mcp.server.fastmcp")
    types_module = types.ModuleType("mcp.types")
    middleware_module = types.ModuleType("mcp.server.auth.middleware")
    auth_context_module = types.ModuleType("mcp.server.auth.middleware.auth_context")

    class ToolManager:
        def list_tools(self) -> list[object]:
            return []

    class AccessToken:
        token: str
        client_id: str
        scopes: list[str]

        def __init__(self, token: str, client_id: str, scopes: list[str]) -> None:
            self.token = token
            self.client_id = client_id
            self.scopes = scopes

    class TokenVerifier:
        pass

    class AuthSettings:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

    class FastMCP:
        _tool_manager: ToolManager

        def __init__(self, *args: object, **kwargs: object) -> None:
            self._tool_manager = ToolManager()

        def tool(self, *_args: object, **_kwargs: object):
            def decorator(fn: object) -> object:
                return fn

            return decorator

        def streamable_http_app(self) -> None:
            return None

    class Tool:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

    setattr(provider_module, "AccessToken", AccessToken)
    setattr(provider_module, "TokenVerifier", TokenVerifier)
    setattr(settings_module, "AuthSettings", AuthSettings)
    setattr(fastmcp_module, "FastMCP", FastMCP)
    setattr(types_module, "Tool", Tool)
    setattr(auth_context_module, "get_access_token", lambda: None)
    setattr(middleware_module, "auth_context", auth_context_module)
    setattr(auth_module, "middleware", middleware_module)
    setattr(auth_module, "provider", provider_module)
    setattr(auth_module, "settings", settings_module)
    setattr(server_module, "auth", auth_module)
    setattr(server_module, "fastmcp", fastmcp_module)
    setattr(mcp_module, "server", server_module)

    sys.modules["mcp"] = mcp_module
    sys.modules["mcp.server"] = server_module
    sys.modules["mcp.server.auth"] = auth_module
    sys.modules["mcp.server.auth.provider"] = provider_module
    sys.modules["mcp.server.auth.settings"] = settings_module
    sys.modules["mcp.server.fastmcp"] = fastmcp_module
    sys.modules["mcp.server.auth.middleware"] = middleware_module
    sys.modules["mcp.server.auth.middleware.auth_context"] = auth_context_module
    sys.modules["mcp.types"] = types_module


_install_mcp_stubs()


class AccessTokenLike(Protocol):
    client_id: str
    scopes: list[str]


class VerifierLike(Protocol):
    async def verify_token(self, token: str) -> AccessTokenLike | None: ...


auth = importlib.import_module("octoprox.auth")
ManagerTokenVerifier = cast(type[VerifierLike], getattr(auth, "ManagerTokenVerifier"))


def test_legacy_claims_envelope_compatibility_prefers_top_level_user_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_introspect(_: str) -> dict[str, object]:
        return {
            "active": True,
            "user_id": "owner-123",
            "claims": {
                "schema_version": "v1",
                "subject": {"kind": "user", "id": "nested-456", "name": "owner"},
            },
        }

    monkeypatch.setattr(auth, "introspect_token", fake_introspect)

    access_token = asyncio.run(ManagerTokenVerifier().verify_token("token"))

    assert access_token is not None
    assert access_token.client_id == "owner-123"
    assert access_token.scopes == ["mcp"]


def test_claims_envelope_compatibility_uses_nested_subject_when_needed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_introspect(_: str) -> dict[str, object]:
        return {
            "active": True,
            "role": "user",
            "claims": {
                "schema_version": "v1",
                "subject": {"kind": "user", "id": "owner-123", "name": "owner"},
                "group_ids": [],
                "role_template_keys": [],
                "policy_version": 0,
                "snapshot_id": None,
                "provider_bindings": [],
                "gitlab_identity": {
                    "user_id": None,
                    "username": None,
                    "auth_ref": None,
                },
                "trace_defaults": {"policy_authority": None, "attributes": {}},
            },
        }

    monkeypatch.setattr(auth, "introspect_token", fake_introspect)

    access_token = asyncio.run(ManagerTokenVerifier().verify_token("token"))

    assert access_token is not None
    assert access_token.client_id == "owner-123"


def test_claims_envelope_rejects_unknown_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_introspect(_: str) -> dict[str, object]:
        return {
            "active": True,
            "user_id": "owner-123",
            "claims": {
                "schema_version": "v999",
                "subject": {"kind": "user", "id": "owner-123", "name": "owner"},
            },
        }

    monkeypatch.setattr(auth, "introspect_token", fake_introspect)

    assert asyncio.run(ManagerTokenVerifier().verify_token("token")) is None


def test_admin_tokens_gain_admin_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_introspect(_: str) -> dict[str, object]:
        return {
            "active": True,
            "user_id": "admin-1",
            "role": "admin",
            "claims": {
                "schema_version": "v1",
                "subject": {"kind": "user", "id": "admin-1", "name": "admin"},
                "group_ids": [],
                "role_template_keys": [],
                "policy_version": 0,
                "snapshot_id": None,
                "provider_bindings": [],
                "gitlab_identity": {
                    "user_id": None,
                    "username": None,
                    "auth_ref": None,
                },
                "trace_defaults": {"policy_authority": None, "attributes": {}},
            },
        }

    monkeypatch.setattr(auth, "introspect_token", fake_introspect)

    access_token = asyncio.run(ManagerTokenVerifier().verify_token("token"))

    assert access_token is not None
    assert "role:admin" in access_token.scopes


def test_denied_tool_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    denied_token = types.SimpleNamespace(client_id="someone-else", scopes=["mcp"])
    monkeypatch.setattr(auth, "get_access_token", lambda: denied_token)
    monkeypatch.setenv("WORKSPACE_OWNER_USER_ID", "owner-123")

    with pytest.raises(RuntimeError, match="Forbidden"):
        auth._require_owner()
