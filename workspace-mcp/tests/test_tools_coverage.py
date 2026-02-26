"""Targeted coverage for octoprox tool helpers."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys
import tempfile
import types
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

# Ensure workspace root exists and is writable for the imported tools.
workspace_root = Path(tempfile.mkdtemp(prefix="octoprox-tests-"))
workspace_root.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("WORKSPACE_ROOT", str(workspace_root))


class _DummyProcess:
    stdout = ""
    returncode = 0


subprocess.run = lambda *args, **kwargs: _DummyProcess()
shutil.which = lambda *args, **kwargs: None

# Inject minimal MCP stubs so importing octoprox does not require the real mcp package.
if "mcp" not in sys.modules:
    mcp_module = types.ModuleType("mcp")
    server_module = types.ModuleType("mcp.server")
    auth_module = types.ModuleType("mcp.server.auth")
    provider_module = types.ModuleType("mcp.server.auth.provider")
    settings_module = types.ModuleType("mcp.server.auth.settings")
    fastmcp_module = types.ModuleType("mcp.server.fastmcp")
    types_module = types.ModuleType("mcp.types")
    middleware_module = types.ModuleType("mcp.server.auth.middleware")
    auth_context_module = types.ModuleType("mcp.server.auth.middleware.auth_context")

    class AccessToken:
        pass

    class TokenVerifier:
        pass

    class AuthSettings:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

    class FastMCP:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            class ToolManager:
                def list_tools(self) -> list[Any]:
                    return []

            self._tool_manager = ToolManager()

        def tool(self, *args: Any, **kwargs: Any) -> Any:
            def decorator(fn: Any) -> Any:
                return fn

            return decorator

        def streamable_http_app(self) -> Any:
            return None

    class Tool:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

    provider_module.AccessToken = AccessToken
    provider_module.TokenVerifier = TokenVerifier
    settings_module.AuthSettings = AuthSettings
    fastmcp_module.FastMCP = FastMCP
    types_module.Tool = Tool
    auth_context_module.get_access_token = lambda: None
    middleware_module.auth_context = auth_context_module
    auth_module.middleware = middleware_module
    server_module.auth = auth_module
    auth_module.provider = provider_module
    auth_module.settings = settings_module
    mcp_module.server = server_module
    server_module.fastmcp = fastmcp_module
    sys.modules["mcp"] = mcp_module
    sys.modules["mcp.server"] = server_module
    sys.modules["mcp.server.auth"] = auth_module
    sys.modules["mcp.server.auth.provider"] = provider_module
    sys.modules["mcp.server.auth.settings"] = settings_module
    sys.modules["mcp.server.fastmcp"] = fastmcp_module
    sys.modules["mcp.server.auth.middleware"] = middleware_module
    sys.modules["mcp.server.auth.middleware.auth_context"] = auth_context_module
    sys.modules["mcp.types"] = types_module

from octoprox.tools.filesystem import register_filesystem_tools
from octoprox.tools.git import _validate_git_args, register_git_tools
from octoprox.tools.gitlab import (
    _build_gitlab_files,
    _gitlab_headers,
    _gitlab_spec_cache,
    _load_gitlab_spec,
    register_gitlab_tools,
)


class StubMCP:
    """Minimal MCP substitute for registering tools."""

    def tool(self, *args: Any, **kwargs: Any) -> Any:
        def decorator(fn: Any) -> Any:
            setattr(self, fn.__name__, fn)
            return fn

        return decorator


def test_filesystem_tools_workflow(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("octoprox.tools.filesystem._require_owner", lambda: None)
    monkeypatch.setattr(
        "octoprox.tools.filesystem._resolve_path",
        lambda path: (tmp_path / path).resolve(),
    )
    mcp = StubMCP()
    register_filesystem_tools(mcp)

    assert mcp.fs_list("missing") == []
    with pytest.raises(FileNotFoundError):
        mcp.fs_read_text("missing")

    assert mcp.fs_write_text("dir/file.txt", "hello") == "ok"
    assert (tmp_path / "dir" / "file.txt").read_text() == "hello"
    assert mcp.fs_list("dir") == ["file.txt"]
    assert mcp.fs_read_text("dir/file.txt") == "hello"
    assert mcp.fs_delete("dir/file.txt") == "ok"

    (tmp_path / "tree").mkdir()
    (tmp_path / "tree" / "inner").mkdir()
    (tmp_path / "tree" / "inner" / "value.txt").write_text("v")
    with pytest.raises(IsADirectoryError):
        mcp.fs_delete("tree")
    assert mcp.fs_delete("tree", recursive=True) == "ok"
    assert not (tmp_path / "tree").exists()
    assert mcp.fs_delete("also-missing") == "ok"


def test_validate_git_args_variants() -> None:
    _validate_git_args("status", ["--short", "--branch"])
    with pytest.raises(ValueError, match="allowed whitelist"):
        _validate_git_args("unknown", [])
    with pytest.raises(ValueError, match="Too many arguments"):
        _validate_git_args("status", ["--short"] * 8)
    with pytest.raises(ValueError, match="invalid characters"):
        _validate_git_args("status", ["--short;"])
    with pytest.raises(ValueError, match="Argument not allowed"):
        _validate_git_args("status", ["--not-a-flag"])
    with pytest.raises(ValueError, match="Path traversal"):
        _validate_git_args("status", ["../escape"])


def test_git_tool_runs_and_validates(
    mock_subprocess: dict[str, MagicMock],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("octoprox.tools.git._require_owner", lambda: None)
    monkeypatch.setattr("octoprox.tools.git.WORKSPACE_ROOT", tmp_path)
    mcp = StubMCP()
    register_git_tools(mcp)

    result = mcp.git(["status", "--short"], timeout_s=5)
    assert result["returncode"] == mock_subprocess["result"].returncode
    assert mock_subprocess["run"].called

    with pytest.raises(ValueError, match="timeout_s must"):
        mcp.git(["status"], timeout_s=0)
    with pytest.raises(ValueError, match="No git command provided"):
        mcp.git([], timeout_s=10)


def test_gitlab_headers_switch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("octoprox.tools.gitlab.GITLAB_TOKEN", "short-token")
    headers = _gitlab_headers()
    assert headers["PRIVATE-TOKEN"] == "short-token"

    token = "long-bearer-" * 10
    monkeypatch.setattr("octoprox.tools.gitlab.GITLAB_TOKEN", token)
    headers = _gitlab_headers({"X-Trace": "1"})
    assert headers["Authorization"] == f"Bearer {token}"
    assert headers["X-Trace"] == "1"


def test_build_gitlab_files_valid_and_invalid() -> None:
    data = base64.b64encode(b"payload").decode("ascii")
    files = _build_gitlab_files(
        [
            {
                "name": "file",
                "filename": "payload.txt",
                "data_base64": data,
                "content_type": "text/plain",
            },
        ]
    )
    assert files == [("file", ("payload.txt", b"payload", "text/plain"))]

    with pytest.raises(ValueError, match="requires name"):
        _build_gitlab_files([{"filename": "skip"}])
    with pytest.raises(ValueError, match="Invalid base64"):
        _build_gitlab_files(
            [
                {
                    "name": "file",
                    "filename": "payload.txt",
                    "data_base64": "not-base64",
                },
            ]
        )


def test_load_gitlab_spec_cache_and_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    spec_url = "https://example.com/spec"
    _gitlab_spec_cache.clear()
    _gitlab_spec_cache[spec_url] = {"cached": True}
    assert _load_gitlab_spec(spec_url) == {"cached": True}

    monkeypatch.setattr(
        "octoprox.tools.gitlab.httpx.get",
        lambda *args, **kwargs: MagicMock(
            **{
                "raise_for_status": lambda: None,
                "text": "paths: {}",
            }
        ),
    )
    spec = _load_gitlab_spec(spec_url, refresh=True)
    assert spec.get("paths") == {}

    _gitlab_spec_cache[spec_url] = {"fallback": True}

    def raise_request_error(*args: Any, **kwargs: Any) -> None:
        raise httpx.RequestError("boom")

    monkeypatch.setattr("octoprox.tools.gitlab.httpx.get", raise_request_error)
    assert _load_gitlab_spec(spec_url, refresh=True) == {"fallback": True}

    _gitlab_spec_cache.clear()
    with pytest.raises(RuntimeError):
        _load_gitlab_spec(spec_url, refresh=True)


def test_gitlab_request_variants(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("octoprox.tools.gitlab._require_owner", lambda: None)
    mcp = StubMCP()
    register_gitlab_tools(mcp)

    json_response = MagicMock()
    json_response.status_code = 200
    json_response.headers = {"content-type": "application/json"}
    json_response.content = b'{"ok":true}'
    json_response.json.return_value = {"ok": True}
    monkeypatch.setattr(
        "octoprox.tools.gitlab.httpx.request", lambda *args, **kwargs: json_response
    )
    payload = mcp.gitlab_request(
        "https://gitlab.com/api/v4", "token", "projects", method="GET"
    )
    assert payload["json"] == {"ok": True}
    assert payload["text"].startswith("{")

    binary_response = MagicMock()
    binary_response.status_code = 201
    binary_response.headers = {"content-type": "application/octet-stream"}
    binary_response.content = b"\x01\x02"
    monkeypatch.setattr(
        "octoprox.tools.gitlab.httpx.request", lambda *args, **kwargs: binary_response
    )
    payload = mcp.gitlab_request(
        "https://gitlab.com/api/v4",
        "token",
        "projects/bin",
        include_text=False,
        include_base64=True,
    )
    assert payload["text"] == ""
    assert payload["base64"] == base64.b64encode(b"\x01\x02").decode("ascii")
    assert "json" not in payload


def test_gitlab_openapi_tools(
    monkeypatch: pytest.MonkeyPatch, sample_openapi_spec: dict[str, Any]
) -> None:
    monkeypatch.setattr("octoprox.tools.gitlab._require_owner", lambda: None)
    monkeypatch.setattr(
        "octoprox.tools.gitlab._load_gitlab_spec",
        lambda spec_url, refresh=False: sample_openapi_spec,
    )
    mcp = StubMCP()
    register_gitlab_tools(mcp)

    spec = mcp.gitlab_openapi_spec(spec_url="url", offset=0, max_bytes=1000)
    assert spec["status_code"] == 200
    assert "openapi" in spec["text"]

    paths = mcp.gitlab_openapi_paths(
        spec_url="url", filter_text="users", limit=5, offset=0
    )
    assert any(entry["path"] == "/users" for entry in paths["entries"])

    operation = mcp.gitlab_openapi_operation("/pets", "GET", spec_url="url")
    assert operation["operationId"] == "listPets"
