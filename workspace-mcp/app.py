from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
from typing import Any

import httpx
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.types import Tool as MCPTool

WORKSPACE_ROOT = pathlib.Path("/workspace").resolve()
OWNER_USER_ID = os.getenv("WORKSPACE_OWNER_USER_ID", "")
INTROSPECT_URL = os.getenv("MANAGER_INTROSPECT_URL", "")
MCP_PORT = int(os.getenv("MCP_PORT", "7000"))

CACHE_TTL_SECONDS = 60
_cache: dict[str, tuple[dict[str, Any], float]] = {}
OPENAPI_CACHE_TTL_SECONDS = 3600
_openapi_cache: tuple[dict[str, Any], float] | None = None

GITLAB_TOOL_ICONS = [
    {
        "type": "image/png",
        "src": "https://about.gitlab.com/images/press/logo/png/gitlab-icon-rgb.png",
    },
    {
        "type": "image/svg+xml",
        "src": "https://about.gitlab.com/images/press/logo/svg/gitlab-icon-rgb.svg",
    },
]

GITLAB_TOOL_METADATA: dict[str, dict[str, Any]] = {
    "gitlab_request": {
        "title": "GitLab: Request",
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": True,
        },
        "icons": GITLAB_TOOL_ICONS,
    },
    "gitlab_openapi_spec": {
        "title": "GitLab: OpenAPI Spec",
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
        "icons": GITLAB_TOOL_ICONS,
    },
    "gitlab_openapi_paths": {
        "title": "GitLab: OpenAPI Paths",
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
        "icons": GITLAB_TOOL_ICONS,
    },
    "gitlab_openapi_operation": {
        "title": "GitLab: OpenAPI Operation",
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
        "icons": GITLAB_TOOL_ICONS,
    },
    "gitlab_tool_help": {
        "title": "GitLab: Tool Help",
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
        "icons": GITLAB_TOOL_ICONS,
    },
}


def _now() -> float:
    return time.time()


def _cache_get(token: str) -> dict[str, Any] | None:
    entry = _cache.get(token)
    if not entry:
        return None
    payload, expires_at = entry
    if _now() > expires_at:
        _cache.pop(token, None)
        return None
    return payload


def _cache_set(token: str, payload: dict[str, Any]) -> None:
    _cache[token] = (payload, _now() + CACHE_TTL_SECONDS)


def _openapi_cache_get() -> dict[str, Any] | None:
    global _openapi_cache
    if not _openapi_cache:
        return None
    payload, expires_at = _openapi_cache
    if _now() > expires_at:
        _openapi_cache = None
        return None
    return payload


def _openapi_cache_set(payload: dict[str, Any]) -> None:
    global _openapi_cache
    _openapi_cache = (payload, _now() + OPENAPI_CACHE_TTL_SECONDS)


async def introspect_token(token: str) -> dict[str, Any]:
    cached = _cache_get(token)
    if cached:
        return cached
    if not INTROSPECT_URL:
        return {"active": False}
    async with httpx.AsyncClient(timeout=5) as client:
        response = await client.post(INTROSPECT_URL, json={"token": token})
    if response.status_code != 200:
        return {"active": False}
    payload = response.json()
    _cache_set(token, payload)
    return payload


class ManagerTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        payload = await introspect_token(token)
        if not payload.get("active"):
            return None
        return AccessToken(
            token=token,
            client_id=payload.get("user_id", ""),
            scopes=["mcp"],
        )


def _require_owner() -> None:
    access_token = get_access_token()
    if not access_token:
        raise RuntimeError("Unauthorized")
    if OWNER_USER_ID and access_token.client_id != OWNER_USER_ID:
        raise RuntimeError("Forbidden")


def _resolve_path(path: str) -> pathlib.Path:
    target = (WORKSPACE_ROOT / path).resolve()
    if not str(target).startswith(str(WORKSPACE_ROOT)):
        raise ValueError("Path escapes workspace")
    return target


def _atomic_write(target: pathlib.Path, text: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=target.parent) as tmp:
        tmp.write(text)
        tmp.flush()
        os.fsync(tmp.fileno())
        temp_name = tmp.name
    os.replace(temp_name, target)


def _ensure_ssh_key() -> None:
    ssh_dir = WORKSPACE_ROOT / ".ssh"
    private_key = ssh_dir / "id_ed25519"
    public_key = ssh_dir / "id_ed25519.pub"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    if not private_key.exists():
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", str(private_key), "-N", ""],
            check=False,
        )
    known_hosts = ssh_dir / "known_hosts"
    if shutil.which("ssh-keyscan"):
        result = subprocess.run(
            ["ssh-keyscan", "-t", "rsa", "gitlab.com"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.stdout:
            known_hosts.write_text(result.stdout)


_ensure_ssh_key()


class GitLabMCP(FastMCP):
    async def list_tools(self) -> list[MCPTool]:
        tools = self._tool_manager.list_tools()
        return [
            MCPTool(
                name=info.name,
                description=info.description,
                inputSchema=info.parameters,
                **GITLAB_TOOL_METADATA.get(info.name, {}),
            )
            for info in tools
        ]


mcp = GitLabMCP(
    "gitfs",
    auth=AuthSettings(issuer_url="http://workspace-manager:8000", resource_server_url=None),
    token_verifier=ManagerTokenVerifier(),
)


@mcp.tool()
def fs_list(path: str = ".") -> list[str]:
    _require_owner()
    target = _resolve_path(path)
    if not target.exists():
        return []
    return [entry.name for entry in target.iterdir()]


@mcp.tool()
def fs_read_text(path: str, max_bytes: int = 200000) -> str:
    _require_owner()
    target = _resolve_path(path)
    if not target.exists():
        raise FileNotFoundError("File not found")
    data = target.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")


@mcp.tool()
def fs_write_text(path: str, text: str, mkdirs: bool = True) -> str:
    _require_owner()
    target = _resolve_path(path)
    if mkdirs:
        target.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(target, text)
    return "ok"


@mcp.tool()
def fs_delete(path: str, recursive: bool = False) -> str:
    _require_owner()
    target = _resolve_path(path)
    if not target.exists():
        return "ok"
    if target.is_dir():
        if not recursive:
            raise IsADirectoryError("Directory delete requires recursive=true")
        shutil.rmtree(target)
    else:
        target.unlink()
    return "ok"


@mcp.tool()
def git(args: list[str], timeout_s: int = 120) -> dict[str, Any]:
    _require_owner()
    cmd = ["git", "-C", str(WORKSPACE_ROOT), *args]
    env = os.environ.copy()
    env["HOME"] = str(WORKSPACE_ROOT / ".home")
    env["GIT_TERMINAL_PROMPT"] = "0"
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout_s,
        check=False,
    )
    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


@mcp.tool()
def ssh_public_key() -> str:
    _require_owner()
    public_key = WORKSPACE_ROOT / ".ssh" / "id_ed25519.pub"
    if not public_key.exists():
        return ""
    return public_key.read_text()


def _gitlab_base_url() -> str:
    return os.getenv("GITLAB_BASE_URL", "https://gitlab.com").rstrip("/")


def _gitlab_openapi_url() -> str:
    return os.getenv("GITLAB_OPENAPI_URL", f"{_gitlab_base_url()}/api/v4/openapi")


def _gitlab_headers(extra_headers: dict[str, str] | None = None) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    token = (
        os.getenv("GITLAB_TOKEN")
        or os.getenv("GITLAB_PRIVATE_TOKEN")
        or os.getenv("GITLAB_BEARER_TOKEN")
    )
    if token:
        if os.getenv("GITLAB_PRIVATE_TOKEN"):
            headers["PRIVATE-TOKEN"] = token
        else:
            headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    return headers


def _fetch_openapi_spec() -> dict[str, Any]:
    cached = _openapi_cache_get()
    if cached:
        return cached
    response = httpx.get(_gitlab_openapi_url(), headers=_gitlab_headers(), timeout=10)
    response.raise_for_status()
    payload = response.json()
    if isinstance(payload, dict):
        _openapi_cache_set(payload)
    return payload


@mcp.tool(name="gitlab_request", description="Send a request to the GitLab REST API.")
def gitlab_request(
    method: str,
    path: str,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout_s: int = 30,
) -> dict[str, Any]:
    _require_owner()
    base_url = _gitlab_base_url()
    url = path if path.startswith("http") else f"{base_url}/{path.lstrip('/')}"
    response = httpx.request(
        method=method.upper(),
        url=url,
        params=params,
        json=json_body,
        headers=_gitlab_headers(headers),
        timeout=timeout_s,
    )
    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type:
        body: Any = response.json()
    else:
        body = response.text
    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body": body,
    }


@mcp.tool(
    name="gitlab_openapi_spec",
    description="Fetch the GitLab OpenAPI specification document.",
)
def gitlab_openapi_spec() -> dict[str, Any]:
    _require_owner()
    return _fetch_openapi_spec()


@mcp.tool(
    name="gitlab_openapi_paths",
    description="List available OpenAPI paths from the GitLab specification.",
)
def gitlab_openapi_paths() -> list[str]:
    _require_owner()
    spec = _fetch_openapi_spec()
    paths = spec.get("paths", {})
    if isinstance(paths, dict):
        return sorted(paths.keys())
    return []


@mcp.tool(
    name="gitlab_openapi_operation",
    description="Get the OpenAPI operation details for a GitLab path and method.",
)
def gitlab_openapi_operation(path: str, method: str) -> dict[str, Any]:
    _require_owner()
    spec = _fetch_openapi_spec()
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return {}
    operation = paths.get(path, {})
    if not isinstance(operation, dict):
        return {}
    return operation.get(method.lower(), {})


@mcp.tool(
    name="gitlab_tool_help",
    description="Describe how to use the GitLab MCP tools.",
)
def gitlab_tool_help() -> str:
    _require_owner()
    return (
        "GitLab tools available:\\n"
        "- gitlab_request: call GitLab REST endpoints; accepts method, path, params, and json_body.\\n"
        "- gitlab_openapi_spec: fetch the OpenAPI document.\\n"
        "- gitlab_openapi_paths: list OpenAPI paths.\\n"
        "- gitlab_openapi_operation: inspect an operation for a path + method.\\n"
        "Authentication uses GITLAB_TOKEN, GITLAB_PRIVATE_TOKEN, or GITLAB_BEARER_TOKEN env vars."
    )


app = mcp.streamable_http_app()
