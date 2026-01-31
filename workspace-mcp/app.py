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

WORKSPACE_ROOT = pathlib.Path("/workspace").resolve()
OWNER_USER_ID = os.getenv("WORKSPACE_OWNER_USER_ID", "")
INTROSPECT_URL = os.getenv("MANAGER_INTROSPECT_URL", "")
MCP_PORT = int(os.getenv("MCP_PORT", "7000"))

CACHE_TTL_SECONDS = 60
_cache: dict[str, tuple[dict[str, Any], float]] = {}


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

mcp = FastMCP(
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


app = mcp.streamable_http_app()
