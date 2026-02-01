from __future__ import annotations

import base64
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
from typing import Any

import httpx
import yaml
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
def _gitlab_spec_get(spec_url: str) -> dict[str, Any] | None:
    entry = _gitlab_spec_cache.get(spec_url)
    if not entry:
        return None
    payload, expires_at = entry
    if _now() > expires_at:
        _gitlab_spec_cache.pop(spec_url, None)
        return None
    return payload


def _openapi_cache_set(payload: dict[str, Any]) -> None:
    global _openapi_cache
    _openapi_cache = (payload, _now() + OPENAPI_CACHE_TTL_SECONDS)
def _gitlab_spec_set(spec_url: str, payload: dict[str, Any]) -> None:
    _gitlab_spec_cache[spec_url] = (payload, _now() + GITLAB_SPEC_CACHE_TTL_SECONDS)


def _load_gitlab_spec(spec_url: str, refresh: bool = False) -> dict[str, Any]:
    if not refresh:
        cached = _gitlab_spec_get(spec_url)
        if cached:
            return cached
    response = httpx.get(spec_url, timeout=30)
    response.raise_for_status()
    payload = yaml.safe_load(response.text)
    if not isinstance(payload, dict):
        raise ValueError("Invalid OpenAPI spec payload.")
    _gitlab_spec_set(spec_url, payload)
    return payload


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

GITLAB_REQUEST_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "status_code": {"type": "number"},
        "headers": {"type": "object"},
        "text": {"type": "string"},
        "json": {"type": ["object", "null"]},
        "truncated": {"type": "boolean"},
        "base64": {"type": ["string", "null"]},
    },
    "required": ["status_code", "headers", "text", "json", "truncated", "base64"],
}

GITLAB_OPENAPI_SPEC_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "status_code": {"type": "number"},
        "offset": {"type": "number"},
        "total_bytes": {"type": "number"},
        "truncated": {"type": "boolean"},
        "text": {"type": "string"},
    },
    "required": ["status_code", "offset", "total_bytes", "truncated", "text"],
}

GITLAB_OPENAPI_PATHS_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "total": {"type": "number"},
        "offset": {"type": "number"},
        "limit": {"type": "number"},
        "entries": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "method": {"type": "string"},
                    "summary": {"type": ["string", "null"]},
                },
                "required": ["path", "method", "summary"],
            },
        },
    },
    "required": ["total", "offset", "limit", "entries"],
}

GITLAB_OPENAPI_OPERATION_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "description": {"type": ["string", "null"]},
        "operationId": {"type": ["string", "null"]},
        "tags": {"type": ["array", "null"]},
        "parameters": {"type": ["array", "null"]},
        "requestBody": {"type": ["object", "null"]},
        "responses": {"type": ["object", "null"]},
    },
    "required": [
        "summary",
        "description",
        "operationId",
        "tags",
        "parameters",
        "requestBody",
        "responses",
    ],
}

GITLAB_TOOL_HELP_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "overview": {"type": "string"},
        "tools": {
            "type": "array",
            "items": {"type": ["string", "object"]},
        },
        "notes": {"type": ["string", "null"]},
    },
    "required": ["overview", "tools", "notes"],
}


@mcp.tool(outputSchema=GITLAB_REQUEST_OUTPUT_SCHEMA)
def gitlab_request() -> dict[str, Any]:
    _require_owner()
    return {
        "status_code": 501,
        "headers": {},
        "text": "Not implemented",
        "json": None,
        "truncated": False,
        "base64": None,
    }


@mcp.tool(outputSchema=GITLAB_OPENAPI_SPEC_OUTPUT_SCHEMA)
def gitlab_openapi_spec() -> dict[str, Any]:
    _require_owner()
    return {
        "status_code": 501,
        "offset": 0,
        "total_bytes": 0,
        "truncated": False,
        "text": "Not implemented",
    }


@mcp.tool(outputSchema=GITLAB_OPENAPI_PATHS_OUTPUT_SCHEMA)
def gitlab_openapi_paths() -> dict[str, Any]:
    _require_owner()
    return {
        "total": 0,
        "offset": 0,
        "limit": 0,
        "entries": [],
    }


@mcp.tool(outputSchema=GITLAB_OPENAPI_OPERATION_OUTPUT_SCHEMA)
def gitlab_openapi_operation() -> dict[str, Any]:
    _require_owner()
    return {
        "summary": "",
        "description": None,
        "operationId": None,
        "tags": None,
        "parameters": None,
        "requestBody": None,
        "responses": None,
    }


@mcp.tool(outputSchema=GITLAB_TOOL_HELP_OUTPUT_SCHEMA)
def gitlab_tool_help() -> dict[str, Any]:
    _require_owner()
    return {
        "overview": "",
        "tools": [],
        "notes": None,
    }


@mcp.tool(execution={"taskSupport": "forbidden"})
def fs_list(path: str = ".") -> list[str]:
    _require_owner()
    target = _resolve_path(path)
    if not target.exists():
        return []
    return [entry.name for entry in target.iterdir()]


@mcp.tool(execution={"taskSupport": "forbidden"})
def fs_read_text(path: str, max_bytes: int = 200000) -> str:
    _require_owner()
    target = _resolve_path(path)
    if not target.exists():
        raise FileNotFoundError("File not found")
    data = target.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")


@mcp.tool(execution={"taskSupport": "forbidden"})
def fs_write_text(path: str, text: str, mkdirs: bool = True) -> str:
    _require_owner()
    target = _resolve_path(path)
    if mkdirs:
        target.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(target, text)
    return "ok"


@mcp.tool(execution={"taskSupport": "forbidden"})
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


@mcp.tool(execution={"taskSupport": "forbidden"})
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


@mcp.tool(execution={"taskSupport": "forbidden"})
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
def _build_gitlab_files(files: list[dict[str, str]] | None) -> list[tuple[str, tuple[str, bytes, str]]] | None:
    if not files:
        return None
    built: list[tuple[str, tuple[str, bytes, str]]] = []
    for entry in files:
        name = entry.get("name")
        filename = entry.get("filename")
        data = entry.get("data_base64")
        content_type = entry.get("content_type", "application/octet-stream")
        if not name or not filename or not data:
            raise ValueError("Each file entry requires name, filename, and data_base64 fields.")
        try:
            payload = base64.b64decode(data)
        except (base64.binascii.Error, ValueError) as exc:
            raise ValueError("Invalid base64 in files payload.") from exc
        built.append((name, (filename, payload, content_type)))
    return built


@mcp.tool(
    description=(
        "Proxy any GitLab REST API request. Provide endpoint, token, and path; optionally "
        "pass params/json/form/files and request base64 for binary responses."
    )
)
def gitlab_request(
    endpoint: str,
    token: str,
    path: str,
    method: str = "GET",
    params: dict[str, Any] | None = None,
    json_body: Any | None = None,
    form: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    files: list[dict[str, str]] | None = None,
    timeout_s: int = 30,
    max_bytes: int = 200000,
    include_text: bool = True,
    include_base64: bool = False,
) -> dict[str, Any]:
    """Proxy arbitrary GitLab REST API requests through MCP.

    Use this tool when you already know the endpoint path and need to call any GitLab API.
    Provide:
    - endpoint: GitLab API base URL (e.g. https://gitlab.com/api/v4)
    - token: GitLab personal access token (sent as PRIVATE-TOKEN)
    - path: API path (e.g. /projects or projects/123/issues)
    Optionally pass query params, JSON body, form data, or multipart files.
    For binary responses (archives, raw file blobs), set include_base64=True.
    """
    _require_owner()
    if not endpoint:
        raise ValueError("GitLab endpoint is required.")
    if not path:
        raise ValueError("GitLab path is required.")
    url = f"{endpoint.rstrip('/')}/{path.lstrip('/')}"
    request_headers = {"Accept": "application/json"}
    if token:
        request_headers["PRIVATE-TOKEN"] = token
    if headers:
        request_headers.update(headers)
    files_payload = _build_gitlab_files(files)
    response = httpx.request(
        method.upper(),
        url,
        params=params,
        json=json_body,
        data=form,
        files=files_payload,
        headers=request_headers,
        timeout=timeout_s,
    )
    content = response.content
    truncated = len(content) > max_bytes
    content = content[:max_bytes]
    text = content.decode("utf-8", errors="replace") if include_text else ""
    payload: dict[str, Any] = {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "text": text,
        "truncated": truncated,
    }
    if include_base64:
        payload["base64"] = base64.b64encode(content).decode("ascii")
    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            payload["json"] = response.json()
        except json.JSONDecodeError:
            payload["json"] = None
    return payload


@mcp.tool(
    description=(
        "Return the GitLab OpenAPI YAML (chunked). Use for deep schema context; cacheable "
        "with optional refresh."
    )
)
def gitlab_openapi_spec(
    spec_url: str = "https://gitlab.com/gitlab-org/gitlab/-/raw/v18.8.2-ee/doc/api/openapi/openapi.yaml",
    offset: int = 0,
    max_bytes: int = 200000,
    refresh: bool = False,
) -> dict[str, Any]:
    """Fetch the GitLab OpenAPI specification as YAML text (chunked).

    Use this tool to load the full OpenAPI document when you need deep schema context.
    For large specs, call repeatedly with offset/max_bytes to paginate through the text.
    Set refresh=True to bypass the cache and re-download the spec.
    """
    _require_owner()
    if offset < 0:
        raise ValueError("offset must be >= 0")
    spec = _load_gitlab_spec(spec_url, refresh=refresh)
    text = yaml.safe_dump(spec, sort_keys=False)
    content = text.encode("utf-8")
    end = offset + max_bytes
    chunk = content[offset:end]
    return {
        "status_code": 200,
        "offset": offset,
        "total_bytes": len(content),
        "truncated": end < len(content),
        "text": chunk.decode("utf-8", errors="replace"),
    }


@mcp.tool(
    description=(
        "List GitLab OpenAPI paths and methods, with optional filtering and pagination "
        "for endpoint discovery."
    )
)
def gitlab_openapi_paths(
    spec_url: str = "https://gitlab.com/gitlab-org/gitlab/-/raw/v18.8.2-ee/doc/api/openapi/openapi.yaml",
    filter_text: str | None = None,
    limit: int = 200,
    offset: int = 0,
    refresh: bool = False,
) -> dict[str, Any]:
    """List GitLab OpenAPI paths + methods for endpoint discovery.

    Use filter_text to search for endpoints (e.g. "issues", "pipelines", "merge requests").
    This returns a paginated list of path/method/summary entries so you can pick an endpoint
    before calling gitlab_openapi_operation or gitlab_request.
    """
    _require_owner()
    if limit <= 0:
        raise ValueError("limit must be > 0")
    if offset < 0:
        raise ValueError("offset must be >= 0")
    spec = _load_gitlab_spec(spec_url, refresh=refresh)
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI spec missing paths.")
    entries: list[dict[str, Any]] = []
    filter_value = filter_text.lower() if filter_text else None
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, detail in methods.items():
            summary = ""
            if isinstance(detail, dict):
                summary = str(detail.get("summary") or detail.get("description") or "")
            record = {"path": path, "method": method.upper(), "summary": summary}
            if filter_value:
                haystack = f"{path} {method} {summary}".lower()
                if filter_value not in haystack:
                    continue
            entries.append(record)
    total = len(entries)
    sliced = entries[offset : offset + limit]
    return {"total": total, "offset": offset, "limit": limit, "entries": sliced}


@mcp.tool(
    description=(
        "Return schema details (parameters, requestBody, responses) for a GitLab OpenAPI "
        "path + method."
    )
)
def gitlab_openapi_operation(
    path: str,
    method: str,
    spec_url: str = "https://gitlab.com/gitlab-org/gitlab/-/raw/v18.8.2-ee/doc/api/openapi/openapi.yaml",
    refresh: bool = False,
) -> dict[str, Any]:
    """Return the OpenAPI schema details for a specific path + method.

    Use this tool after selecting an endpoint to get parameters, requestBody, and responses
    so you can construct a valid gitlab_request call.
    """
    _require_owner()
    spec = _load_gitlab_spec(spec_url, refresh=refresh)
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI spec missing paths.")
    path_item = paths.get(path)
    if not isinstance(path_item, dict):
        raise ValueError(f"Unknown path: {path}")
    operation = path_item.get(method.lower())
    if not isinstance(operation, dict):
        raise ValueError(f"Unknown operation: {method.upper()} {path}")
    return {
        "summary": operation.get("summary"),
        "description": operation.get("description"),
        "operationId": operation.get("operationId"),
        "tags": operation.get("tags"),
        "parameters": operation.get("parameters"),
        "requestBody": operation.get("requestBody"),
        "responses": operation.get("responses"),
    }


@mcp.tool(
    description=(
        "Return machine-readable help for GitLab MCP tools, including usage guidance and examples."
    )
)
def gitlab_tool_help() -> dict[str, Any]:
    _require_owner()
    return {
        "overview": (
            "Use gitlab_openapi_paths to discover endpoints, gitlab_openapi_operation to "
            "inspect parameters/request bodies, and gitlab_request to call the API. "
            "Use gitlab_openapi_spec only when you need the full OpenAPI document."
        ),
        "tools": {
            "gitlab_openapi_paths": {
                "purpose": "Search and list available GitLab REST endpoints.",
                "inputs": ["spec_url?", "filter_text?", "limit?", "offset?", "refresh?"],
                "output": "entries[{path, method, summary}], plus pagination metadata.",
                "example": {"filter_text": "issues", "limit": 20},
            },
            "gitlab_openapi_operation": {
                "purpose": "Get schema details for a specific path + method.",
                "inputs": ["path", "method", "spec_url?", "refresh?"],
                "output": "parameters, requestBody, responses, summary/description.",
                "example": {"path": "/projects/{id}/issues", "method": "post"},
            },
            "gitlab_request": {
                "purpose": "Make the actual GitLab API call.",
                "inputs": [
                    "endpoint",
                    "token",
                    "path",
                    "method?",
                    "params?",
                    "json_body?",
                    "form?",
                    "headers?",
                    "files?",
                    "timeout_s?",
                    "max_bytes?",
                    "include_text?",
                    "include_base64?",
                ],
                "output": "status_code, headers, text, json?, truncated, base64? (optional)",
                "example": {
                    "endpoint": "https://gitlab.com/api/v4",
                    "token": "<gitlab_token>",
                    "path": "/projects/123/issues",
                    "method": "GET",
                    "params": {"state": "opened"},
                },
            },
            "gitlab_openapi_spec": {
                "purpose": "Retrieve raw OpenAPI YAML (chunked).",
                "inputs": ["spec_url?", "offset?", "max_bytes?", "refresh?"],
                "output": "text chunk with offset/total bytes.",
                "example": {"offset": 0, "max_bytes": 200000},
            },
        },
        "notes": [
            "Set endpoint to the GitLab REST base URL, e.g. https://gitlab.com/api/v4.",
            "Set token to a GitLab personal access token; it is sent as PRIVATE-TOKEN.",
            "For binary responses, set include_base64=true and use the base64 field.",
        ],
    }


app = mcp.streamable_http_app()
