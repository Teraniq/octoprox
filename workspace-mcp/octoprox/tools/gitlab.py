"""GitLab tools for API integration."""
from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

import httpx
import yaml
from cachetools import TTLCache

from ..auth import _require_owner
from ..config import GITLAB_BASE_URL, GITLAB_OPENAPI_URL, GITLAB_TOKEN

if TYPE_CHECKING:
    from .. import OctoproxMCP


# GitLab spec cache with TTL
_gitlab_spec_cache: TTLCache[str, dict[str, Any]] = TTLCache(maxsize=10, ttl=3600)

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


def _gitlab_headers(extra_headers: dict[str, str] | None = None) -> dict[str, str]:
    """Build headers for GitLab API requests."""
    headers = {"Accept": "application/json"}
    token = GITLAB_TOKEN
    if token:
        if "PRIVATE-TOKEN" in str(token) or len(token) < 100:
            # Assume it's a private token
            headers["PRIVATE-TOKEN"] = token
        else:
            headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    return headers


def _gitlab_spec_get(spec_url: str) -> dict[str, Any] | None:
    """Get GitLab spec from cache."""
    return _gitlab_spec_cache.get(spec_url)


def _gitlab_spec_set(spec_url: str, payload: dict[str, Any]) -> None:
    """Set GitLab spec in cache."""
    _gitlab_spec_cache[spec_url] = payload


def _load_gitlab_spec(spec_url: str, refresh: bool = False) -> dict[str, Any]:
    """Load GitLab OpenAPI spec from URL or cache."""
    cached = _gitlab_spec_get(spec_url)
    if cached and not refresh:
        return cached
    try:
        response = httpx.get(spec_url, timeout=30)
        response.raise_for_status()
        payload = yaml.safe_load(response.text)
    except (httpx.RequestError, httpx.HTTPStatusError, yaml.YAMLError) as exc:
        if cached:
            return cached
        raise RuntimeError("Failed to fetch GitLab OpenAPI spec.") from exc
    if not isinstance(payload, dict):
        if cached:
            return cached
        raise ValueError("Invalid OpenAPI spec payload.")
    _gitlab_spec_set(spec_url, payload)
    return payload


def _build_gitlab_files(files: list[dict[str, str]] | None) -> list[tuple[str, tuple[str, bytes, str]]] | None:
    """Build files payload for multipart requests."""
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


def register_gitlab_tools(mcp: "OctoproxMCP") -> None:
    """Register GitLab tools with the MCP server."""

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
        name="gitlab_openapi_spec",
        description=(
            "Return the GitLab OpenAPI YAML (chunked). Use for deep schema context; cacheable "
            "with optional refresh."
        ),
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
        name="gitlab_openapi_paths",
        description=(
            "List GitLab OpenAPI paths and methods, with optional filtering and pagination "
            "for endpoint discovery."
        ),
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
        name="gitlab_openapi_operation",
        description=(
            "Return schema details (parameters, requestBody, responses) for a GitLab OpenAPI "
            "path + method."
        ),
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
        name="gitlab_tool_help",
        description=(
            "Return machine-readable help for GitLab MCP tools, including usage guidance and examples."
        ),
    )
    def gitlab_tool_help() -> dict[str, Any]:
        """Get help for GitLab MCP tools."""
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