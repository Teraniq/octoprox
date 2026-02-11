"""OpenAPI-to-MCP Adapter tools for generic API integration."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx
import yaml

from ..auth import _require_owner

if TYPE_CHECKING:
    from .. import OctoproxMCP


@dataclass
class LoadedAPI:
    """Represents a loaded OpenAPI specification."""
    spec: dict[str, Any]
    base_url: str
    auth_header: str | None
    auth_header_name: str
    title: str
    version: str


# Global storage for loaded APIs
_loaded_apis: dict[str, LoadedAPI] = {}


def _resolve_ref(spec: dict[str, Any], ref: str) -> dict[str, Any]:
    """Resolve a $ref pointer in the OpenAPI spec.

    Args:
        spec: The full OpenAPI specification
        ref: The reference string (e.g., "#/components/schemas/Foo")

    Returns:
        The resolved reference object

    Raises:
        ValueError: If the reference cannot be resolved
    """
    if not ref.startswith("#/"):
        raise ValueError(f"Invalid $ref format: {ref}. Only local references (#/...) are supported.")

    # Remove the leading "#/" and split by "/"
    parts = ref[2:].split("/")

    # Navigate the spec to resolve the reference
    current: Any = spec
    for part in parts:
        if not isinstance(current, dict):
            raise ValueError(f"Cannot resolve $ref '{ref}': intermediate value is not an object")
        if part not in current:
            raise ValueError(f"Cannot resolve $ref '{ref}': '{part}' not found")
        current = current[part]

    if not isinstance(current, dict):
        raise ValueError(f"Cannot resolve $ref '{ref}': resolved value is not an object")

    return current


def _deep_resolve(spec: dict[str, Any], obj: Any) -> Any:
    """Recursively resolve all $ref pointers in an object.

    Args:
        spec: The full OpenAPI specification
        obj: The object to resolve references in

    Returns:
        The object with all $ref pointers resolved
    """
    if isinstance(obj, dict):
        if "$ref" in obj and len(obj) == 1:
            # This is a pure reference, resolve it
            resolved = _resolve_ref(spec, obj["$ref"])
            # Recursively resolve within the resolved object
            return _deep_resolve(spec, resolved)
        else:
            # Recursively resolve in all values
            return {k: _deep_resolve(spec, v) for k, v in obj.items()}
    elif isinstance(obj, list):
        # Recursively resolve in all items
        return [_deep_resolve(spec, item) for item in obj]
    else:
        # Primitive value, return as-is
        return obj


def _count_endpoints(spec: dict[str, Any]) -> int:
    """Count the total number of endpoints in the spec."""
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return 0
    count = 0
    http_methods = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
    for path_item in paths.values():
        if isinstance(path_item, dict):
            for method in path_item.keys():
                if method.lower() in http_methods:
                    count += 1
    return count


def _extract_tags(operation: dict[str, Any]) -> list[str]:
    """Extract tags from an operation."""
    tags = operation.get("tags", [])
    if isinstance(tags, list):
        return [str(tag) for tag in tags if isinstance(tag, (str, int, float))]
    return []


def _extract_base_url(spec: dict[str, Any]) -> str:
    """Extract base URL from the OpenAPI spec."""
    # Try servers first (OpenAPI 3.x)
    servers = spec.get("servers", [])
    if isinstance(servers, list) and len(servers) > 0:
        server = servers[0]
        if isinstance(server, dict):
            url = server.get("url", "")
            if url:
                return url

    # Fall back to host + basePath (Swagger 2.0)
    host = spec.get("host", "")
    base_path = spec.get("basePath", "")
    schemes = spec.get("schemes", ["https"])
    scheme = schemes[0] if isinstance(schemes, list) and schemes else "https"

    if host:
        return f"{scheme}://{host}{base_path}"

    return ""


def register_openapi_tools(mcp: "OctoproxMCP") -> None:
    """Register OpenAPI adapter tools with the MCP server."""

    @mcp.tool(
        description="Load an OpenAPI specification and register it for use.",
    )
    def openapi_load(
        name: str,
        spec_url: str | None = None,
        spec_content: str | None = None,
        auth_header: str | None = None,
        auth_header_name: str = "Authorization",
        base_url_override: str | None = None,
    ) -> dict[str, Any]:
        """Load an OpenAPI specification.

        Parameters:
            name: Unique identifier for this API
            spec_url: URL to fetch spec from (optional if spec_content provided)
            spec_content: Inline spec content in YAML or JSON (optional if spec_url provided)
            auth_header: Auth header value for API calls
            auth_header_name: Header name for auth (default "Authorization")
            base_url_override: Override the base URL from the spec

        Returns:
            {"name": str, "title": str, "version": str, "endpoint_count": int}

        Annotations:
            readOnlyHint: False
            destructiveHint: False
            idempotentHint: True
            openWorldHint: True
        """
        _require_owner()

        if not name:
            raise ValueError("API name is required")

        if not spec_url and not spec_content:
            raise ValueError("Either spec_url or spec_content must be provided")

        # Load spec from URL or content
        try:
            if spec_content:
                # Parse inline content
                try:
                    spec = yaml.safe_load(spec_content)
                except yaml.YAMLError:
                    try:
                        spec = json.loads(spec_content)
                    except json.JSONDecodeError as e:
                        raise ValueError(f"Invalid spec_content: not valid YAML or JSON: {e}")
            else:
                # Fetch from URL
                response = httpx.get(spec_url, timeout=30)
                response.raise_for_status()
                content_type = response.headers.get("content-type", "")
                if "json" in content_type:
                    spec = response.json()
                else:
                    spec = yaml.safe_load(response.text)
        except httpx.RequestError as e:
            raise RuntimeError(f"Failed to fetch spec from URL: {e}") from e
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            raise ValueError(f"Invalid spec format: {e}") from e

        if not isinstance(spec, dict):
            raise ValueError("Invalid spec: must be an object")

        # Extract metadata
        title = spec.get("info", {}).get("title", "Unknown API")
        version = spec.get("info", {}).get("version", "unknown")

        # Determine base URL
        base_url = base_url_override or _extract_base_url(spec)
        if not base_url and spec_url:
            # Extract base from spec URL
            from urllib.parse import urlparse
            parsed = urlparse(spec_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Store the loaded API
        loaded_api = LoadedAPI(
            spec=spec,
            base_url=base_url,
            auth_header=auth_header,
            auth_header_name=auth_header_name,
            title=title,
            version=version,
        )
        _loaded_apis[name] = loaded_api

        endpoint_count = _count_endpoints(spec)

        return {
            "name": name,
            "title": title,
            "version": version,
            "endpoint_count": endpoint_count,
        }

    @mcp.tool(
        description="List all loaded OpenAPI APIs.",
    )
    def openapi_list_apis() -> dict[str, Any]:
        """List all loaded APIs.

        Returns:
            {"apis": [{"name": str, "title": str, "version": str, "endpoint_count": int}]}

        Annotations:
            readOnlyHint: True
            destructiveHint: False
            idempotentHint: True
            openWorldHint: False
        """
        _require_owner()

        apis = []
        for name, api in _loaded_apis.items():
            apis.append({
                "name": name,
                "title": api.title,
                "version": api.version,
                "endpoint_count": _count_endpoints(api.spec),
            })

        return {"apis": apis}

    @mcp.tool(
        description="List endpoints from a loaded API with optional filtering.",
    )
    def openapi_list_endpoints(
        name: str,
        filter: str | None = None,
        tag: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """List endpoints from a loaded API.

        Parameters:
            name: API name
            filter: Filter by path substring (optional)
            tag: Filter by tag (optional)
            limit: Maximum number of results (default 50)
            offset: Pagination offset (default 0)

        Returns:
            Paginated list of {"path": str, "method": str, "summary": str, "tags": list}

        Annotations:
            readOnlyHint: True
            destructiveHint: False
            idempotentHint: True
            openWorldHint: False
        """
        _require_owner()

        if name not in _loaded_apis:
            raise ValueError(f"API '{name}' not found. Use openapi_load first.")

        api = _loaded_apis[name]
        spec = api.spec
        paths = spec.get("paths", {})

        if not isinstance(paths, dict):
            raise ValueError("Invalid spec: paths is not an object")

        if limit <= 0:
            limit = 50
        if offset < 0:
            offset = 0

        http_methods = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
        entries: list[dict[str, Any]] = []
        filter_lower = filter.lower() if filter else None

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method, operation in path_item.items():
                if method.lower() not in http_methods:
                    continue
                if not isinstance(operation, dict):
                    continue

                summary = operation.get("summary", "") or ""
                tags = _extract_tags(operation)

                # Apply filters
                if filter_lower:
                    search_text = f"{path} {method} {summary}".lower()
                    if filter_lower not in search_text:
                        continue

                if tag:
                    if tag not in tags:
                        continue

                entries.append({
                    "path": path,
                    "method": method.upper(),
                    "summary": summary,
                    "tags": tags,
                })

        total = len(entries)
        sliced = entries[offset : offset + limit]

        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "entries": sliced,
        }

    @mcp.tool(
        description="Get detailed information about a specific API operation.",
    )
    def openapi_get_operation(
        name: str,
        path: str,
        method: str,
    ) -> dict[str, Any]:
        """Get operation details with resolved $ref pointers.

        Parameters:
            name: API name
            path: Path
            method: HTTP method

        Returns:
            Full operation details with resolved $ref pointers

        Annotations:
            readOnlyHint: True
            destructiveHint: False
            idempotentHint: True
            openWorldHint: False
        """
        _require_owner()

        if name not in _loaded_apis:
            raise ValueError(f"API '{name}' not found. Use openapi_load first.")

        api = _loaded_apis[name]
        spec = api.spec
        paths = spec.get("paths", {})

        if not isinstance(paths, dict):
            raise ValueError("Invalid spec: paths is not an object")

        if path not in paths:
            raise ValueError(f"Path '{path}' not found in API '{name}'")

        path_item = paths[path]
        if not isinstance(path_item, dict):
            raise ValueError(f"Invalid path item for '{path}'")

        method_lower = method.lower()
        if method_lower not in path_item:
            raise ValueError(f"Method '{method}' not found for path '{path}'")

        operation = path_item[method_lower]
        if not isinstance(operation, dict):
            raise ValueError(f"Invalid operation for {method.upper()} {path}")

        # Resolve all $ref pointers
        resolved_operation = _deep_resolve(spec, operation)

        return {
            "path": path,
            "method": method.upper(),
            **resolved_operation,
        }

    @mcp.tool(
        description="Call an API operation with the loaded OpenAPI spec.",
    )
    def openapi_call(
        name: str,
        path: str,
        method: str,
        path_params: dict[str, Any] | None = None,
        query_params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        body: Any | None = None,
        timeout_s: int = 30,
        max_response_bytes: int = 100000,
    ) -> dict[str, Any]:
        """Call an API operation.

        Parameters:
            name: API name
            path: Path with {param} placeholders
            method: HTTP method
            path_params: Path parameter values
            query_params: Query parameters
            headers: Additional headers
            body: Request body
            timeout_s: Request timeout (default 30)
            max_response_bytes: Max response size (default 100000)

        Returns:
            {"status": int, "headers": dict, "body": Any, "truncated": bool}

        Annotations:
            readOnlyHint: False
            destructiveHint: True
            idempotentHint: False
            openWorldHint: True
        """
        _require_owner()

        if name not in _loaded_apis:
            raise ValueError(f"API '{name}' not found. Use openapi_load first.")

        api = _loaded_apis[name]

        # Build URL with path params
        resolved_path = path
        if path_params:
            for param_name, param_value in path_params.items():
                placeholder = "{" + param_name + "}"
                resolved_path = resolved_path.replace(placeholder, str(param_value))

        # Check if there are remaining placeholders
        import re
        remaining = re.findall(r"\{([^}]+)\}", resolved_path)
        if remaining:
            raise ValueError(f"Missing path parameters: {remaining}")

        # Build full URL
        url = urljoin(api.base_url.rstrip("/") + "/", resolved_path.lstrip("/"))

        # Build headers
        request_headers: dict[str, str] = {"Accept": "application/json"}
        if api.auth_header:
            request_headers[api.auth_header_name] = api.auth_header
        if headers:
            request_headers.update(headers)

        # Make the request
        try:
            response = httpx.request(
                method=method.upper(),
                url=url,
                params=query_params,
                headers=request_headers,
                json=body if body is not None else None,
                timeout=timeout_s,
            )
        except httpx.RequestError as e:
            raise RuntimeError(f"Request failed: {e}") from e

        # Process response
        content = response.content
        truncated = len(content) > max_response_bytes
        content = content[:max_response_bytes]

        result: dict[str, Any] = {
            "status": response.status_code,
            "headers": dict(response.headers),
            "truncated": truncated,
        }

        # Try to parse as JSON, otherwise return as text
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                result["body"] = response.json()
            except json.JSONDecodeError:
                result["body"] = content.decode("utf-8", errors="replace")
        else:
            result["body"] = content.decode("utf-8", errors="replace")

        return result