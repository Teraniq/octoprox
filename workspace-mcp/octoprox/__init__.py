"""Octoprox - OpenAPI-to-MCP Adapter for workspace-mcp."""

from __future__ import annotations

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.types import Tool as MCPTool
from pydantic import AnyHttpUrl

from .auth import ManagerTokenVerifier, _require_owner
from .config import ENABLE_OPENAPI
from .path_utils import WORKSPACE_ROOT, _atomic_write, _resolve_path
from .tools.catalog import get_tool_catalog


class OctoproxMCP(FastMCP):
    """Extended FastMCP with custom tool listing for metadata support."""

    async def list_tools(self) -> list[MCPTool]:
        tools = self._tool_manager.list_tools()
        catalog_by_name = {entry["tool_id"]: entry for entry in get_tool_catalog()}
        return [
            MCPTool(
                name=info.name,
                description=info.description,
                inputSchema=info.parameters,
                **catalog_by_name.get(info.name, {}),
            )
            for info in tools
        ]

    def get_tool_catalog(self) -> list[dict[str, object]]:
        catalog_by_name = {
            entry["tool_id"]: dict(entry) for entry in get_tool_catalog()
        }
        for info in self._tool_manager.list_tools():
            if info.name in catalog_by_name:
                catalog_by_name[info.name]["name"] = info.name
                catalog_by_name[info.name]["description"] = info.description
                catalog_by_name[info.name]["inputSchema"] = info.parameters
        return [catalog_by_name[name] for name in sorted(catalog_by_name)]


# Create the MCP app instance
mcp = OctoproxMCP(
    "octoprox",
    auth=AuthSettings(
        issuer_url=AnyHttpUrl("http://workspace-manager:8000"),
        resource_server_url=None,
    ),
    token_verifier=ManagerTokenVerifier(),
)

# Import and register all tools
from .tools import register_all_tools

register_all_tools(mcp)

# Export the streamable HTTP app
app = mcp.streamable_http_app()

__all__ = [
    "OctoproxMCP",
    "app",
    "get_tool_catalog",
    "mcp",
    "ManagerTokenVerifier",
    "_require_owner",
    "WORKSPACE_ROOT",
    "_resolve_path",
    "_atomic_write",
    "ENABLE_OPENAPI",
]
