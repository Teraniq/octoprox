"""Octoprox - OpenAPI-to-MCP Adapter for workspace-mcp."""
from __future__ import annotations

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.types import Tool as MCPTool

from .auth import ManagerTokenVerifier, _require_owner
from .config import ENABLE_OPENAPI
from .path_utils import WORKSPACE_ROOT, _atomic_write, _resolve_path


class OctoproxMCP(FastMCP):
    """Extended FastMCP with custom tool listing for metadata support."""

    async def list_tools(self) -> list[MCPTool]:
        tools = self._tool_manager.list_tools()
        return [
            MCPTool(
                name=info.name,
                description=info.description,
                inputSchema=info.parameters,
            )
            for info in tools
        ]


# Create the MCP app instance
mcp = OctoproxMCP(
    "octoprox",
    auth=AuthSettings(issuer_url="http://workspace-manager:8000", resource_server_url=None),
    token_verifier=ManagerTokenVerifier(),
)

# Import and register all tools
from .tools import register_all_tools

register_all_tools(mcp)

# Export the streamable HTTP app
app = mcp.streamable_http_app()

__all__ = [
    "app",
    "mcp",
    "ManagerTokenVerifier",
    "_require_owner",
    "WORKSPACE_ROOT",
    "_resolve_path",
    "_atomic_write",
    "ENABLE_OPENAPI",
]