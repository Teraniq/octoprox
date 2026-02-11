"""Tool registration for octoprox."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .. import OctoproxMCP


def register_all_tools(mcp: "OctoproxMCP") -> None:
    """Register all tools with the MCP server."""
    from .filesystem import register_filesystem_tools
    from .git import register_git_tools
    from .gitlab import register_gitlab_tools
    from .openapi import register_openapi_tools
    from .ssh import register_ssh_tools

    register_filesystem_tools(mcp)
    register_git_tools(mcp)
    register_gitlab_tools(mcp)
    register_ssh_tools(mcp)
    register_openapi_tools(mcp)


__all__ = ["register_all_tools"]