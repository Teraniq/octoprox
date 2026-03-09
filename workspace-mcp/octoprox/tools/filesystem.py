"""Filesystem tools for workspace operations."""

from __future__ import annotations

import shutil
from typing import TYPE_CHECKING

from ..auth import _require_owner
from ..path_utils import _atomic_write, _resolve_path
from .catalog import catalog_tool

if TYPE_CHECKING:
    from .. import OctoproxMCP


def register_filesystem_tools(mcp: "OctoproxMCP") -> None:
    """Register filesystem tools with the MCP server."""

    @catalog_tool(
        mcp,
        tool_id="fs_list",
        provider="octoprox",
        tool_class="filesystem",
        operations=("list", "inspect"),
        risk_class="low",
        supports_readonly=True,
        evidence_kind="filesystem_listing",
    )
    def fs_list(path: str = ".") -> list[str]:
        """List files and directories at the given path."""
        _require_owner()
        target = _resolve_path(path)
        if not target.exists():
            return []
        return [entry.name for entry in target.iterdir()]

    @catalog_tool(
        mcp,
        tool_id="fs_read_text",
        provider="octoprox",
        tool_class="filesystem",
        operations=("read", "inspect"),
        risk_class="low",
        supports_readonly=True,
        evidence_kind="filesystem_text",
    )
    def fs_read_text(path: str, max_bytes: int = 200000) -> str:
        """Read text content from a file."""
        _require_owner()
        target = _resolve_path(path)
        if not target.exists():
            raise FileNotFoundError("File not found")
        data = target.read_bytes()[:max_bytes]
        return data.decode("utf-8", errors="replace")

    @catalog_tool(
        mcp,
        tool_id="fs_write_text",
        provider="octoprox",
        tool_class="filesystem",
        operations=("write", "create", "update"),
        risk_class="high",
        supports_readonly=False,
        evidence_kind="filesystem_text",
    )
    def fs_write_text(path: str, text: str, mkdirs: bool = True) -> str:
        """Write text content to a file."""
        _require_owner()
        target = _resolve_path(path)
        if mkdirs:
            target.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(target, text)
        return "ok"

    @catalog_tool(
        mcp,
        tool_id="fs_delete",
        provider="octoprox",
        tool_class="filesystem",
        operations=("delete", "remove"),
        risk_class="high",
        supports_readonly=False,
        evidence_kind="filesystem_mutation",
    )
    def fs_delete(path: str, recursive: bool = False) -> str:
        """Delete a file or directory."""
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
