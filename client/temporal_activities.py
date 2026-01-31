from __future__ import annotations

from typing import Any

from .mcp_client import call_tool_sync


def mcp_fs_read(endpoint: str, token: str, path: str) -> str:
    return call_tool_sync(endpoint, token, "fs_read_text", {"path": path})


def mcp_fs_write(endpoint: str, token: str, path: str, text: str) -> str:
    return call_tool_sync(endpoint, token, "fs_write_text", {"path": path, "text": text, "mkdirs": True})


def mcp_git(endpoint: str, token: str, args: list[str]) -> dict[str, Any]:
    return call_tool_sync(endpoint, token, "git", {"args": args})
