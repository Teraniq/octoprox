from __future__ import annotations

import asyncio
from typing import Any

import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def call_tool(endpoint: str, token: str, tool: str, arguments: dict[str, Any] | None = None) -> Any:
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(headers=headers) as http_client:
        async with streamable_http_client(endpoint, http_client=http_client) as (read_stream, write_stream, _):
            session = ClientSession(read_stream, write_stream)
            await session.initialize()
            result = await session.call_tool(tool, arguments or {})
            await session.close()
    if result.isError:
        raise RuntimeError(result.content)
    return result.content


def call_tool_sync(endpoint: str, token: str, tool: str, arguments: dict[str, Any] | None = None) -> Any:
    return asyncio.run(call_tool(endpoint, token, tool, arguments))
