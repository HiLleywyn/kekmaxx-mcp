#!/usr/bin/env python3
"""Verify the MCP handshake and tool inventory without network access."""

from __future__ import annotations

import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

EXPECTED = {
    "browse_page",
    "inspect_public_page",
    "resolve_dns",
    "inspect_tls_certificate",
    "compare_public_pages",
    "google_ads_find_advertisers",
    "fec_independent_expenditure_summary",
}


async def run() -> None:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "kekmaxxing_mcp.server"],
    )
    async with stdio_client(parameters) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = {tool.name for tool in tools.tools}
            if names != EXPECTED:
                raise RuntimeError(f"Unexpected MCP tool inventory: {sorted(names)}")
    print("MCP handshake: OK")
    print(f"Tool inventory: OK ({len(EXPECTED)})")


if __name__ == "__main__":
    asyncio.run(run())
