#!/usr/bin/env python3
"""Verify the MCP handshake and tool inventory without network access."""

from __future__ import annotations

import ast
import asyncio
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def expected_inventory():
    root = Path(__file__).resolve().parents[1] / "src/kekmaxxing_mcp"
    names = set()
    for path in (root / "server.py", root / "intelligence_tools.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(
                    isinstance(d, ast.Call)
                    and isinstance(d.func, ast.Attribute)
                    and d.func.attr == "tool"
                    for d in node.decorator_list
                ):
                    names.add(node.name)
    return names


async def run() -> None:
    expected = expected_inventory()
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "kekmaxxing_mcp.server"],
    )
    temporary = tempfile.TemporaryDirectory(prefix="kekmaxxing-smoke-")
    parameters.env = {"KEKMAXX_DATA_DIR": temporary.name}
    async with stdio_client(parameters) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = {tool.name for tool in tools.tools}
            if names != expected:
                raise RuntimeError(f"Unexpected MCP tool inventory: {sorted(names)}")
            import jsonschema

            for tool in tools.tools:
                jsonschema.Draft202012Validator.check_schema(tool.inputSchema)
            result = await session.call_tool("investigation_workflows", {})
            if result.isError:
                raise RuntimeError("MCP workflow call failed")
            resource = await session.read_resource("kekmaxxing://skills/evidence-verification")
            if not resource.contents:
                raise RuntimeError("MCP skill resource is unavailable")
    temporary.cleanup()
    print("MCP handshake: OK")
    print(f"Tool inventory and schemas: OK ({len(expected)})")


if __name__ == "__main__":
    asyncio.run(run())
