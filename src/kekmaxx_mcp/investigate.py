"""CLI parity with registered MCP tools; no additional collection implementations."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

from .branding import meme_tool_name
from .server import mcp


async def execute(tool_name, arguments):
    tool = mcp._tool_manager.get_tool(tool_name)
    if tool is None:
        try:
            tool = mcp._tool_manager.get_tool(meme_tool_name(tool_name))
        except RuntimeError:
            pass
    if tool is None:
        raise ValueError("Unknown tool")
    return await tool.run(arguments)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", help="Registered tool name, inventory, or monitor-worker")
    parser.add_argument("--input", type=Path, help="Private JSON arguments file, otherwise stdin")
    parser.add_argument("--output", type=Path, help="Private output file, otherwise stdout")
    parser.add_argument(
        "--parquet", type=Path, help="Export returned record rows (optional columnar extra)"
    )
    args = parser.parse_args()
    try:
        if args.tool == "inventory":
            result = [
                {"name": t.name, "description": t.description, "schema": t.parameters}
                for t in mcp._tool_manager.list_tools()
            ]
        else:
            raw = (
                args.input.read_text(encoding="utf-8") if args.input else sys.stdin.read(2_000_001)
            )
            if len(raw) > 2_000_000:
                raise ValueError("CLI input exceeds 2 MB")
            inputs = json.loads(raw)
            if args.tool == "monitor-worker":
                while True:
                    result = asyncio.run(execute("this_is_fine_monitor_run", inputs))
                    print(json.dumps(result, ensure_ascii=False), flush=True)
                    time.sleep(30)
            result = asyncio.run(execute(args.tool, inputs))
        if args.parquet:
            try:
                import pyarrow as pa
                import pyarrow.parquet as pq
            except ImportError as exc:
                raise RuntimeError("Install kekmaxx-mcp[columnar]") from exc
            rows = result.get("records", [])
            pq.write_table(pa.Table.from_pylist(rows), args.parquet)
        rendered = json.dumps(result, indent=2, ensure_ascii=False)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
        else:
            print(rendered)
        return 0
    except (ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
