#!/usr/bin/env python3
"""Verify the MCP handshake and tool inventory without network access."""

from __future__ import annotations

import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

EXPECTED = {
    "browse_page",
    "compare_public_pages",
    "fcc_file_details",
    "fcc_public_file_download_url",
    "fcc_search_entity_files",
    "fec_api_schedule_e",
    "fec_filing_schedule_e",
    "fec_independent_expenditure_summary",
    "fec_treasurer_service_baseline",
    "fpds_award_history",
    "google_ads_find_advertisers",
    "inspect_public_page",
    "inspect_tls_certificate",
    "public_checkout_identity_map",
    "public_post_event_timeline",
    "public_site_identity_map",
    "public_x_status",
    "resolve_dns",
    "usaspending_award_record",
    "wordpress_public_identity_map",
    "wordpress_public_post_counts",
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
