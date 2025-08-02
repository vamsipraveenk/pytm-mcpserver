#!/usr/bin/env python3
"""
Test script to demonstrate the MCP server functionality.
This would typically be run by an MCP client.
"""

import asyncio
import json
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

async def test_mcp_server():
    """Test the MCP server by calling the hello_world tool."""
    
    # Server parameters - this would point to your server script
    server_params = StdioServerParameters(
        command="python",
        args=["server.py"],
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize the session
            await session.initialize()
            
            # List available tools
            tools = await session.list_tools()
            print("Available tools:")
            for tool in tools.tools:
                print(f"  - {tool.name}: {tool.description}")
            
            # Call the hello_world tool without parameters
            print("\n--- Calling hello_world() ---")
            result1 = await session.call_tool("hello_world", {})
            for content in result1.content:
                if hasattr(content, 'text'):
                    print(f"Result: {content.text}")
            
            # Call the hello_world tool with a name parameter
            print("\n--- Calling hello_world with name='Alice' ---")
            result2 = await session.call_tool("hello_world", {"name": "Alice"})
            for content in result2.content:
                if hasattr(content, 'text'):
                    print(f"Result: {content.text}")

if __name__ == "__main__":
    print("Testing MCP Hello World Server...")
    asyncio.run(test_mcp_server())
