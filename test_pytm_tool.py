#!/usr/bin/env python3
"""
Test script for the PyTM data flow diagram generation tool.
"""

import asyncio
import json
from server import call_tool

async def test_pytm_tool():
    """Test the PyTM data flow diagram generation tool."""
    
    # Example system with web application components
    test_arguments = {
        "system_name": "WebApplication",
        "description": "A simple web application with user authentication and data storage",
        "components": [
            {
                "name": "User",
                "type": "actor",
                "description": "End user of the web application"
            },
            {
                "name": "Web Server",
                "type": "server",
                "description": "Main web application server"
            },
            {
                "name": "Database",
                "type": "datastore",
                "description": "User data and application data storage"
            },
            {
                "name": "DMZ",
                "type": "boundary",
                "description": "Demilitarized zone boundary"
            }
        ],
        "dataflows": [
            {
                "source": "User",
                "sink": "Web Server",
                "name": "HTTP Request",
                "data": "User credentials and requests"
            },
            {
                "source": "Web Server",
                "sink": "User",
                "name": "HTTP Response",
                "data": "Web pages and data"
            },
            {
                "source": "Web Server",
                "sink": "Database",
                "name": "Database Query",
                "data": "SQL queries and user data"
            },
            {
                "source": "Database",
                "sink": "Web Server",
                "name": "Database Response",
                "data": "Query results"
            }
        ],
        "output_format": "dfd"
    }
    
    print("Testing PyTM Data Flow Diagram Generation Tool...")
    print("=" * 50)
    
    try:
        result = await call_tool("generate_data_flow_diagram", test_arguments)
        
        for content in result:
            print(content.text)
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_pytm_tool())
