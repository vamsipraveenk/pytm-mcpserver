#!/usr/bin/env python3
"""
MCP Server with hello world and PyTM data flow diagram generation tools.
"""

import asyncio
import sys
import os
import tempfile
from typing import Any, Dict, List

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    Tool,
    TextContent,
)

# PyTM imports
try:
    from pytm import TM, Server as PyTMServer, Actor, Dataflow, Boundary, Classification, DatastoreType, Datastore, Data
    PYTM_AVAILABLE = True
except ImportError:
    PYTM_AVAILABLE = False

# Create the server instance
server = Server("hello-world-server")

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools."""
    tools = [
        Tool(
            name="hello_world",
            description="Returns a simple 'hello world' greeting",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Optional name to include in the greeting"
                    }
                }
            }
        )
    ]
    
    if PYTM_AVAILABLE:
        tools.append(
            Tool(
                name="generate_data_flow_diagram",
                description="Generates a data flow diagram using PyTM threat modeling framework",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "system_name": {
                            "type": "string",
                            "description": "Name of the system being modeled"
                        },
                        "description": {
                            "type": "string",
                            "description": "Description of the system"
                        },
                        "components": {
                            "type": "array",
                            "description": "List of system components",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "type": {"type": "string", "enum": ["server", "actor", "datastore", "boundary"]},
                                    "description": {"type": "string"}
                                },
                                "required": ["name", "type"]
                            }
                        },
                        "dataflows": {
                            "type": "array",
                            "description": "List of data flows between components",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "source": {"type": "string"},
                                    "sink": {"type": "string"},
                                    "name": {"type": "string"},
                                    "data": {"type": "string"}
                                },
                                "required": ["source", "sink", "name"]
                            }
                        },
                        "output_format": {
                            "type": "string",
                            "enum": ["dfd", "seq", "stride"],
                            "description": "Output format: dfd (data flow diagram), seq (sequence diagram), or stride (STRIDE report)",
                            "default": "dfd"
                        },
                        "output_dir": {
                            "type": "string",
                            "description": "Directory to save diagram files (optional, defaults to temp directory)"
                        }
                    },
                    "required": ["system_name", "components"]
                }
            )
        )
    
    return tools

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any] | None = None) -> List[TextContent]:
    """Handle tool calls."""
    if arguments is None:
        arguments = {}
        
    if name == "hello_world":
        # Get the optional name parameter
        user_name = arguments.get("name", "World")
        
        # Create the hello world message
        message = f"Hello {user_name}!"
        
        return [
            TextContent(
                type="text",
                text=message
            )
        ]
    
    elif name == "generate_data_flow_diagram":
        if not PYTM_AVAILABLE:
            return [
                TextContent(
                    type="text",
                    text="PyTM is not available. Please install it using: pip install pytm"
                )
            ]
        
        try:
            return await generate_pytm_diagram(arguments)
        except Exception as e:
            return [
                TextContent(
                    type="text",
                    text=f"Error generating diagram: {str(e)}"
                )
            ]
    
    else:
        raise ValueError(f"Unknown tool: {name}")


async def generate_pytm_diagram(arguments: Dict[str, Any]) -> List[TextContent]:
    """Generate a PyTM data flow diagram."""
    system_name = arguments.get("system_name", "System")
    description = arguments.get("description", "")
    components = arguments.get("components", [])
    dataflows = arguments.get("dataflows", [])
    output_format = arguments.get("output_format", "dfd")
    output_dir = arguments.get("output_dir", None)
    
    # Create threat model
    tm = TM(system_name)
    tm.description = description
    
    # Store component objects for reference
    component_objects = {}
    
    # Create components
    for comp in components:
        comp_name = comp["name"]
        comp_type = comp["type"]
        comp_desc = comp.get("description", "")
        
        if comp_type == "actor":
            component_objects[comp_name] = Actor(comp_name)
        elif comp_type == "server":
            component_objects[comp_name] = PyTMServer(comp_name)
        elif comp_type == "datastore":
            component_objects[comp_name] = Datastore(comp_name)
        elif comp_type == "boundary":
            component_objects[comp_name] = Boundary(comp_name)
        
        if comp_desc:
            component_objects[comp_name].description = comp_desc
    
    # Create dataflows
    for flow in dataflows:
        source_name = flow["source"]
        sink_name = flow["sink"]
        flow_name = flow["name"]
        flow_data = flow.get("data", "")
        
        if source_name in component_objects and sink_name in component_objects:
            df = Dataflow(
                source=component_objects[source_name],
                sink=component_objects[sink_name],
                name=flow_name
            )
            if flow_data:
                # Create a Data object instead of using string directly
                data_obj = Data(flow_data)
                df.data = data_obj
    
    # Generate output based on format
    try:
        # Use provided output directory or create a temporary one
        if output_dir and os.path.exists(output_dir):
            work_dir = output_dir
            cleanup_dir = False
        else:
            work_dir = tempfile.mkdtemp()
            cleanup_dir = True
            
        try:
            if output_format == "dfd":
                tm.process()
                
                # Generate actual DFD diagram file
                try:
                    # Get the DOT format from PyTM
                    dfd_dot = tm.dfd()
                    
                    # Save the DOT file
                    dot_file = os.path.join(work_dir, f"{system_name}_dfd.dot")
                    with open(dot_file, 'w', encoding='utf-8') as f:
                        f.write(dfd_dot)
                    
                    result = f"Data Flow Diagram generated for: {system_name}\n\n"
                    result += f"Description: {description}\n\n"
                    result += f"DOT file saved to: {dot_file}\n"
                    result += f"File size: {os.path.getsize(dot_file)} bytes\n\n"
                    result += "Note: Use Graphviz to convert DOT file to PNG/SVG:\n"
                    result += f"  dot -Tpng {dot_file} -o {system_name}_dfd.png\n\n"
                        
                except Exception as diagram_error:
                    result = f"Could not generate visual diagram: {diagram_error}\n\n"
                
                # Also include textual representation
                result += "Components:\n"
                for name, obj in component_objects.items():
                    result += f"- {name} ({type(obj).__name__}): {getattr(obj, 'description', '')}\n"
                result += "\nData Flows:\n"
                for flow in dataflows:
                    result += f"- {flow['source']} -> {flow['sink']}: {flow['name']}\n"
                
            elif output_format == "seq":
                tm.process()
                
                # Generate sequence diagram
                try:
                    # Get the MSC format from PyTM
                    seq_msc = tm.seq()
                    
                    # Save the MSC file
                    msc_file = os.path.join(work_dir, f"{system_name}_seq.msc")
                    with open(msc_file, 'w', encoding='utf-8') as f:
                        f.write(seq_msc)
                    
                    result = f"Sequence Diagram generated for: {system_name}\n\n"
                    result += f"MSC file saved to: {msc_file}\n"
                    result += f"File size: {os.path.getsize(msc_file)} bytes\n\n"
                    result += "Note: Use mscgen to convert MSC file to PNG/SVG:\n"
                    result += f"  mscgen -T png {msc_file}\n\n"
                        
                except Exception as seq_error:
                    result = f"Could not generate sequence diagram: {seq_error}\n\n"
                
                result += "Sequence of interactions:\n"
                for i, flow in enumerate(dataflows, 1):
                    result += f"{i}. {flow['source']} -> {flow['sink']}: {flow['name']}\n"
                    
            elif output_format == "stride":
                tm.process()
                
                # Generate STRIDE report
                try:
                    # Get the report from PyTM
                    stride_report = tm.report("template")
                    
                    # Save the report file
                    stride_file = os.path.join(work_dir, f"{system_name}_stride.md")
                    with open(stride_file, 'w', encoding='utf-8') as f:
                        f.write(stride_report)
                    
                    result = f"STRIDE Threat Analysis for: {system_name}\n\n"
                    result += f"STRIDE report saved to: {stride_file}\n"
                    result += f"File size: {os.path.getsize(stride_file)} bytes\n\n"
                    
                    # Include part of the report content
                    result += "STRIDE Analysis Results:\n"
                    result += stride_report[:1000] + "..." if len(stride_report) > 1000 else stride_report
                        
                except Exception as stride_error:
                    result = f"Could not generate STRIDE report: {stride_error}\n\n"
                    result += "Components and their potential threats have been analyzed.\n"
            
            return [
                TextContent(
                    type="text",
                    text=result
                )
            ]
            
        finally:
            # Clean up temporary directory if we created one
            if cleanup_dir and os.path.exists(work_dir):
                import shutil
                shutil.rmtree(work_dir)
            
    except Exception as e:
        return [
            TextContent(
                type="text",
                text=f"Error processing threat model: {str(e)}"
            )
        ]

async def main():
    """Main entry point for the server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
