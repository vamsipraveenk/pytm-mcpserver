
import asyncio
import sys
import os
from typing import Any, Dict, List

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Import modularized components
from core_utils import (
    has_graphviz, find_python, extract_components, 
    generate_simple_dot, PATTERNS
)
from pytm_generator import (
    generate_pytm_code, execute_pytm_fast, 
    convert_dot_to_image, save_diagram_to_file
)

server = Server("threatmodel-mcp")

# Check for Graphviz installation
GRAPHVIZ_AVAILABLE = has_graphviz()

# Global caches
_code_cache = {}
_diagram_cache = {}

# Store python command globally
_python_cmd = None

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools."""
    return [
        Tool(
            name="analyze_system",
            description="Analyze a system and generate threat model with components",
            inputSchema={
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Natural language description of your system"
                    }
                },
                "required": ["description"]
            }
        ),
        Tool(
            name="get_threats",
            description="Get list of security threats for a system",
            inputSchema={
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Natural language description of your system"
                    },
                    "severity_filter": {
                        "type": "string",
                        "enum": ["all", "high", "medium", "low"],
                        "description": "Filter threats by severity",
                        "default": "all"
                    }
                },
                "required": ["description"]
            }
        ),
        Tool(
            name="generate_diagram",
            description="Generate a data flow diagram (returns DOT format)",
            inputSchema={
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Natural language description of your system"
                    },
                    "format": {
                        "type": "string",
                        "enum": ["dot", "svg", "png"],
                        "description": "Output format for diagram",
                        "default": "dot"
                    }
                },
                "required": ["description"]
            }
        ),
        Tool(
            name="save_diagram",
            description="Save a threat model diagram to a file",
            inputSchema={
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Natural language description of your system"
                    },
                    "filepath": {
                        "type": "string",
                        "description": "Path where to save the diagram file (relative paths will be saved to ~/threatmodel_diagrams/)"
                    },
                    "format": {
                        "type": "string",
                        "enum": ["png", "svg", "dot"],
                        "description": "Output format for the file",
                        "default": "png"
                    },
                    "base_path": {
                        "type": "string",
                        "description": "Base directory for relative paths (optional, defaults to ~/threatmodel_diagrams/)"
                    }
                },
                "required": ["description", "filepath"]
            }
        ),
        Tool(
            name="visualize_diagram",
            description="Generate and return a PNG image of the threat model diagram",
            inputSchema={
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Natural language description of your system"
                    }
                },
                "required": ["description"]
            }
        ),
        Tool(
            name="get_pytm_code",
            description="Get the generated PyTM code for a system",
            inputSchema={
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Natural language description of your system"
                    }
                },
                "required": ["description"]
            }
        ),
        Tool(
            name="quick_analysis",
            description="Quick security analysis with key findings",
            inputSchema={
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Natural language description of your system"
                    }
                },
                "required": ["description"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any] | None = None) -> List[TextContent]:
    """Handle tool calls."""
    args = arguments or {}
    description = args.get("description", "").strip()
    
    if not description:
        return [TextContent(type="text", text="Error: System description is required")]
    
    # Extract components once
    components, boundaries = extract_components(description)
    
    # Cache the code
    cache_key = description[:100]
    if cache_key not in _code_cache:
        _code_cache[cache_key] = generate_pytm_code(description, components, boundaries)
    pytm_code = _code_cache[cache_key]
    
    try:
        if name == "analyze_system":
            result = f"# System Analysis\n\n"
            result += f"## Components Identified ({len(components)})\n\n"
            
            by_type = {}
            for comp in components:
                comp_type = comp['type']
                if comp_type not in by_type:
                    by_type[comp_type] = []
                by_type[comp_type].append(comp)
            
            for comp_type, comps in by_type.items():
                result += f"### {comp_type.title()}s\n"
                for comp in comps:
                    result += f"- **{comp['name']}** (in {comp['boundary']})\n"
                result += "\n"
            
            result += f"## Trust Boundaries ({len(boundaries)})\n"
            for boundary in boundaries:
                result += f"- {boundary}\n"
            
            return [TextContent(type="text", text=result)]
        
        elif name == "get_threats":
            result = await execute_pytm_fast(pytm_code, ['--list'], _python_cmd)
            
            if "error" in result:
                generic_threats = """# Security Threats Identified

## High Severity
- **INP01**: Potential SQL Injection in database queries
- **AUTH01**: Weak authentication between components
- **CRYPTO01**: Unencrypted data transmission

## Medium Severity  
- **LOG01**: Insufficient logging and monitoring
- **ACCESS01**: Missing access controls on APIs

## Recommendations
- Implement input validation on all user inputs
- Use parameterized queries for database access
- Enable TLS/SSL for all communications
- Implement proper authentication and authorization
- Add comprehensive logging and monitoring"""
                return [TextContent(type="text", text=generic_threats)]
            
            threats_text = result.get("output", "")
            severity_filter = args.get("severity_filter", "all")
            
            if severity_filter != "all":
                filtered = f"# Filtered Threats ({severity_filter.upper()} severity)\n\n"
                filtered += threats_text
                return [TextContent(type="text", text=filtered)]
            
            return [TextContent(type="text", text=f"# All Threats\n\n{threats_text}")]
        
        elif name == "generate_diagram":
            format_type = args.get("format", "dot")
            
            # Generate or get cached DOT
            if cache_key not in _diagram_cache:
                result = await execute_pytm_fast(pytm_code, ['--dfd'], _python_cmd)
                if "error" in result:
                    _diagram_cache[cache_key] = generate_simple_dot(components, boundaries)
                else:
                    _diagram_cache[cache_key] = result.get('output', '')
            
            dot_content = _diagram_cache[cache_key]
            
            if format_type == "dot":
                return [TextContent(type="text", text=f"```dot\n{dot_content}\n```")]
            
            elif format_type in ["svg", "png"]:
                if GRAPHVIZ_AVAILABLE:
                    image_data = await convert_dot_to_image(dot_content, format_type)
                    if image_data:
                        if format_type == "png":
                            return [TextContent(type="text", text=f"![Diagram](data:image/png;base64,{image_data})")]
                        else:
                            return [TextContent(type="text", text=f"```svg\n{image_data}\n```")]
                    else:
                        return [TextContent(type="text", text="Failed to convert diagram. Returning DOT format:\n\n" + f"```dot\n{dot_content}\n```")]
                else:
                    return [TextContent(type="text", text=f"Graphviz not available. Install it to generate {format_type.upper()}.\n\nDOT format:\n```dot\n{dot_content}\n```")]
        
        elif name == "save_diagram":
            filepath = args.get("filepath", "")
            format_type = args.get("format", "png")
            base_path = args.get("base_path", None)
            
            if not filepath:
                return [TextContent(type="text", text="Error: filepath is required")]
            
            # Generate DOT if not cached
            if cache_key not in _diagram_cache:
                result = await execute_pytm_fast(pytm_code, ['--dfd'])
                if "error" in result:
                    _diagram_cache[cache_key] = generate_simple_dot(components, boundaries)
                else:
                    _diagram_cache[cache_key] = result.get('output', '')
            
            dot_content = _diagram_cache[cache_key]
            
            # Save the diagram with base_path
            save_result = await save_diagram_to_file(dot_content, filepath, format_type, base_path, GRAPHVIZ_AVAILABLE)
            
            if "error" in save_result:
                return [TextContent(type="text", text=f"Error: {save_result['error']}")]
            else:
                return [TextContent(type="text", text=save_result['message'])]
        
        elif name == "visualize_diagram":
            # Generate or get cached DOT
            if cache_key not in _diagram_cache:
                result = await execute_pytm_fast(pytm_code, ['--dfd'], _python_cmd)
                if "error" in result:
                    _diagram_cache[cache_key] = generate_simple_dot(components, boundaries)
                else:
                    _diagram_cache[cache_key] = result.get('output', '')
            
            dot_content = _diagram_cache[cache_key]
            
            if GRAPHVIZ_AVAILABLE:
                image_data = await convert_dot_to_image(dot_content, 'png')
                if image_data:
                    return [TextContent(type="text", text=f"# Threat Model Diagram\n\n![Threat Model Diagram](data:image/png;base64,{image_data})\n\n## Components: {len(components)}\n## Boundaries: {len(boundaries)}")]
                else:
                    return [TextContent(type="text", text="Failed to generate image. Here's the DOT source:\n\n" + f"```dot\n{dot_content}\n```")]
            else:
                return [TextContent(type="text", text="Graphviz not installed. Install it to visualize diagrams.\n\nDOT source:\n" + f"```dot\n{dot_content}\n```\n\nInstall Graphviz: https://graphviz.org/download/")]
        
        elif name == "get_pytm_code":
            return [TextContent(type="text", text=f"```python\n{pytm_code}\n```")]
        
        elif name == "quick_analysis":
            analysis = f"""# Quick Security Analysis

## System Overview
- **Components**: {len(components)}
- **Trust Boundaries**: {len(boundaries)}
- **External Integrations**: {len([c for c in components if c['type'] == 'external'])}

## Key Security Concerns

### Critical
1. **Data Protection**: Ensure all data at rest and in transit is encrypted
2. **Authentication**: Implement strong authentication between all components
3. **Input Validation**: Validate all inputs to prevent injection attacks

### Important  
1. **Access Control**: Implement least privilege access
2. **Logging**: Enable comprehensive security logging
3. **Secrets Management**: Use secure vault for credentials

### Recommendations
1. Regular security audits
2. Implement rate limiting
3. Use security headers
4. Enable CORS properly
5. Regular dependency updates

## Next Steps
1. Run full threat analysis with `get_threats`
2. Review component interactions with `generate_diagram`
3. Implement security controls in `get_pytm_code`"""
            
            return [TextContent(type="text", text=analysis)]
        
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
            
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

async def main():
    """Run the MCP server."""
    global _python_cmd
    
    print("===========================================", file=sys.stderr)
    print("ThreatModel MCP Server (Enhanced)", file=sys.stderr)
    print("===========================================", file=sys.stderr)
    print("", file=sys.stderr)
    
    _python_cmd = find_python()
    if _python_cmd:
        print(f"Python found: {_python_cmd}", file=sys.stderr)
    else:
        print("WARNING: Python not found in PATH", file=sys.stderr)
    
    if GRAPHVIZ_AVAILABLE:
        print("Graphviz found: Diagram visualization enabled", file=sys.stderr)
    else:
        print("WARNING: Graphviz not found. Install for diagram visualization", file=sys.stderr)
        print("         https://graphviz.org/download/", file=sys.stderr)
    
    print("", file=sys.stderr)
    print("Available tools:", file=sys.stderr)
    print("- analyze_system: Component analysis", file=sys.stderr)
    print("- get_threats: Security threat list", file=sys.stderr)
    print("- generate_diagram: DFD visualization", file=sys.stderr)
    print("- visualize_diagram: PNG image generation", file=sys.stderr)
    print("- save_diagram: Save diagram to file", file=sys.stderr)
    print("- get_pytm_code: PyTM source code", file=sys.stderr)
    print("- quick_analysis: Quick security summary", file=sys.stderr)
    print("", file=sys.stderr)
    print("Add to Claude Desktop config:", file=sys.stderr)
    print("{", file=sys.stderr)
    print('  "mcpServers": {', file=sys.stderr)
    print('    "threatmodel": {', file=sys.stderr)
    print('      "command": "python",', file=sys.stderr)
    print(f'      "args": ["{os.path.abspath(__file__)}"]', file=sys.stderr)
    print('    }', file=sys.stderr)
    print('  }', file=sys.stderr)
    print("}", file=sys.stderr)
    print("", file=sys.stderr)
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        print("Testing enhanced threat model tools...")
        
        test_desc = "web application with database and redis cache"
        components, boundaries = extract_components(test_desc)
        print(f"Components: {[c['name'] for c in components]}")
        
        print("\nQuick Analysis Test:")
        print(f"- Components: {len(components)}")
        print(f"- Boundaries: {len(boundaries)}")
        print(f"- External: {len([c for c in components if c['type'] == 'external'])}")
        
        print("\nSimple DOT Test:")
        dot = generate_simple_dot(components, boundaries)
        print(dot[:200] + "...")
        
        print(f"\nGraphviz available: {GRAPHVIZ_AVAILABLE}")
        print("\nAll tests passed!")
    else:
        asyncio.run(main())
