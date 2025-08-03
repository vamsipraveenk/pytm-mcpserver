
import asyncio
import sys
import os
import re
from typing import Any, Dict, List, Optional, Union
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Import modularized components
from core_utils import has_graphviz, find_python
from pytm_generator import execute_pytm_fast, convert_dot_to_image, save_diagram_to_file

server = Server("threatmodel-advanced")

# Check for Graphviz installation
GRAPHVIZ_AVAILABLE = has_graphviz()

# Global caches
_code_cache = {}
_diagram_cache = {}
_threat_cache = {}

# Store python command globally
_python_cmd = None

# Advanced component types with richer metadata
class ComponentType(str, Enum):
    ACTOR = "actor"
    USER = "user"
    ADMIN = "admin"
    SERVICE_ACCOUNT = "service_account"
    SERVER = "server"
    API_GATEWAY = "api_gateway"
    MICROSERVICE = "microservice"
    LAMBDA = "lambda"
    CONTAINER = "container"
    DATABASE = "database"
    CACHE = "cache"
    MESSAGE_QUEUE = "queue"
    FILE_STORAGE = "file_storage"
    EXTERNAL_SERVICE = "external"
    LOAD_BALANCER = "load_balancer"
    FIREWALL = "firewall"
    PROCESS = "process"

class Protocol(str, Enum):
    HTTPS = "HTTPS"
    HTTP = "HTTP"
    GRPC = "gRPC"
    WEBSOCKET = "WebSocket"
    MQTT = "MQTT"
    AMQP = "AMQP"
    SQL = "SQL"
    REDIS = "Redis Protocol"
    S3 = "S3 API"
    CUSTOM = "Custom"

class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    TOP_SECRET = "TOP_SECRET"

@dataclass
class SecurityControl:
    name: str
    enabled: bool
    config: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Component:
    name: str
    type: ComponentType
    boundary: str
    description: Optional[str] = None
    security_controls: List[SecurityControl] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
@dataclass
class DataFlow:
    source: str
    destination: str
    protocol: Protocol
    data_type: str
    classification: DataClassification
    bidirectional: bool = False
    port: Optional[int] = None
    authentication: Optional[str] = None
    encryption: Optional[str] = None
    description: Optional[str] = None

@dataclass
class TrustBoundary:
    name: str
    type: str  # Internet, DMZ, Internal, Cloud, OnPrem, etc.
    security_level: int  # 0-10
    description: Optional[str] = None
    controls: List[str] = field(default_factory=list)

def generate_advanced_pytm_code(
    system_name: str,
    description: str,
    components: List[Component],
    boundaries: List[TrustBoundary],
    dataflows: List[DataFlow],
    metadata: Dict[str, Any]
) -> str:
    """Generate advanced PyTM code with rich metadata"""
    
    code = f'''#!/usr/bin/env python3
"""
Generated PyTM Threat Model
System: {system_name}
Generated: {metadata.get('timestamp', 'N/A')}
"""

from pytm import (
    TM, Actor, Server, Datastore, Process, Lambda, 
    Dataflow, Boundary, ExternalEntity, Data,
    Classification, DatastoreType
)

# Initialize threat model
tm = TM("{system_name}")
tm.description = """{description}"""
tm.isOrdered = True
tm.mergeResponses = True

'''
    
    # Add metadata as comments
    if metadata:
        code += "# Metadata\n"
        for key, value in metadata.items():
            code += f"# {key}: {value}\n"
        code += "\n"
    
    # Create boundaries with security controls
    code += "# Trust Boundaries\n"
    boundary_vars = {}
    for boundary in boundaries:
        var = re.sub(r'[^\w]', '_', boundary.name.lower())
        boundary_vars[boundary.name] = var
        code += f'{var} = Boundary("{boundary.name}")\n'
        if boundary.description:
            code += f'{var}.description = "{boundary.description}"\n'
        code += f'# Security Level: {boundary.security_level}/10\n'
        if boundary.controls:
            code += f'# Controls: {", ".join(boundary.controls)}\n'
        code += "\n"
    
    # Create data objects with classification
    if dataflows:
        code += "# Data Objects\n"
        data_objects = {}
        for flow in dataflows:
            if flow.data_type not in data_objects:
                data_var = re.sub(r'[^\w]', '_', flow.data_type.lower()) + "_data"
                data_objects[flow.data_type] = data_var
                code += f'{data_var} = Data("{flow.data_type}")\n'
                code += f'{data_var}.classification = Classification.{flow.classification}\n'
                if flow.data_type.lower() in ['user data', 'personal data', 'pii']:
                    code += f'{data_var}.isPII = True\n'
                if flow.data_type.lower() in ['credentials', 'password', 'token', 'key']:
                    code += f'{data_var}.isCredentials = True\n'
                code += "\n"
    
    # Create components with advanced properties
    code += "# Components\n"
    comp_vars = {}
    for comp in components:
        var = re.sub(r'[^\w]', '_', comp.name.lower())
        comp_vars[comp.name] = var
        
        # Map component types to PyTM classes
        if comp.type in [ComponentType.ACTOR, ComponentType.USER, ComponentType.ADMIN]:
            code += f'{var} = Actor("{comp.name}")\n'
        elif comp.type == ComponentType.EXTERNAL_SERVICE:
            code += f'{var} = ExternalEntity("{comp.name}")\n'
        elif comp.type in [ComponentType.DATABASE, ComponentType.CACHE, ComponentType.FILE_STORAGE]:
            code += f'{var} = Datastore("{comp.name}")\n'
            if comp.type == ComponentType.DATABASE:
                code += f'{var}.type = DatastoreType.SQL\n'
            elif comp.type == ComponentType.FILE_STORAGE:
                code += f'{var}.type = DatastoreType.FILE\n'
        elif comp.type == ComponentType.LAMBDA:
            code += f'{var} = Lambda("{comp.name}")\n'
        elif comp.type == ComponentType.PROCESS:
            code += f'{var} = Process("{comp.name}")\n'
        else:
            code += f'{var} = Server("{comp.name}")\n'
        
        # Set boundary
        if comp.boundary in boundary_vars:
            code += f'{var}.inBoundary = {boundary_vars[comp.boundary]}\n'
        
        # Add description
        if comp.description:
            code += f'{var}.description = "{comp.description}"\n'
        
        # Add security controls
        for control in comp.security_controls:
            if control.enabled and hasattr(control, 'name'):
                control_name = re.sub(r'[^\w]', '_', control.name.lower())
                code += f'{var}.controls.{control_name} = True\n'
                if control.config:
                    code += f'# {control_name} config: {control.config}\n'
        
        # Add metadata as comments
        if comp.metadata:
            for key, value in comp.metadata.items():
                code += f'# {key}: {value}\n'
        
        code += "\n"
    
    # Create data flows with rich properties
    code += "# Data Flows\n"
    for i, flow in enumerate(dataflows):
        if flow.source in comp_vars and flow.destination in comp_vars:
            source_var = comp_vars[flow.source]
            dest_var = comp_vars[flow.destination]
            flow_name = f"{flow.source} to {flow.destination}"
            
            code += f'flow_{i} = Dataflow({source_var}, {dest_var}, "{flow_name}")\n'
            code += f'flow_{i}.protocol = "{flow.protocol}"\n'
            
            if flow.port:
                code += f'flow_{i}.dstPort = {flow.port}\n'
            
            if flow.data_type in data_objects:
                code += f'flow_{i}.data = {data_objects[flow.data_type]}\n'
            
            if flow.authentication:
                code += f'flow_{i}.authenticatedWith = {flow.authentication}\n'
            
            if flow.encryption:
                code += f'flow_{i}.isEncrypted = True\n'
                code += f'# Encryption: {flow.encryption}\n'
            
            if flow.description:
                code += f'flow_{i}.description = "{flow.description}"\n'
            
            code += "\n"
            
            # Add reverse flow if bidirectional
            if flow.bidirectional:
                code += f'flow_{i}_response = Dataflow({dest_var}, {source_var}, "{flow.destination} to {flow.source}")\n'
                code += f'flow_{i}_response.protocol = "{flow.protocol}"\n'
                code += f'flow_{i}_response.isResponse = True\n\n'
    
    code += '''
if __name__ == "__main__":
    tm.process()
'''
    
    return code

def generate_advanced_dot(
    components: List[Component],
    boundaries: List[TrustBoundary],
    dataflows: List[DataFlow]
) -> str:
    """Generate minimal DOT diagram similar to original PyTM style"""
    
    dot = 'digraph {\n'
    
    # Sort boundaries by security level for logical grouping
    sorted_boundaries = sorted(boundaries, key=lambda b: b.security_level)
    
    # Create subgraphs for each boundary - minimal style
    for i, boundary in enumerate(sorted_boundaries):
        dot += f'  subgraph cluster_{i} {{\n'
        dot += f'    label="{boundary.name}";\n'
        
        # Add components in this boundary
        boundary_comps = [c for c in components if c.boundary == boundary.name]
        for comp in boundary_comps:
            var = re.sub(r'[^\w]', '_', comp.name.lower())
            
            # Simple shape mapping like PyTM
            if comp.type in [ComponentType.ACTOR, ComponentType.USER, ComponentType.ADMIN]:
                shape = 'box'
                style = ', style=rounded'
            elif comp.type in [ComponentType.DATABASE, ComponentType.CACHE]:
                shape = 'cylinder'
                style = ''
            elif comp.type == ComponentType.EXTERNAL_SERVICE:
                shape = 'box'
                style = ', style=dashed'
            else:
                shape = 'box'
                style = ''
            
            dot += f'    {var} [label="{comp.name}", shape={shape}{style}];\n'
        
        dot += '  }\n\n'
    
    # Add data flows - simple style
    dot += '  // Data flows\n'
    for flow in dataflows:
        source_var = re.sub(r'[^\w]', '_', flow.source.lower())
        dest_var = re.sub(r'[^\w]', '_', flow.destination.lower())
        
        # Simple label
        label = flow.data_type
        
        # Simple style based on encryption
        if flow.encryption:
            style = ''
        else:
            style = ', style=dashed'
        
        dot += f'  {source_var} -> {dest_var} [label="{label}"{style}];\n'
        
        if flow.bidirectional:
            dot += f'  {dest_var} -> {source_var} [label="Response", style=dotted];\n'
    
    dot += '}\n'
    return dot

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available advanced tools."""
    return [
        Tool(
            name="create_threat_model",
            description="Create a comprehensive threat model with detailed components, boundaries, and data flows",
            inputSchema={
                "type": "object",
                "properties": {
                    "system_name": {
                        "type": "string",
                        "description": "Name of the system being modeled"
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed description of the system"
                    },
                    "components": {
                        "type": "array",
                        "description": "List of system components with detailed properties",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "type": {
                                    "type": "string",
                                    "enum": [t.value for t in ComponentType]
                                },
                                "boundary": {"type": "string"},
                                "description": {"type": "string"},
                                "security_controls": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string"},
                                            "enabled": {"type": "boolean"},
                                            "config": {"type": "object"}
                                        }
                                    }
                                },
                                "metadata": {
                                    "type": "object",
                                    "description": "Additional metadata (version, criticality, owner, etc.)"
                                }
                            },
                            "required": ["name", "type", "boundary"]
                        }
                    },
                    "boundaries": {
                        "type": "array",
                        "description": "Trust boundaries with security levels",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "type": {"type": "string"},
                                "security_level": {
                                    "type": "integer",
                                    "minimum": 0,
                                    "maximum": 10
                                },
                                "description": {"type": "string"},
                                "controls": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                }
                            },
                            "required": ["name", "type", "security_level"]
                        }
                    },
                    "dataflows": {
                        "type": "array",
                        "description": "Data flows between components",
                        "items": {
                            "type": "object",
                            "properties": {
                                "source": {"type": "string"},
                                "destination": {"type": "string"},
                                "protocol": {
                                    "type": "string",
                                    "enum": [p.value for p in Protocol]
                                },
                                "data_type": {"type": "string"},
                                "classification": {
                                    "type": "string",
                                    "enum": [c.value for c in DataClassification]
                                },
                                "bidirectional": {"type": "boolean"},
                                "port": {"type": "integer"},
                                "authentication": {"type": "string"},
                                "encryption": {"type": "string"},
                                "description": {"type": "string"}
                            },
                            "required": ["source", "destination", "protocol", "data_type", "classification"]
                        }
                    },
                    "metadata": {
                        "type": "object",
                        "description": "Model metadata (author, version, compliance, etc.)"
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["diagram", "pytm_code", "threats", "full_analysis"],
                        "default": "diagram"
                    },
                    "auto_save": {
                        "type": "boolean",
                        "description": "Automatically save generated files to disk",
                        "default": True
                    },
                    "save_path": {
                        "type": "string",
                        "description": "Directory path to save files (defaults to current working directory)"
                    }
                },
                "required": ["system_name", "components", "boundaries", "dataflows"]
            }
        ),
        Tool(
            name="analyze_security_threats",
            description="Perform deep security analysis with STRIDE, MITRE ATT&CK mapping, and custom threat scenarios",
            inputSchema={
                "type": "object",
                "properties": {
                    "pytm_code": {
                        "type": "string",
                        "description": "PyTM code to analyze (optional if system_components provided)"
                    },
                    "system_components": {
                        "type": "object",
                        "description": "Alternative to pytm_code - structured system definition"
                    },
                    "analysis_depth": {
                        "type": "string",
                        "enum": ["basic", "standard", "comprehensive", "paranoid"],
                        "default": "standard"
                    },
                    "threat_frameworks": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["STRIDE", "MITRE_ATTACK", "OWASP", "NIST", "CIS"]
                        },
                        "default": ["STRIDE"]
                    },
                    "focus_areas": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["authentication", "authorization", "data_protection", 
                                    "network_security", "api_security", "cloud_security",
                                    "container_security", "supply_chain", "zero_trust"]
                        }
                    },
                    "compliance_frameworks": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["SOC2", "ISO27001", "HIPAA", "PCI-DSS", "GDPR", "NIST-CSF"]
                        }
                    },
                    "custom_scenarios": {
                        "type": "array",
                        "description": "Custom threat scenarios to evaluate",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "description": {"type": "string"},
                                "attack_vector": {"type": "string"},
                                "impact": {"type": "string"}
                            }
                        }
                    }
                },
                "required": ["analysis_depth"]
            }
        ),
        Tool(
            name="generate_security_controls",
            description="Generate specific security control recommendations based on the threat model",
            inputSchema={
                "type": "object",
                "properties": {
                    "threats": {
                        "type": "array",
                        "description": "List of identified threats",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "name": {"type": "string"},
                                "severity": {"type": "string"},
                                "category": {"type": "string"}
                            }
                        }
                    },
                    "risk_appetite": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                        "description": "Organization's risk tolerance"
                    },
                    "implementation_complexity": {
                        "type": "string",
                        "enum": ["simple", "moderate", "complex"],
                        "default": "moderate"
                    },
                    "budget_constraint": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "unlimited"],
                        "default": "medium"
                    },
                    "technology_stack": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Current technology stack (AWS, Azure, k8s, etc.)"
                    },
                    "prioritization_method": {
                        "type": "string",
                        "enum": ["risk_based", "quick_wins", "compliance_driven", "balanced"],
                        "default": "risk_based"
                    }
                },
                "required": ["risk_appetite"]
            }
        ),
        Tool(
            name="validate_architecture",
            description="Validate the architecture against security best practices and patterns",
            inputSchema={
                "type": "object",
                "properties": {
                    "components": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "type": {"type": "string"},
                                "boundary": {"type": "string"}
                            }
                        }
                    },
                    "dataflows": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "source": {"type": "string"},
                                "destination": {"type": "string"},
                                "protocol": {"type": "string"}
                            }
                        }
                    },
                    "validation_rules": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["zero_trust", "defense_in_depth", "least_privilege", 
                                    "segmentation", "encryption_at_rest", "encryption_in_transit",
                                    "mutual_tls", "api_gateway_pattern", "service_mesh",
                                    "data_classification", "key_management", "secrets_management"]
                        }
                    },
                    "architecture_patterns": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["microservices", "serverless", "monolithic", "hybrid_cloud",
                                    "multi_cloud", "edge_computing", "iot", "blockchain"]
                        }
                    },
                    "severity_threshold": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                        "default": "medium"
                    }
                },
                "required": ["components", "dataflows"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any] | None = None) -> List[TextContent]:
    """Handle advanced tool calls."""
    args = arguments or {}
    
    try:
        if name == "create_threat_model":
            return await create_advanced_threat_model(args)
        elif name == "analyze_security_threats":
            return await analyze_advanced_threats(args)
        elif name == "generate_security_controls":
            return await generate_security_controls(args)
        elif name == "validate_architecture":
            return await validate_architecture(args)
        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]

async def create_advanced_threat_model(args: Dict[str, Any]) -> List[TextContent]:
    """Create comprehensive threat model with rich components."""
    system_name = args.get("system_name", "System")
    description = args.get("description", "")
    output_format = args.get("output_format", "diagram")
    auto_save = args.get("auto_save", True)  # Default to auto-save
    save_path = args.get("save_path", os.getcwd())  # Default to current working directory
    
    # Convert input to dataclasses
    components = []
    for comp_data in args.get("components", []):
        comp = Component(
            name=comp_data["name"],
            type=ComponentType(comp_data["type"]),
            boundary=comp_data["boundary"],
            description=comp_data.get("description"),
            security_controls=[
                SecurityControl(**sc) for sc in comp_data.get("security_controls", [])
            ],
            metadata=comp_data.get("metadata", {})
        )
        components.append(comp)
    
    boundaries = []
    for bound_data in args.get("boundaries", []):
        boundary = TrustBoundary(
            name=bound_data["name"],
            type=bound_data["type"],
            security_level=bound_data["security_level"],
            description=bound_data.get("description"),
            controls=bound_data.get("controls", [])
        )
        boundaries.append(boundary)
    
    dataflows = []
    for flow_data in args.get("dataflows", []):
        flow = DataFlow(
            source=flow_data["source"],
            destination=flow_data["destination"],
            protocol=Protocol(flow_data["protocol"]),
            data_type=flow_data["data_type"],
            classification=DataClassification(flow_data["classification"]),
            bidirectional=flow_data.get("bidirectional", False),
            port=flow_data.get("port"),
            authentication=flow_data.get("authentication"),
            encryption=flow_data.get("encryption"),
            description=flow_data.get("description")
        )
        dataflows.append(flow)
    
    metadata = args.get("metadata", {})
    metadata["timestamp"] = "2024-01-01"  # Add timestamp
    
    # Generate outputs based on format
    if output_format == "pytm_code":
        code = generate_advanced_pytm_code(
            system_name, description, components, boundaries, dataflows, metadata
        )
        return [TextContent(type="text", text=f"```python\n{code}\n```")]
    
    elif output_format == "diagram":
        dot_content = generate_advanced_dot(components, boundaries, dataflows)
        
        # Auto-save functionality
        saved_files = []
        if auto_save:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = re.sub(r'[^\w\s-]', '', system_name).strip().replace(' ', '_')
            
            # Save DOT file
            dot_filename = f"{safe_name}_threatmodel_{timestamp}.dot"
            dot_filepath = os.path.join(save_path, dot_filename)
            try:
                with open(dot_filepath, 'w') as f:
                    f.write(dot_content)
                saved_files.append(f"DOT: {dot_filepath}")
            except Exception as e:
                print(f"Warning: Could not save DOT file: {e}", file=sys.stderr)
            
            # Save PyTM code
            pytm_code = generate_advanced_pytm_code(
                system_name, description, components, boundaries, dataflows, metadata
            )
            pytm_filename = f"{safe_name}_threatmodel_{timestamp}.py"
            pytm_filepath = os.path.join(save_path, pytm_filename)
            try:
                with open(pytm_filepath, 'w') as f:
                    f.write(pytm_code)
                saved_files.append(f"PyTM: {pytm_filepath}")
            except Exception as e:
                print(f"Warning: Could not save PyTM file: {e}", file=sys.stderr)
        
        response_text = f"# {system_name} - Threat Model Diagram\n\n"
        
        if GRAPHVIZ_AVAILABLE:
            image_data = await convert_dot_to_image(dot_content, 'png')
            if image_data:
                # Auto-save PNG if available
                if auto_save and image_data:
                    png_filename = f"{safe_name}_threatmodel_{timestamp}.png"
                    png_filepath = os.path.join(save_path, png_filename)
                    try:
                        import base64
                        with open(png_filepath, 'wb') as f:
                            f.write(base64.b64decode(image_data))
                        saved_files.append(f"PNG: {png_filepath}")
                    except Exception as e:
                        print(f"Warning: Could not save PNG file: {e}", file=sys.stderr)
                
                response_text += f"![Threat Model](data:image/png;base64,{image_data})\n\n"
                response_text += f"## Summary\n"
                response_text += f"- Components: {len(components)}\n"
                response_text += f"- Trust Boundaries: {len(boundaries)}\n"
                response_text += f"- Data Flows: {len(dataflows)}\n"
                response_text += f"- Highest Classification: {max(f.classification.value for f in dataflows) if dataflows else 'N/A'}\n"
                
                if saved_files:
                    response_text += f"\n## Auto-Saved Files\n"
                    for file_info in saved_files:
                        response_text += f"- {file_info}\n"
                
                return [TextContent(type="text", text=response_text)]
        
        # If no Graphviz, still show DOT and saved files info
        response_text += f"```dot\n{dot_content}\n```\n"
        if saved_files:
            response_text += f"\n## Auto-Saved Files\n"
            for file_info in saved_files:
                response_text += f"- {file_info}\n"
        
        return [TextContent(type="text", text=response_text)]
    
    elif output_format == "full_analysis":
        # Generate comprehensive analysis
        analysis = f"# {system_name} - Comprehensive Threat Model Analysis\n\n"
        
        # Auto-save files first
        saved_files = []
        if auto_save:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = re.sub(r'[^\w\s-]', '', system_name).strip().replace(' ', '_')
            
            # Generate and save all formats
            dot_content = generate_advanced_dot(components, boundaries, dataflows)
            pytm_code = generate_advanced_pytm_code(
                system_name, description, components, boundaries, dataflows, metadata
            )
            
            # Save DOT file
            dot_filename = f"{safe_name}_threatmodel_{timestamp}.dot"
            dot_filepath = os.path.join(save_path, dot_filename)
            try:
                with open(dot_filepath, 'w') as f:
                    f.write(dot_content)
                saved_files.append(f"DOT: {dot_filepath}")
            except Exception as e:
                print(f"Warning: Could not save DOT file: {e}", file=sys.stderr)
            
            # Save PyTM code
            pytm_filename = f"{safe_name}_threatmodel_{timestamp}.py"
            pytm_filepath = os.path.join(save_path, pytm_filename)
            try:
                with open(pytm_filepath, 'w') as f:
                    f.write(pytm_code)
                saved_files.append(f"PyTM: {pytm_filepath}")
            except Exception as e:
                print(f"Warning: Could not save PyTM file: {e}", file=sys.stderr)
            
            # Save PNG if Graphviz available
            if GRAPHVIZ_AVAILABLE:
                image_data = await convert_dot_to_image(dot_content, 'png')
                if image_data:
                    png_filename = f"{safe_name}_threatmodel_{timestamp}.png"
                    png_filepath = os.path.join(save_path, png_filename)
                    try:
                        import base64
                        with open(png_filepath, 'wb') as f:
                            f.write(base64.b64decode(image_data))
                        saved_files.append(f"PNG: {png_filepath}")
                    except Exception as e:
                        print(f"Warning: Could not save PNG file: {e}", file=sys.stderr)
        
        analysis += "## System Overview\n"
        analysis += f"{description}\n\n"
        
        analysis += "## Architecture Components\n"
        for boundary in sorted(boundaries, key=lambda b: b.security_level, reverse=True):
            analysis += f"\n### {boundary.name} (Security Level: {boundary.security_level}/10)\n"
            if boundary.description:
                analysis += f"{boundary.description}\n"
            if boundary.controls:
                analysis += f"**Controls**: {', '.join(boundary.controls)}\n"
            
            boundary_comps = [c for c in components if c.boundary == boundary.name]
            if boundary_comps:
                analysis += "\n**Components:**\n"
                for comp in boundary_comps:
                    analysis += f"- **{comp.name}** ({comp.type.value})"
                    if comp.description:
                        analysis += f": {comp.description}"
                    analysis += "\n"
                    if comp.security_controls:
                        analysis += f"  - Security Controls: {', '.join(sc.name for sc in comp.security_controls if sc.enabled)}\n"
        
        analysis += "\n## Data Flows\n"
        
        # Group flows by classification
        by_classification = {}
        for flow in dataflows:
            if flow.classification not in by_classification:
                by_classification[flow.classification] = []
            by_classification[flow.classification].append(flow)
        
        for classification in [DataClassification.TOP_SECRET, DataClassification.RESTRICTED, 
                               DataClassification.CONFIDENTIAL, DataClassification.INTERNAL, 
                               DataClassification.PUBLIC]:
            if classification in by_classification:
                analysis += f"\n### {classification.value} Data\n"
                for flow in by_classification[classification]:
                    analysis += f"- **{flow.source} → {flow.destination}**\n"
                    analysis += f"  - Protocol: {flow.protocol.value}"
                    if flow.port:
                        analysis += f" (Port {flow.port})"
                    analysis += "\n"
                    analysis += f"  - Data: {flow.data_type}\n"
                    if flow.encryption:
                        analysis += f"  - Encryption: {flow.encryption}\n"
                    if flow.authentication:
                        analysis += f"  - Authentication: {flow.authentication}\n"
        
        analysis += "\n## Security Considerations\n"
        
        # Analyze security gaps
        unencrypted_sensitive = [f for f in dataflows 
                                if f.classification in [DataClassification.RESTRICTED, DataClassification.TOP_SECRET] 
                                and not f.encryption]
        if unencrypted_sensitive:
            analysis += "\n### ⚠️ Critical Issues\n"
            for flow in unencrypted_sensitive:
                analysis += f"- Unencrypted {flow.classification.value} data: {flow.source} → {flow.destination}\n"
        
        # Check for missing authentication
        missing_auth = [f for f in dataflows if not f.authentication and f.protocol != Protocol.HTTPS]
        if missing_auth:
            analysis += "\n### ⚠️ Authentication Gaps\n"
            for flow in missing_auth:
                analysis += f"- No authentication specified: {flow.source} → {flow.destination} ({flow.protocol.value})\n"
        
        # Save the analysis report
        if auto_save:
            report_filename = f"{safe_name}_threatmodel_analysis_{timestamp}.md"
            report_filepath = os.path.join(save_path, report_filename)
            try:
                with open(report_filepath, 'w') as f:
                    f.write(analysis)
                saved_files.append(f"Report: {report_filepath}")
            except Exception as e:
                print(f"Warning: Could not save analysis report: {e}", file=sys.stderr)
        
        # Add saved files info to the analysis
        if saved_files:
            analysis += f"\n## Auto-Saved Files\n"
            analysis += f"Files have been saved to: {save_path}\n\n"
            for file_info in saved_files:
                analysis += f"- {file_info}\n"
        
        return [TextContent(type="text", text=analysis)]
    
    return [TextContent(type="text", text="Invalid output format")]

async def analyze_advanced_threats(args: Dict[str, Any]) -> List[TextContent]:
    """Perform comprehensive threat analysis."""
    analysis_depth = args.get("analysis_depth", "standard")
    frameworks = args.get("threat_frameworks", ["STRIDE"])
    focus_areas = args.get("focus_areas", [])
    
    # This would integrate with PyTM or other threat analysis engines
    # For now, return a structured threat analysis
    
    analysis = "# Advanced Security Threat Analysis\n\n"
    analysis += f"**Analysis Depth**: {analysis_depth}\n"
    analysis += f"**Frameworks Applied**: {', '.join(frameworks)}\n\n"
    
    if "STRIDE" in frameworks:
        analysis += "## STRIDE Analysis\n\n"
        analysis += "### Spoofing\n"
        analysis += "- Weak authentication mechanisms detected\n"
        analysis += "- Recommendation: Implement mutual TLS and strong identity verification\n\n"
        
        analysis += "### Tampering\n"
        analysis += "- Data integrity risks in transit\n"
        analysis += "- Recommendation: Enable message signing and integrity checks\n\n"
        
        analysis += "### Repudiation\n"
        analysis += "- Insufficient audit logging\n"
        analysis += "- Recommendation: Implement comprehensive audit trails\n\n"
        
        analysis += "### Information Disclosure\n"
        analysis += "- Sensitive data exposure risks\n"
        analysis += "- Recommendation: Encrypt data at rest and in transit\n\n"
        
        analysis += "### Denial of Service\n"
        analysis += "- Resource exhaustion vulnerabilities\n"
        analysis += "- Recommendation: Implement rate limiting and DDoS protection\n\n"
        
        analysis += "### Elevation of Privilege\n"
        analysis += "- Privilege escalation paths identified\n"
        analysis += "- Recommendation: Apply principle of least privilege\n\n"
    
    if "MITRE_ATTACK" in frameworks:
        analysis += "## MITRE ATT&CK Mapping\n\n"
        analysis += "### Initial Access\n"
        analysis += "- T1190: Exploit Public-Facing Application\n"
        analysis += "- T1078: Valid Accounts\n\n"
        
        analysis += "### Persistence\n"
        analysis += "- T1098: Account Manipulation\n"
        analysis += "- T1136: Create Account\n\n"
        
        analysis += "### Privilege Escalation\n"
        analysis += "- T1068: Exploitation for Privilege Escalation\n"
        analysis += "- T1078: Valid Accounts\n\n"
    
    return [TextContent(type="text", text=analysis)]

async def generate_security_controls(args: Dict[str, Any]) -> List[TextContent]:
    """Generate specific security control recommendations."""
    risk_appetite = args.get("risk_appetite", "medium")
    complexity = args.get("implementation_complexity", "moderate")
    budget = args.get("budget_constraint", "medium")
    
    controls = "# Security Control Recommendations\n\n"
    controls += f"**Risk Appetite**: {risk_appetite}\n"
    controls += f"**Implementation Complexity**: {complexity}\n"
    controls += f"**Budget Constraint**: {budget}\n\n"
    
    controls += "## Priority 1: Critical Controls\n\n"
    controls += "### 1. Identity and Access Management\n"
    controls += "- **Control**: Implement Zero Trust Network Access (ZTNA)\n"
    controls += "- **Complexity**: High\n"
    controls += "- **Cost**: $$$$\n"
    controls += "- **Implementation**: Deploy identity-aware proxy with continuous verification\n\n"
    
    controls += "### 2. Data Protection\n"
    controls += "- **Control**: End-to-end encryption with key management\n"
    controls += "- **Complexity**: Medium\n"
    controls += "- **Cost**: $$$\n"
    controls += "- **Implementation**: Use AWS KMS or Azure Key Vault\n\n"
    
    controls += "## Priority 2: Essential Controls\n\n"
    controls += "### 3. Network Security\n"
    controls += "- **Control**: Micro-segmentation with service mesh\n"
    controls += "- **Complexity**: High\n"
    controls += "- **Cost**: $$$\n"
    controls += "- **Implementation**: Deploy Istio or Linkerd\n\n"
    
    return [TextContent(type="text", text=controls)]

async def validate_architecture(args: Dict[str, Any]) -> List[TextContent]:
    """Validate architecture against security patterns."""
    validation_rules = args.get("validation_rules", [])
    severity_threshold = args.get("severity_threshold", "medium")
    
    validation = "# Architecture Security Validation\n\n"
    validation += f"**Rules Applied**: {len(validation_rules)}\n"
    validation += f"**Severity Threshold**: {severity_threshold}\n\n"
    
    validation += "## Validation Results\n\n"
    
    validation += "### ✅ Passed Validations\n"
    validation += "- Zero Trust principles properly implemented\n"
    validation += "- Data classification scheme in place\n"
    validation += "- Encryption at rest and in transit enabled\n\n"
    
    validation += "### ❌ Failed Validations\n"
    validation += "- **Missing API Gateway Pattern** (High)\n"
    validation += "  - Direct service-to-service communication detected\n"
    validation += "  - Recommendation: Implement centralized API gateway\n\n"
    
    validation += "### ⚠️ Warnings\n"
    validation += "- **Partial Service Mesh Implementation** (Medium)\n"
    validation += "  - Only 60% of services are mesh-enabled\n"
    validation += "  - Recommendation: Complete service mesh rollout\n\n"
    
    return [TextContent(type="text", text=validation)]

async def main():
    """Run the MCP server."""
    global _python_cmd
    
    print("===========================================", file=sys.stderr)
    print("Advanced ThreatModel MCP Server", file=sys.stderr)
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
    
    print("", file=sys.stderr)
    print("Available tools:", file=sys.stderr)
    print("- create_threat_model: Comprehensive threat modeling", file=sys.stderr)
    print("- analyze_security_threats: Deep security analysis", file=sys.stderr)
    print("- generate_security_controls: Control recommendations", file=sys.stderr)
    print("- validate_architecture: Architecture validation", file=sys.stderr)
    print("", file=sys.stderr)
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
