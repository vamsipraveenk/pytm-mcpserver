import os
import re
import platform
import glob
import shutil
import subprocess
from typing import Dict, List, Tuple

# Component patterns for automatic detection
PATTERNS = {
    'web|frontend|ui|portal|dashboard': ('Web Frontend', 'server', 'Internet'),
    'api|backend|rest|graphql|service': ('API Server', 'server', 'DMZ'),
    'database|postgres|mysql|sql|db': ('Database', 'datastore', 'Internal'),
    'redis|cache|memcache': ('Cache', 'datastore', 'Internal'),
    'storage|s3|blob|file': ('File Storage', 'datastore', 'Internal'),
    'user|customer|client': ('User', 'actor', 'Internet'),
    'admin|administrator': ('Admin', 'actor', 'Internet'),
    'payment|stripe|paypal': ('Payment Gateway', 'external', 'Internet'),
    'email|smtp|mail': ('Email Service', 'external', 'Internet'),
    'auth|oauth|sso|identity': ('Auth Provider', 'external', 'Internet'),
    'mobile|ios|android|app': ('Mobile App', 'actor', 'Internet'),
    'microservice': ('Microservice', 'process', 'Internal'),
    'queue|kafka|rabbitmq': ('Message Queue', 'datastore', 'Internal'),
    'cdn|cloudfront': ('CDN', 'external', 'Internet'),
}

def has_graphviz() -> bool:
    """Check if Graphviz dot command is available."""
    return shutil.which('dot') is not None

def find_python() -> str:
    """Find Python executable on the system."""
    for cmd in ['python', 'py', 'python3', 'python.exe']:
        try:
            result = subprocess.run([cmd, '--version'], capture_output=True, timeout=2)
            if result.returncode == 0:
                return cmd
        except:
            continue
    
    if platform.system() == 'Windows':
        paths = [
            r'C:\Python*\python.exe',
            r'C:\Program Files\Python*\python.exe',
            os.path.expanduser(r'~\AppData\Local\Programs\Python\Python*\python.exe'),
            r'C:\Windows\py.exe',
        ]
        for pattern in paths:
            matches = glob.glob(pattern)
            if matches:
                return matches[0]
    
    return None

def extract_components(description: str) -> Tuple[List[Dict], List[str]]:
    """Extract components from natural language description."""
    desc_lower = description.lower()
    components = []
    boundaries = set(['Internet'])
    found = set()
    
    for pattern, (name, comp_type, boundary) in PATTERNS.items():
        if re.search(pattern, desc_lower) and name not in found:
            components.append({
                'name': name,
                'type': comp_type,
                'boundary': boundary
            })
            boundaries.add(boundary)
            found.add(name)
    
    # Add defaults if missing
    if not any(c['type'] == 'actor' for c in components):
        components.append({'name': 'User', 'type': 'actor', 'boundary': 'Internet'})
    if not any(c['type'] == 'server' for c in components):
        components.append({'name': 'Application', 'type': 'server', 'boundary': 'DMZ'})
        boundaries.add('DMZ')
    
    return components, list(boundaries)

def generate_simple_dot(components: List[Dict], boundaries: List[str]) -> str:
    """Generate a professional DOT diagram."""
    dot = 'digraph ThreatModel {\n'
    dot += '  rankdir=TB;\n'  # Top to Bottom for better width
    dot += '  graph [fontname="Arial", fontsize=14, bgcolor="#ffffff", pad="0.5", nodesep="1.5", ranksep="2", compound=true];\n'
    dot += '  node [fontname="Arial", fontsize=11, style="filled,rounded", margin="0.3,0.15"];\n'
    dot += '  edge [fontname="Arial", fontsize=9, fontcolor="#333333", labeldistance=3];\n\n'
    
    # Color schemes
    colors = {
        'Internet': '#e3f2fd',
        'DMZ': '#fff9c4',
        'Internal': '#f1f8e9',
        'Cloud': '#f3e5f5'
    }
    
    # Order boundaries for better layout
    boundary_order = ['Internet', 'DMZ', 'Internal']
    ordered_boundaries = [b for b in boundary_order if b in boundaries] + [b for b in boundaries if b not in boundary_order]
    
    # Add subgraphs for boundaries with better layout
    for i, boundary in enumerate(ordered_boundaries):
        color = colors.get(boundary, '#f5f5f5')
        dot += f'  subgraph cluster_{i} {{\n'
        dot += f'    label="{boundary}";\n'
        dot += f'    style="rounded,filled";\n'
        dot += f'    fillcolor="{color}";\n'
        dot += f'    color="#999999";\n'
        dot += f'    fontsize=16;\n'
        dot += f'    labelloc=t;\n'
        dot += f'    margin=15;\n\n'
        
        # Arrange components in a grid-like pattern within each boundary
        boundary_components = [c for c in components if c['boundary'] == boundary]
        
        # Create invisible nodes to help with layout
        if len(boundary_components) > 2:
            dot += f'    // Layout helpers for {boundary}\n'
            dot += f'    {{rank=same; '
            for j, comp in enumerate(boundary_components[:len(boundary_components)//2]):
                var = re.sub(r'[^\w]', '_', comp['name'].lower())
                if j > 0:
                    dot += '; '
                dot += var
            dot += '}\n'
        
        # Add components in this boundary
        for comp in components:
            if comp['boundary'] == boundary:
                var = re.sub(r'[^\w]', '_', comp['name'].lower())
                
                # Style based on component type
                if comp['type'] == 'actor':
                    shape = 'ellipse'
                    color = '#2196f3'
                    fontcolor = 'white'
                elif comp['type'] == 'server':
                    shape = 'box'
                    color = '#4caf50'
                    fontcolor = 'white'
                elif comp['type'] == 'datastore':
                    shape = 'cylinder'
                    color = '#ff9800'
                    fontcolor = 'white'
                elif comp['type'] == 'external':
                    shape = 'house'
                    color = '#f44336'
                    fontcolor = 'white'
                elif comp['type'] == 'process':
                    shape = 'component'
                    color = '#9c27b0'
                    fontcolor = 'white'
                else:
                    shape = 'box'
                    color = '#607d8b'
                    fontcolor = 'white'
                
                dot += f'    {var} [label="{comp["name"]}", shape={shape}, fillcolor="{color}", fontcolor="{fontcolor}", width=2.5, fixedsize=true];\n'
        
        dot += '  }\n\n'
    
    # Add some structure to prevent overlap
    dot += '\n'
    
    # Add data flows with better spacing
    actors = [c for c in components if c['type'] == 'actor']
    servers = [c for c in components if c['type'] in ['server', 'process']]
    stores = [c for c in components if c['type'] == 'datastore']
    externals = [c for c in components if c['type'] == 'external']
    
    # Use constraint=false for some edges to allow better layout
    dot += '  // Data flows\n'
    
    # Actor -> Server flows (primary flows)
    for i, actor in enumerate(actors):
        for j, server in enumerate(servers):
            a_var = re.sub(r'[^\w]', '_', actor['name'].lower())
            s_var = re.sub(r'[^\w]', '_', server['name'].lower())
            # Only show primary flows to reduce clutter
            if i == 0 or j == 0:  # First actor to all servers, or all actors to first server
                dot += f'  {a_var} -> {s_var} [label="HTTPS", color="#1976d2", penwidth=2, fontsize=9];\n'
                if i == 0 and j == 0:  # Only one response flow
                    dot += f'  {s_var} -> {a_var} [label="Response", color="#388e3c", style=dashed, constraint=false, fontsize=9];\n'
    
    # Server -> Datastore flows
    for i, server in enumerate(servers[:1]):  # Only from first server to reduce clutter
        for store in stores:
            s_var = re.sub(r'[^\w]', '_', server['name'].lower())
            d_var = re.sub(r'[^\w]', '_', store['name'].lower())
            dot += f'  {s_var} -> {d_var} [label="Query", color="#f57c00", penwidth=2, fontsize=9];\n'
    
    # Server -> External flows
    for server in servers[:1]:  # Only from first server
        for external in externals:
            s_var = re.sub(r'[^\w]', '_', server['name'].lower())
            e_var = re.sub(r'[^\w]', '_', external['name'].lower())
            dot += f'  {s_var} -> {e_var} [label="API", color="#d32f2f", penwidth=2, fontsize=9];\n'
    
    dot += '}\n'
    return dot
