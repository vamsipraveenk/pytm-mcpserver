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
    dot += '  rankdir=LR;\n'
    dot += '  graph [fontname="Arial", fontsize=12, bgcolor="#f5f5f5"];\n'
    dot += '  node [fontname="Arial", fontsize=10, style=filled];\n'
    dot += '  edge [fontname="Arial", fontsize=9];\n\n'
    
    # Color schemes
    colors = {
        'Internet': '#ffebee',
        'DMZ': '#fff3e0',
        'Internal': '#e8f5e9',
        'Cloud': '#e3f2fd'
    }
    
    # Add subgraphs for boundaries
    for i, boundary in enumerate(boundaries):
        color = colors.get(boundary, '#f5f5f5')
        dot += f'  subgraph cluster_{i} {{\n'
        dot += f'    label="{boundary}";\n'
        dot += f'    style="rounded,filled";\n'
        dot += f'    fillcolor="{color}";\n'
        dot += f'    fontsize=12;\n'
        dot += f'    fontweight=bold;\n\n'
        
        # Add components in this boundary
        for comp in components:
            if comp['boundary'] == boundary:
                var = comp['name'].lower().replace(' ', '_')
                
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
                    shape = 'diamond'
                    color = '#f44336'
                    fontcolor = 'white'
                else:
                    shape = 'box'
                    color = '#9e9e9e'
                    fontcolor = 'white'
                
                dot += f'    {var} [label="{comp["name"]}", shape={shape}, fillcolor="{color}", fontcolor="{fontcolor}"];\n'
        
        dot += '  }\n\n'
    
    # Add data flows
    actors = [c for c in components if c['type'] == 'actor']
    servers = [c for c in components if c['type'] in ['server', 'process']]
    stores = [c for c in components if c['type'] == 'datastore']
    externals = [c for c in components if c['type'] == 'external']
    
    # Actor -> Server flows
    for actor in actors:
        for server in servers:
            a_var = actor['name'].lower().replace(' ', '_')
            s_var = server['name'].lower().replace(' ', '_')
            dot += f'  {a_var} -> {s_var} [label="HTTPS Request", color="#2196f3"];\n'
            dot += f'  {s_var} -> {a_var} [label="Response", color="#4caf50", style=dashed];\n'
    
    # Server -> Datastore flows
    for server in servers:
        for store in stores:
            s_var = server['name'].lower().replace(' ', '_')
            d_var = store['name'].lower().replace(' ', '_')
            dot += f'  {s_var} -> {d_var} [label="Query", color="#ff9800"];\n'
    
    # Server -> External flows
    for server in servers:
        for external in externals:
            s_var = server['name'].lower().replace(' ', '_')
            e_var = external['name'].lower().replace(' ', '_')
            dot += f'  {s_var} -> {e_var} [label="API Call", color="#f44336"];\n'
    
    dot += '}\n'
    return dot
