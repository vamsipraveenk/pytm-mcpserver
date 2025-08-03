
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
    """Generate a minimal DOT diagram like PyTM."""
    dot = 'digraph {\n'
    
    # Add subgraphs for boundaries - minimal style
    for i, boundary in enumerate(boundaries):
        dot += f'  subgraph cluster_{i} {{\n'
        dot += f'    label="{boundary}";\n'
        
        # Add components in this boundary
        boundary_components = [c for c in components if c['boundary'] == boundary]
        for comp in boundary_components:
            var = re.sub(r'[^\w]', '_', comp['name'].lower())
            
            # Simple shape mapping
            if comp['type'] == 'actor':
                shape = 'box'
                style = ', style=rounded'
            elif comp['type'] == 'datastore':
                shape = 'cylinder'
                style = ''
            elif comp['type'] == 'external':
                shape = 'box'
                style = ', style=dashed'
            else:
                shape = 'box'
                style = ''
            
            dot += f'    {var} [label="{comp["name"]}", shape={shape}{style}];\n'
        
        dot += '  }\n\n'
    
    # Add data flows - simple style
    actors = [c for c in components if c['type'] == 'actor']
    servers = [c for c in components if c['type'] in ['server', 'process']]
    stores = [c for c in components if c['type'] == 'datastore']
    externals = [c for c in components if c['type'] == 'external']
    
    dot += '  // Data flows\n'
    
    # Actor -> Server flows
    for i, actor in enumerate(actors):
        for j, server in enumerate(servers):
            if i == 0 or j == 0:  # Reduce clutter
                a_var = re.sub(r'[^\w]', '_', actor['name'].lower())
                s_var = re.sub(r'[^\w]', '_', server['name'].lower())
                dot += f'  {a_var} -> {s_var} [label="Request"];\n'
                if i == 0 and j == 0:
                    dot += f'  {s_var} -> {a_var} [label="Response", style=dashed];\n'
    
    # Server -> Datastore flows
    for i, server in enumerate(servers[:1]):
        for store in stores:
            s_var = re.sub(r'[^\w]', '_', server['name'].lower())
            d_var = re.sub(r'[^\w]', '_', store['name'].lower())
            dot += f'  {s_var} -> {d_var} [label="Query"];\n'
    
    # Server -> External flows
    for server in servers[:1]:
        for external in externals:
            s_var = re.sub(r'[^\w]', '_', server['name'].lower())
            e_var = re.sub(r'[^\w]', '_', external['name'].lower())
            dot += f'  {s_var} -> {e_var} [label="API"];\n'
    
    dot += '}\n'
    return dot
