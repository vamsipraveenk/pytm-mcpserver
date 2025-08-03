
import asyncio
import os
import re
import tempfile
import shutil
import time
import base64
from typing import Any, Dict, List, Optional
from pathlib import Path

def generate_pytm_code(description: str, components: List[Dict], boundaries: List[str]) -> str:
    """Generate PyTM code from components and boundaries."""
    code = f'''#!/usr/bin/env python3
from pytm import TM, Actor, Server, Datastore, Process, Dataflow, Boundary, ExternalEntity

tm = TM("Threat Model")
tm.description = """{description}"""
tm.isOrdered = False
tm.mergeResponses = False

# Boundaries
'''
    
    for boundary in boundaries:
        var = re.sub(r'[^\w]', '_', boundary.lower())
        code += f'{var} = Boundary("{boundary}")\n'
    
    code += '\n# Components\n'
    comp_vars = {}
    
    for comp in components:
        var = re.sub(r'[^\w]', '_', comp['name'].lower())
        comp_vars[comp['name']] = var
        boundary_var = re.sub(r'[^\w]', '_', comp['boundary'].lower())
        
        if comp['type'] == 'actor':
            code += f'{var} = Actor("{comp["name"]}")\n'
        elif comp['type'] == 'server':
            code += f'{var} = Server("{comp["name"]}")\n'
        elif comp['type'] == 'datastore':
            code += f'{var} = Datastore("{comp["name"]}")\n'
        elif comp['type'] == 'process':
            code += f'{var} = Process("{comp["name"]}")\n'
        elif comp['type'] == 'external':
            code += f'{var} = ExternalEntity("{comp["name"]}")\n'
        
        code += f'{var}.inBoundary = {boundary_var}\n\n'
    
    code += '# Data flows\n'
    actors = [c for c in components if c['type'] == 'actor']
    servers = [c for c in components if c['type'] in ['server', 'process']]
    stores = [c for c in components if c['type'] == 'datastore']
    
    for i, actor in enumerate(actors[:2]):
        for j, server in enumerate(servers[:2]):
            a_var = comp_vars[actor['name']]
            s_var = comp_vars[server['name']]
            code += f'Dataflow({a_var}, {s_var}, "Request")\n'
            if i == 0 and j == 0:
                code += f'Dataflow({s_var}, {a_var}, "Response")\n'
    
    for server in servers[:1]:
        for store in stores[:2]:
            s_var = comp_vars[server['name']]
            d_var = comp_vars[store['name']]
            code += f'Dataflow({s_var}, {d_var}, "Query")\n'
    
    code += '\nif __name__ == "__main__":\n    tm.process()\n'
    return code

async def execute_pytm_fast(code: str, args: List[str], python_cmd: str) -> Dict[str, Any]:
    """Execute PyTM with better Windows file handling."""
    if not python_cmd:
        return {"error": "Python not found. Please install Python and add it to PATH."}
    
    # Use a unique temporary directory for this execution
    temp_dir = tempfile.mkdtemp()
    temp_file = os.path.join(temp_dir, "model.py")
    
    # Add DOT layout improvements for PyTM
    enhanced_args = args.copy()
    if '--dfd' in args:
        # PyTM doesn't directly support these, but we'll process the output
        pass
    
    try:
        # Write the file
        with open(temp_file, 'w') as f:
            f.write(code)
        
        # Execute PyTM
        process = await asyncio.create_subprocess_exec(
            python_cmd, temp_file, *enhanced_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=temp_dir
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=10.0
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return {"error": "PyTM execution timed out. Try a simpler model."}
        
        if process.returncode == 0:
            output = stdout.decode('utf-8', errors='ignore')
            
            # If it's DOT output, enhance it with better layout directives
            if '--dfd' in args and 'digraph' in output:
                # Add layout improvements to PyTM's DOT output
                output = output.replace('digraph {', 'digraph ThreatModel {')
                if 'rankdir=' not in output:
                    output = output.replace('digraph ThreatModel {', 
                        'digraph ThreatModel {\n  rankdir=TB;\n  nodesep=1.5;\n  ranksep=2;')
            
            return {"success": True, "output": output}
        else:
            return {"error": stderr.decode('utf-8', errors='ignore')}
            
    finally:
        # Clean up with retry for Windows
        for attempt in range(3):
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir)
                break
            except Exception:
                if attempt < 2:
                    time.sleep(0.1)
                else:
                    pass  # Ignore cleanup errors

async def convert_dot_to_image(dot_content: str, format: str = 'png') -> Optional[str]:
    """Convert DOT to image format, return base64 encoded result."""
    # Use unique temporary files
    temp_dir = tempfile.mkdtemp()
    dot_file = os.path.join(temp_dir, "graph.dot")
    output_file = os.path.join(temp_dir, f"graph.{format}")
    
    try:
        # Write DOT content
        with open(dot_file, 'w') as f:
            f.write(dot_content)
        
        # Convert using Graphviz
        cmd = ['dot', f'-T{format}', dot_file, '-o', output_file]
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        await process.communicate()
        
        if process.returncode == 0 and os.path.exists(output_file):
            # Read and encode the image
            with open(output_file, 'rb') as f:
                image_data = f.read()
            
            if format == 'png':
                return base64.b64encode(image_data).decode('utf-8')
            else:
                return image_data.decode('utf-8')
        
        return None
        
    finally:
        # Clean up with retry
        for attempt in range(3):
            try:
                shutil.rmtree(temp_dir)
                break
            except Exception:
                if attempt < 2:
                    time.sleep(0.1)

async def save_diagram_to_file(dot_content: str, filepath: str, format: str = 'png', 
                              base_path: Optional[str] = None, graphviz_available: bool = False) -> Dict[str, str]:
    """Save diagram to file."""
    try:
        # Handle relative paths
        if not os.path.isabs(filepath):
            if base_path:
                # Use provided base path
                filepath = os.path.abspath(os.path.join(base_path, filepath))
            else:
                # Default to user's home directory or current directory
                default_dir = os.path.expanduser("~/threatmodel_diagrams")
                filepath = os.path.abspath(os.path.join(default_dir, filepath))
        
        # Ensure directory exists
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        
        if format == 'dot':
            # Save DOT directly
            with open(filepath, 'w') as f:
                f.write(dot_content)
            return {"success": True, "message": f"DOT file saved to {os.path.abspath(filepath)}"}
        
        elif format in ['png', 'svg'] and graphviz_available:
            # Convert and save
            image_data = await convert_dot_to_image(dot_content, format)
            if image_data:
                if format == 'png':
                    with open(filepath, 'wb') as f:
                        f.write(base64.b64decode(image_data))
                else:
                    with open(filepath, 'w') as f:
                        f.write(image_data)
                return {"success": True, "message": f"{format.upper()} file saved to {os.path.abspath(filepath)}"}
            else:
                return {"error": "Failed to convert diagram"}
        
        else:
            return {"error": f"Format '{format}' not supported or Graphviz not available"}
            
    except Exception as e:
        return {"error": f"Failed to save file: {str(e)}"}
