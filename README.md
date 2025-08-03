# <i><b>`ThreatModel-MCP`</b></i>

A modular Model Context Protocol server that transforms natural language into threat models - no API keys required.<br>

---

<samp>

## <b>Features</b>

- <b>`Natural Language`</b>: Describe your system in plain English<br>
  Automatic component detection from descriptions<br>
  No need to learn threat modeling syntax
- <b>`Threat Analysis`</b>: STRIDE-based security analysis<br>
  Severity-filtered threat identification<br>
  Actionable security recommendations
- <b>`Visual Diagrams`</b>: Data flow diagrams in DOT/PNG/SVG<br>
  Professional styling with trust boundaries<br>
  Export or view inline
- <b>`PyTM Integration`</b>: Generate executable PyTM code<br>
  Full compatibility with PyTM library<br>
  Customize and extend generated models

---

## <b>Setup</b>

### Prerequisites
- <code>Python 3.8+</code>
- <code>Graphviz</code> (optional, for PNG/SVG output)

### Installation

1. Clone and navigate:<br>
   <code>cd mcp-threatmodel</code>

2. Install dependencies:<br>
   <code>pip install -r requirements.txt</code>

3. Install Graphviz (optional):<br>
   - <b>Windows</b>: Download from https://graphviz.org/download/<br>
   - <b>Mac</b>: <code>brew install graphviz</code><br>
   - <b>Linux</b>: <code>sudo apt-get install graphviz</code>

4. Add to mcp config:<br>
   ```json
   {
     "mcpServers": {
       "threatmodel": {
         "command": "python",
         "args": ["/full/path/to/threatmodel_server.py"]
       }
     }
   }
   ```

---

## <b>Usage</b>

### Available Tools

The server provides these MCP tools:<br>
- <b><code>analyze_system</code></b> - Extract components and boundaries
- <b><code>get_threats</code></b> - List security threats with filtering
- <b><code>generate_diagram</code></b> - Create diagrams in various formats
- <b><code>visualize_diagram</code></b> - Show PNG diagram inline
- <b><code>save_diagram</code></b> - Save diagrams to disk
- <b><code>get_pytm_code</code></b> - Export PyTM Python code
- <b><code>quick_analysis</code></b> - Get security overview

### Examples

<b>System Analysis</b><br>
```
analyze_system("e-commerce platform with payment gateway")
```

<b>Threat Identification</b><br>
```
get_threats("banking mobile app", severity_filter="high")
```

<b>Diagram Generation</b><br>
```
generate_diagram("microservices with kafka", format="png")
```

<b>Save to File</b><br>
```
save_diagram("web app with database", filepath="architecture.png")
```

---

## <b>Architecture</b>

The server is organized into three modules:<br>
- <b><code>threatmodel_server.py</code></b> - Main MCP server and tool handlers
- <b><code>core_utils.py</code></b> - Component extraction and DOT generation
- <b><code>pytm_generator.py</code></b> - PyTM code generation and execution

---

## <b>Component Recognition</b>

Automatically identifies:<br>
- <b>Actors</b>: user, customer, admin, mobile
- <b>Servers</b>: web, api, backend, service
- <b>Datastores</b>: database, redis, cache, storage
- <b>External</b>: payment, email, auth, cdn
- <b>Infrastructure</b>: queue, kafka, microservice

Trust boundaries are automatically assigned:<br>
- <b>Internet</b> - External-facing components
- <b>DMZ</b> - API and web servers
- <b>Internal</b> - Databases and services

---

## <b>Testing</b>

Verify installation:<br>
<code>python threatmodel_server.py --test</code>

This runs basic component extraction and diagram generation tests.

---

## <b>Troubleshooting</b>

If diagrams don't generate:<br>
- Ensure Graphviz is installed and in PATH
- Try <code>dot -V</code> to verify installation
- Use <code>format="dot"</code> for text-based output
- Check PyTM is installed: <code>pip show pytm</code>

---
</samp>
