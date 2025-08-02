# MCP Server with PyTM Data Flow Diagram Generation


This Model Context Protocol (MCP) server provides tools for generating data flow diagrams and threat models using the OWASP PyTM framework, along with a simple "hello world" tool.


## Features


- **Hello World Tool**: Simple greeting functionality
- **PyTM Data Flow Diagrams**: Generate threat models and security analysis diagrams


## 🚀 Getting Started


### Prerequisites


- **Python 3.8+** (Python 3.9+ recommended)
- **Git** for cloning the repository
- **Graphviz** (optional, for converting DOT files to PNG/SVG)


### Step 1: Clone the Repository


```bash
git clone https://github.com/yourusername/py-tm-mcpserver.git
cd py-tm-mcpserver
```


### Step 2: Set Up Python Environment (Recommended)


Create a virtual environment to isolate dependencies:


```bash
# Create virtual environment
python -m venv venv


# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```


### Step 3: Install Dependencies


```bash
pip install -r requirements.txt
```


This will install:


- `mcp>=1.0.0` - Model Context Protocol framework
- `pytm>=1.0.0` - OWASP PyTM threat modeling framework


### Step 4: Start the Server


**Option A: Using Python directly**


```bash
python server.py
```

### Step 5: Verify Installation


Test that the server is working correctly:


```bash
# Run basic functionality test
python test_client.py
```


You should see output showing successful diagram generation and file creation.


### Step 6: Install Graphviz (Optional)


To convert generated DOT files to visual PNG/SVG images:


**Windows:**


```bash
# Using Chocolatey
choco install graphviz


# Or download from: https://graphviz.org/download/
```


**macOS:**


```bash
brew install graphviz
```


**Ubuntu/Debian:**


```bash
sudo apt-get install graphviz
```


**Converting diagrams:**


```bash
# Convert DOT file to PNG
dot -Tpng your_diagram.dot -o your_diagram.png


# Convert DOT file to SVG
dot -Tsvg your_diagram.dot -o your_diagram.svg
```


## 🔧 Quick Test


Once the server is running, you can test it with this simple example:


```python
# The server will generate DOT files for diagrams like this:
# System: "WebApp" with User -> WebServer -> Database flows
# Output: WebApp_dfd.dot file ready for visualization
```


### Quick MCP Client Setup


To use with any MCP-compatible client, add this to your MCP configuration file:


```json
{
  "servers": {
    "pytm-mcpserver": {
      "command": "python",
      "args": ["path/to/your/py-tm-mcpserver/server.py"],
      "cwd": "path/to/your/py-tm-mcpserver"
    }
  }
}
```

## 🛠️ Usage


### Available Tools


### hello_world


Returns a simple greeting message.


**Parameters:**


- `name` (optional): Name to include in the greeting. Defaults to "World" if not provided.


**Example usage:**


- `hello_world()` → Returns "Hello World!"
- `hello_world({"name": "Alice"})` → Returns "Hello Alice!"


### generate_data_flow_diagram


Generates data flow diagrams using the OWASP PyTM threat modeling framework.


**Parameters:**


- `system_name` (required): Name of the system being modeled
- `description` (optional): Description of the system
- `components` (required): Array of system components (actor, server, datastore, boundary)
- `dataflows` (optional): Array of data flows between components
- `output_format` (optional): Output format - "dfd", "seq", or "stride" (default: "dfd")


## Testing


Test the PyTM tool functionality:


```bash
python test_pytm_tool.py
```


### Verification


After configuring your MCP client:


1. **Restart your MCP client** application
2. **Check if the tools are available:**
   - `hello_world` - Simple greeting tool
   - `generate_data_flow_diagram` - PyTM diagram generation
3. **Test with a simple command:**
   - Try: "Hello world" to test the basic tool
   - Try: "Generate a data flow diagram for a simple web app" to test PyTM functionality

### Getting Help

- Review example usage in `test_pytm_tool.py` and `test_advanced_examples.py`
- For PyTM-specific issues, see the [PyTM documentation](https://github.com/OWASP/pytm)


## 🤝 Contributing


1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request


## 📄 License

This project is open source.

## 🙏 Acknowledgments


- [OWASP PyTM](https://github.com/OWASP/pytm) - Threat modeling framework
- [Model Context Protocol](https://github.com/modelcontextprotocol) - MCP framework