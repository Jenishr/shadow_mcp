# ShadowDiscovery: MCP Security Scanner

**ShadowDiscovery** is a specialized security diagnostic tool designed to uncover and analyze **Model Context Protocol (MCP)** servers running on a local machine. As AI agents increasingly use local servers to interact with your OS, "Shadow MCP" refers to unauthorized or unmonitored connectors that could expose sensitive data.

---

## 🚀 Features

* **Multi-Platform Detection**: Automatically identifies configuration paths for Windows, macOS, and Linux.
* **Active Process Scanning**: Uses `psutil` to hunt for running MCP instances by monitoring keywords like `npx`, `uvx`, and `modelcontextprotocol`.
* **Configuration Parsing**: Supports both list-based (`[[mcp_servers]]`) and dictionary-based (`[mcp_servers.name]`) TOML/JSON configurations.
* **LLM Security Auditing**: Integrates with **Ollama Cloud** (Llama 3.1) to perform automated risk assessments of exposed toolsets.
* **Interactive Dashboard**: A Flask-based web UI to manage configurations, trigger scans, and view real-time results.

---

## 🛠️ Requirements

To run this application, ensure you have Python 3.11+ installed to support `tomllib` natively.

```text
Flask==3.0.3
psutil==5.9.8
requests==2.31.0
pathlib==1.0.1

```

---

## 📂 Project Structure

* **`app.py`**: The primary Flask web server handling routing, configuration saving, and report exports.
* **`shadow_discovery.py`**: The core engine that performs filesystem searches and process inspection.
* **`mcp_connector.py`**: Utility for fetching tool definitions from HTTP-based MCP servers via JSON-RPC.
* **`ollama_analyzer.py`**: Interfaces with the Ollama Cloud API to analyze server metadata for security vulnerabilities.

---

## ⚙️ Setup & Usage

### 1. Configuration

The scanner relies on a `config.json` file to know where to look for MCP clients (like Claude Desktop). Example:

```json
{
  "platforms": {
    "darwin": {
      "clients": [
        {
          "name": "Claude Desktop",
          "config_paths": ["~/Library/Application Support/Claude/claude_desktop_config.json"]
        }
      ]
    }
  }
}

```

### 2. Installation

```bash
pip install -r requirements.txt

```

### 3. Execution

```bash
python app.py

```

Open your browser to `http://127.0.0.1:5000`.

---

## 🛡️ Security Analysis

To enable the "Senior Cybersecurity Analyst" AI mode:

1. Navigate to the **Advanced** section in the UI.
2. Enter your **Ollama Cloud API Key**.
3. The system will generate a JSON-formatted risk report including:
* **Risk Level**: Low, Medium, High, or Critical.
* **Abuse Scenarios**: How an attacker might exploit the tool.
* **Mitigations**: Recommended steps to secure the server.



---

## 📊 Exporting Findings

You can export the scan results as a `shadow_report.json` directly from the interface for archival or further manual review.
