# Wazuh IT Asset Management Ontology & Knowledge Graph Visualizer

A formal IT Asset Management Ontology, Data Collector, Model Context Protocol (MCP) Server, and Interactive Web Visualizer Dashboard for **Wazuh Security Platform** (`https://192.168.1.38:55000`).

---

## 🌟 Key Features

1. **Formal OWL/Turtle Ontology**: Defines classes (`Agent`, `ManagerAgent`, `EndpointAgent`, `OperatingSystem`, `IPAddress`, `HardwareSpec`, `Vulnerability`, `SoftwarePackage`, `NetworkPort`) and relationships (`hasOS`, `hasIP`, `hasHardware`, `hasVulnerability`, `installedPackage`, `managedBy`).
2. **Automated Wazuh API Collector**: Connects to Wazuh REST API (`192.168.1.38:55000`), authenticates with JWT tokens, and builds an IT Asset Knowledge Graph snapshot.
3. **MCP Tool Server for AI Chatbots**: Exposes standard MCP tools (`get_asset_summary`, `list_agents`, `get_agent_vulnerabilities`, `search_assets`, `refresh_wazuh_data`) so LLM chatbots can query connected assets.
4. **Interactive Glassmorphism Dashboard**: Visual network canvas built with Vis.js & Vanilla CSS, with real-time node filtering, CVE severity color highlights, node inspector drawer, and live API sync.

---

## 📁 Repository Structure

```
/home/hari/Desktop/AM/
├── ontology/
│   ├── asset_ontology.ttl    # Formal OWL/Turtle Ontology Definition
│   ├── asset_schema.json     # JSON-LD Context & Schema Definition
│   └── asset_graph.ttl       # Exported Graph Knowledge Base in Turtle format
├── web/
│   ├── index.html            # Web Dashboard UI
│   ├── style.css             # Glassmorphism Cyberpunk Dark Styling
│   └── app.js                # Vis-Network Graph & Interactive Handlers
├── config.py                 # Configuration settings (Wazuh IP, Credentials)
├── wazuh_collector.py        # Wazuh API REST Data Collector & Graph Builder
├── mcp_server.py             # Model Context Protocol (MCP) Server for Chatbots
├── server.py                 # HTTP Server & REST API Proxy
├── asset_graph.json          # Generated Knowledge Graph JSON
├── requirements.txt          # Python Dependencies
└── README.md                 # Usage Documentation
```

---

## 🚀 How to Run

### 1. Build Knowledge Graph from Wazuh Server
Run the collector to fetch agent data from `https://192.168.1.38:55000`:
```bash
python3 wazuh_collector.py
```
This generates `asset_graph.json` and `ontology/asset_graph.ttl`.

### 2. Start the Visual Web Dashboard
Launch the web dashboard server:
```bash
python3 server.py
```
Open your browser at **`http://localhost:8080`** to view the interactive graph.

### 3. Connect to MCP Chatbot Tool Server
Run the MCP server to interface with AI Chatbots (Claude Desktop, Cursor, Gemini Chatbot):
```bash
python3 mcp_server.py
```

To test MCP summary output via CLI:
```bash
python3 mcp_server.py --summary
```

---

## 🤖 MCP Chatbot Integration Configuration

To add this tool to Claude Desktop or MCP client config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "wazuh_asset_management": {
      "command": "python3",
      "args": [
        "/home/hari/Desktop/AM/mcp_server.py"
      ]
    }
  }
}
```

---

## 🔗 Wazuh Credentials & Configuration
Configured in `config.py` (or via environment variables):
- **Wazuh API Host**: `https://192.168.1.38:55000`
- **Username**: `wazuh-wui`
- **Password**: `MyS3cr37P450r.*-`
