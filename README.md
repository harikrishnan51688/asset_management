# Wazuh IT Asset Management & Neo4j Knowledge Graph with MCP AI Integration

A containerized IT Asset Management Knowledge Graph system, powered by **Neo4j Graph Database**, **Wazuh Security Platform Telemetry Collector**, **Interactive Web Visualizer**, and **Model Context Protocol (MCP) AI Server**.

---

## 🌟 Key Features

1. **Neo4j Graph Database Backend**: Replaces static Turtle TTL files with a production-grade Neo4j graph database. Stores agents, hardware specs, operating systems, network interfaces, open ports, and agent groups as nodes and relationships (`HAS_OS`, `HAS_IP`, `HAS_HARDWARE`, `HAS_PORT`, `BELONGS_TO_GROUP`, `MANAGED_BY`, etc.).
2. **Automated Wazuh API Collector & Sync**: Connects to Wazuh REST API (`https://192.168.1.38:55000`), authenticates with JWT tokens, and automatically ingests knowledge graph telemetry into Neo4j.
3. **Model Context Protocol (MCP) Server for AI Chatbots**: Exposes standard MCP tools (`get_asset_summary`, `list_agents`, `search_assets`, `refresh_wazuh_data`) so LLMs (Claude Desktop, Cursor, Gemini, VS Code AI) can directly query Neo4j assets and topology.
4. **Interactive Glassmorphism Dashboard**: Vis.js network visualizer with category filtering, node inspector drawer, and live sync with Neo4j & Wazuh REST API.
5. **Full Dockerization**: One-command launch via `docker compose up -d` for both Neo4j Database and the Asset Management application.

---

## 📁 Repository Structure

```
asset_management/
├── docker-compose.yml       # Docker Compose service definitions (Neo4j + App)
├── Dockerfile               # Python application container build specification
├── config.py                # System & Database configuration (Wazuh, Neo4j, Server)
├── neo4j_client.py          # Neo4j Database driver manager, schema init & Cypher queries
├── wazuh_collector.py       # Wazuh REST API collector & Neo4j graph sync engine
├── server.py                # Web server, REST API proxy & Neo4j graph renderer
├── mcp_server.py            # Model Context Protocol (MCP) Server for AI Chatbots
├── csv_importer.py          # CSV Asset Importer for unmanaged PCs and devices
├── sample_assets.csv        # Template/example CSV for manual asset import
├── requirements.txt         # Python dependencies (neo4j, requests, mcp, etc.)
└── web/                     # Visualizer Web Dashboard (Vis.js, HTML5, CSS3)
```



---

## 🚀 Quick Start with Docker Compose

### 1. Launch the Entire Stack
Run Docker Compose from the project directory:
```bash
docker compose up -d
```

This starts:
- **Neo4j Graph Database**: Running at `bolt://localhost:7687`
- **Neo4j Web Browser**: Available at `http://localhost:7474` (Credentials: `neo4j` / `password123`)
- **Wazuh Asset Web Dashboard**: Available at `http://localhost:8080`

### 2. View Service Status & Logs
```bash
docker compose ps
docker compose logs -f app
```

---

## 📥 Import Assets from CSV (Unmanaged PCs & Devices)

Some computers, laptops, local NAS servers, or warehouse terminals may not have Wazuh agent installed. You can import these unmanaged assets directly into **Neo4j** and visualize them in the network graph alongside Wazuh-managed agents.

### 📋 CSV Format & Field Reference

| Column Name | Required | Example | Description |
|-------------|:--------:|---------|-------------|
| `device_id` | **Yes** | `pc-fin-01` | Unique device identifier |
| `name` | **Yes** | `Finance-Desktop-01` | Hostname or display name |
| `ip` | **Yes** | `192.168.1.110` | IPv4 or IPv6 address (creates `:IPAddress` node & `hasIP` edge) |
| `device_type` | No | `Workstation` | Node type (`EndpointAgent`, `Workstation`, `Server`, `Device`) |
| `os_name` | No | `Windows 11 Pro` | Operating system name (creates `:OperatingSystem` node & `hasOS` edge) |
| `os_version` | No | `23H2` | OS version / release |
| `status` | No | `active` | Asset status (`active`, `disconnected`, `unmanaged`) |
| `group` | No | `Finance` | Department or group (creates `:AgentGroup` node & `belongsToGroup` edge) |
| `cpu` | No | `Intel Core i7-13700` | CPU specification (creates `:HardwareSpec` node & `hasHardware` edge) |
| `ram_gb` | No | `32` | Total RAM in GB |
| `mac_address` | No | `00:1A:2B:3C:4D:5E` | Network MAC address |
| `open_ports` | No | `445,3389` | Comma-separated list of listening TCP ports (creates `:NetworkPort` nodes & `hasPort` edges) |
| `description` | No | `Accounts Workstation` | Additional metadata / inventory notes |

### 📄 Example CSV (`sample_assets.csv`)
```csv
device_id,name,ip,device_type,os_name,os_version,status,group,cpu,ram_gb,mac_address,open_ports,description
pc-fin-01,Finance-Desktop-01,192.168.1.110,Workstation,Windows 11 Pro,23H2,active,Finance,Intel Core i7-13700,32,00:1A:2B:3C:4D:5E,"445,3389",Accounts Workstation
pc-hr-01,HR-Laptop-01,192.168.1.120,EndpointAgent,macOS Sonoma,14.5,active,HumanResources,Apple M2 Pro,16,A4:83:E7:2B:11:0A,"22",HR MacBook
srv-backup-01,NAS-Storage-Server,192.168.1.200,Server,Ubuntu Server,24.04,active,Infrastructure,AMD EPYC 7302P,64,00:25:90:AB:CD:EF,"22,80,443",Backup NAS
```

### 🚀 How to Import

#### Method 1: Web Dashboard (Recommended)
1. Open the dashboard at **[http://localhost:8080](http://localhost:8080)**.
2. Click the **"Import CSV"** button in the top navigation bar.
3. Select your `.csv` file. The graph will immediately refresh and display the newly imported PCs and relationships.

#### Method 2: Command Line (CLI)
Run the importer script with Python:
```bash
python3 csv_importer.py sample_assets.csv
```
Or via virtual environment:
```bash
./venv/bin/python csv_importer.py sample_assets.csv
```

#### Method 3: REST API Upload (curl)
```bash
curl -X POST -H "Content-Type: text/csv" --data-binary @sample_assets.csv http://localhost:8080/api/import/csv
```

---


## 🤖 MCP AI Chatbot Integration

To connect this Knowledge Graph to AI Chatbots (Claude Desktop, Cursor, Gemini, MCP CLI), configure the MCP client configuration.

### Option A: Local Python Execution (Pointing to Docker Neo4j)
If running an MCP client on your host system:

```json
{
  "mcpServers": {
    "wazuh_asset_management": {
      "command": "python3",
      "args": [
        "/absolute/path/to/asset_management/mcp_server.py"
      ],
      "env": {
        "NEO4J_URI": "bolt://localhost:7687",
        "NEO4J_USER": "neo4j",
        "NEO4J_PASSWORD": "password123",
        "WAZUH_HOST": "https://192.168.1.38:55000"
      }
    }
  }
}
```

### Option B: Docker Container Execution
To run the MCP server directly via the Docker container:

```json
{
  "mcpServers": {
    "wazuh_asset_management": {
      "command": "docker",
      "args": [
        "exec",
        "-i",
        "wazuh_asset_app",
        "python3",
        "/app/mcp_server.py"
      ]
    }
  }
}
```

### Available MCP Tools
- **`get_asset_summary`**: High-level overview of connected agents, unique IP addresses, and operating systems.
- **`list_agents`**: List all Wazuh agents filtered by status (`active`, `disconnected`, etc.).
- **`search_assets`**: Keyword search across all Neo4j nodes (IPs, OS, hardware, ports, agents).
- **`refresh_wazuh_data`**: Fetch live telemetry from Wazuh REST API and update Neo4j.

---

## 📊 Querying Neo4j directly via Cypher

You can open the Neo4j Browser UI at `http://localhost:7474` and run Cypher queries:

- **View All Nodes and Relationships**:
  ```cypher
  MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 100;
  ```
- **Find Agents by Operating System**:
  ```cypher
  MATCH (a:AssetNode)-[:HAS_OS]->(os:OperatingSystem)
  RETURN a.name AS Agent, os.label AS OperatingSystem;
  ```
- **List All Agent IP Addresses**:
  ```cypher
  MATCH (a:AssetNode)-[:HAS_IP]->(ip:IPAddress)
  RETURN a.name AS Agent, ip.ip AS IPAddress;
  ```

---

## ⚙️ Configuration & Environment Variables

Key settings can be modified in `docker-compose.yml` or via `.env`:

| Parameter | Default Value | Description |
|-----------|---------------|-------------|
| `NEO4J_URI` | `bolt://neo4j:7687` | Connection URI for Neo4j Database |
| `NEO4J_USER` | `neo4j` | Database Username |
| `NEO4J_PASSWORD` | `password123` | Database Password |
| `WAZUH_HOST` | `https://192.168.1.38:55000` | Wazuh Manager REST API Endpoint |
| `WAZUH_USER` | `wazuh-wui` | Wazuh API Username |
| `WAZUH_PASSWORD` | `MyS3cr37P450r.*-` | Wazuh API Password |
| `SERVER_PORT` | `8080` | Web Dashboard & REST API Port |
