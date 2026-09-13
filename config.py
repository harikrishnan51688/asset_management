import os

# Wazuh API Configuration
WAZUH_HOST = os.getenv("WAZUH_HOST", "https://192.168.1.38:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh-wui")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "MyS3cr37P450r.*-")
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() in ("true", "1", "t")

# Output File Paths
GRAPH_JSON_PATH = os.path.join(os.path.dirname(__file__), "asset_graph.json")


# Neo4j Database Config
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password123")

# Server Config
SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("SERVER_PORT", "8080"))

