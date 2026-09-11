#!/usr/bin/env python3
"""
HTTP Server and API Proxy for Wazuh Asset Management Visualizer.
Serves web interface and API endpoints for Graph data and MCP tools.
"""

import http.server
import socketserver
import json
import os
import logging
from urllib.parse import urlparse
from config import SERVER_HOST, SERVER_PORT, GRAPH_JSON_PATH
from wazuh_collector import fetch_and_generate_graph
from mcp_server import WazuhMCPToolHandler

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("WazuhServer")

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")

class AssetManagementHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP Request Handler serving Web Dashboard & API Endpoints."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_GET(self):
        parsed_path = urlparse(self.path).path

        if parsed_path == "/api/graph":
            self._send_json(self._get_graph_data())
        elif parsed_path == "/api/summary":
            summary = WazuhMCPToolHandler.get_asset_summary()
            self._send_json(summary)
        elif parsed_path == "/api/agents":
            agents = WazuhMCPToolHandler.list_agents()
            self._send_json(agents)
        elif parsed_path.startswith("/api/vulnerabilities/"):
            agent_id = parsed_path.split("/")[-1]
            vulns = WazuhMCPToolHandler.get_agent_vulnerabilities(agent_id)
            self._send_json(vulns)
        elif parsed_path == "/asset_graph.json":
            self._send_file(GRAPH_JSON_PATH, "application/json")
        elif parsed_path.startswith("/ontology/"):
            ttl_path = os.path.join(os.path.dirname(__file__), parsed_path.lstrip("/"))
            self._send_file(ttl_path, "text/turtle")
        else:
            # Default static file handler
            super().do_GET()

    def do_POST(self):
        parsed_path = urlparse(self.path).path

        if parsed_path == "/api/refresh":
            logger.info("Triggering Wazuh API live refresh...")
            res = WazuhMCPToolHandler.refresh_wazuh_data()
            self._send_json(res)
        else:
            self.send_error(404, "Endpoint not found")

    def _get_graph_data(self):
        if not os.path.exists(GRAPH_JSON_PATH):
            logger.info("Graph file missing. Generating initial snapshot...")
            return fetch_and_generate_graph() or {"nodes": [], "edges": [], "error": "Fetch failed"}
        try:
            with open(GRAPH_JSON_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading graph JSON: {e}")
            return {"nodes": [], "edges": [], "error": str(e)}

    def _send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, filepath, mime_type):
        if not os.path.exists(filepath):
            self.send_error(404, "File not found")
            return
        with open(filepath, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(content)

def run_server(port=SERVER_PORT):
    server_address = (SERVER_HOST, port)
    # Allow address reuse
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(server_address, AssetManagementHTTPHandler) as httpd:
        logger.info(f"Wazuh Asset Ontology Web Dashboard running on http://0.0.0.0:{port} (http://localhost:{port})")
        logger.info(f"API endpoints available at http://0.0.0.0:{port}/api/graph and http://0.0.0.0:{port}/api/summary")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("Server shutting down.")

if __name__ == "__main__":
    run_server()
