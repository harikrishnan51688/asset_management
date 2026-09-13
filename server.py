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
from neo4j_client import neo4j_manager


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("WazuhServer")

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")

class AssetManagementHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP Request Handler serving Web Dashboard & API Endpoints."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

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
        elif parsed_path == "/sample_assets.csv":
            sample_path = os.path.join(os.path.dirname(__file__), "sample_assets.csv")
            self._send_file(sample_path, "text/csv")
        elif parsed_path == "/asset_graph.json":
            self._send_file(GRAPH_JSON_PATH, "application/json")
        else:

            # Default static file handler
            super().do_GET()

    def do_POST(self):
        parsed_path = urlparse(self.path).path

        if parsed_path == "/api/refresh":
            logger.info("Triggering Wazuh API live refresh...")
            res = WazuhMCPToolHandler.refresh_wazuh_data()
            self._send_json(res)
        elif parsed_path == "/api/import/csv":
            logger.info("Received CSV asset import request...")
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self._send_json({"status": "error", "message": "Empty CSV payload"}, status=400)
                return

            raw_data = self.rfile.read(content_length)
            content_type = self.headers.get("Content-Type", "")

            # Handle multipart/form-data or raw CSV text
            csv_text = ""
            if "multipart/form-data" in content_type:
                parts = raw_data.split(b"\r\n\r\n", 1)
                if len(parts) > 1:
                    body = parts[1]
                    boundary_idx = body.rfind(b"\r\n--")
                    if boundary_idx != -1:
                        body = body[:boundary_idx]
                    csv_text = body.decode("utf-8-sig", errors="ignore")
            else:
                csv_text = raw_data.decode("utf-8-sig", errors="ignore")

            from csv_importer import import_csv_content
            res = import_csv_content(csv_text)
            self._send_json(res, status=200 if res.get("status") == "success" else 400)
        else:
            self.send_error(404, "Endpoint not found")


    def _get_graph_data(self):
        if neo4j_manager.is_connected():
            graph_data = neo4j_manager.fetch_full_graph()
            if graph_data.get("nodes"):
                return graph_data
            logger.info("Neo4j database is empty. Triggering initial fetch or seed...")
            fetched = fetch_and_generate_graph()
            graph_data = neo4j_manager.fetch_full_graph()
            if graph_data.get("nodes"):
                return graph_data
            if fetched and fetched.get("nodes"):
                return fetched
        
        if os.path.exists(GRAPH_JSON_PATH):
            try:
                with open(GRAPH_JSON_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading graph JSON fallback: {e}")

        return fetch_and_generate_graph() or {"nodes": [], "edges": [], "error": "Fetch failed"}



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
