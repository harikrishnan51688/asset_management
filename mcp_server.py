#!/usr/bin/env python3
"""
Model Context Protocol (MCP) Server for Wazuh IT Asset Management & Vulnerability Ontology.
Provides standardized tools for Chatbots and LLMs to query IT assets, IP addresses,
operating systems, open ports, software packages, and vulnerabilities directly from Neo4j.
"""

import sys
import json
import os
import logging
from wazuh_collector import fetch_and_generate_graph, GRAPH_JSON_PATH
from neo4j_client import neo4j_manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", stream=sys.stderr)
logger = logging.getLogger("WazuhMCPServer")

def load_graph_fallback():
    """Load the local JSON asset graph fallback if Neo4j is unavailable."""
    if not os.path.exists(GRAPH_JSON_PATH):
        logger.info("Graph file not found. Triggering initial fetch from Wazuh...")
        return fetch_and_generate_graph()
    try:
        with open(GRAPH_JSON_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error reading fallback graph file: {e}")
        return fetch_and_generate_graph()


class WazuhMCPToolHandler:
    """Tool execution handlers for MCP framework connected to Neo4j Graph DB."""

    @staticmethod
    def get_asset_summary():
        if neo4j_manager.is_connected():
            summary = neo4j_manager.get_asset_summary()
            if "error" not in summary:
                return summary

        logger.info("Neo4j unavailable for summary. Falling back to local JSON snapshot...")
        graph = load_graph_fallback()
        if not graph:
            return {"error": "Unable to load asset graph from Wazuh or Neo4j."}

        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        
        agents = [n for n in nodes if n["type"] in ("Agent", "ManagerAgent", "EndpointAgent")]
        active_agents = [a for a in agents if a["properties"].get("status") == "active"]
        vulns = [n for n in nodes if n["type"] == "Vulnerability"]
        
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for v in vulns:
            sev = v["properties"].get("severity", "Medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        ips = [n for n in nodes if n["type"] == "IPAddress"]
        os_list = [n for n in nodes if n["type"] == "OperatingSystem"]

        return {
            "summary": "Wazuh IT Asset Management & Security Overview (JSON Fallback)",
            "wazuh_host": graph.get("metadata", {}).get("wazuh_host", "https://192.168.1.38:55000"),
            "total_nodes": len(nodes),
            "total_relationships": len(edges),
            "agents": {
                "total": len(agents),
                "active": len(active_agents),
                "list": [{"id": a["properties"].get("agent_id"), "name": a["properties"].get("name"), "ip": a["properties"].get("ip"), "status": a["properties"].get("status")} for a in agents]
            },
            "network": {
                "total_unique_ips": len(ips),
                "ip_addresses": [i["properties"].get("ip") for i in ips if i["properties"].get("ip")]
            },
            "operating_systems": [o["label"] for o in os_list],
            "vulnerability_metrics": {
                "total_cves_detected": len(vulns),
                "by_severity": severity_counts
            }
        }

    @staticmethod
    def list_agents(status_filter=None):
        if neo4j_manager.is_connected():
            agents = neo4j_manager.list_agents(status_filter)
            return {"agents": agents}

        logger.info("Neo4j unavailable for list_agents. Falling back to local JSON snapshot...")
        graph = load_graph_fallback() or {}
        nodes = graph.get("nodes", [])
        agents = [n for n in nodes if n["type"] in ("Agent", "ManagerAgent", "EndpointAgent")]
        
        result = []
        for a in agents:
            props = a["properties"]
            if status_filter and props.get("status") != status_filter:
                continue
            result.append({
                "agent_id": props.get("agent_id"),
                "name": props.get("name"),
                "node_type": a["type"],
                "status": props.get("status"),
                "ip": props.get("ip"),
                "wazuh_version": props.get("version"),
                "registered_ip": props.get("register_ip"),
                "last_keep_alive": props.get("last_keep_alive")
            })
        return {"agents": result}

    @staticmethod
    def get_agent_vulnerabilities(agent_id):
        if neo4j_manager.is_connected():
            res = neo4j_manager.get_agent_vulnerabilities(agent_id)
            if "error" not in res:
                return res

        logger.info("Neo4j unavailable for get_agent_vulnerabilities. Falling back to local JSON snapshot...")
        graph = load_graph_fallback() or {}
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        
        target_agent_id = str(agent_id).zfill(3) if str(agent_id).isdigit() else str(agent_id)
        agent_node = next((n for n in nodes if n["properties"].get("agent_id") == target_agent_id or n["properties"].get("name") == agent_id), None)
        
        if not agent_node:
            return {"error": f"Agent '{agent_id}' not found in asset graph."}
        
        agent_nid = agent_node["id"]
        vuln_edge_targets = [e["target"] for e in edges if e["source"] == agent_nid and e["relationship"] in ("hasVulnerability", "HAS_VULNERABILITY")]
        vuln_nodes = [n for n in nodes if n["id"] in vuln_edge_targets]

        vulnerabilities = []
        for v in vuln_nodes:
            props = v["properties"]
            vulnerabilities.append({
                "cve_id": props.get("cve_id"),
                "severity": props.get("severity"),
                "cvss_score": props.get("cvss_score"),
                "title": props.get("title"),
                "package_name": props.get("package_name"),
                "package_version": props.get("package_version")
            })

        sev_priority = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        vulnerabilities.sort(key=lambda x: sev_priority.get(x.get("severity", "Medium"), 4))

        return {
            "agent_id": agent_node["properties"].get("agent_id"),
            "agent_name": agent_node["properties"].get("name"),
            "agent_ip": agent_node["properties"].get("ip"),
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }

    @staticmethod
    def search_assets(query):
        if neo4j_manager.is_connected():
            results = neo4j_manager.search_assets(query)
            return {
                "query": query,
                "match_count": len(results),
                "source": "Neo4j Database",
                "results": results
            }

        logger.info("Neo4j unavailable for search_assets. Falling back to local JSON snapshot...")
        graph = load_graph_fallback() or {}
        q = str(query).lower().strip()
        nodes = graph.get("nodes", [])
        
        matching_nodes = []
        for n in nodes:
            props_str = " ".join([str(v) for v in n.get("properties", {}).values()]).lower()
            if q in n["id"].lower() or q in n["label"].lower() or q in props_str:
                matching_nodes.append({
                    "id": n["id"],
                    "label": n["label"],
                    "type": n["type"],
                    "category": n.get("category"),
                    "properties": n["properties"]
                })

        return {
            "query": query,
            "match_count": len(matching_nodes),
            "source": "JSON Fallback",
            "results": matching_nodes[:30]
        }

    @staticmethod
    def refresh_wazuh_data():
        logger.info("MCP Tool refresh_wazuh_data invoked.")
        graph = fetch_and_generate_graph()
        if graph:
            return {
                "status": "success",
                "message": "Asset Knowledge Graph successfully refreshed from Wazuh API and synced to Neo4j.",
                "total_nodes": len(graph.get("nodes", [])),
                "total_edges": len(graph.get("edges", []))
            }
        else:
            return {"status": "error", "message": "Failed to refresh data from Wazuh API."}


# Try importing MCP SDK if available; otherwise provide fallback stdio runner
try:
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("Wazuh Asset Management Neo4j Server")

    @mcp.tool()
    def get_asset_summary():
        """Get high-level summary of connected Wazuh agents, IP addresses, OS types, and vulnerability statistics from Neo4j."""
        return WazuhMCPToolHandler.get_asset_summary()

    @mcp.tool()
    def list_agents(status_filter: str = None):
        """List all Wazuh agent assets with status, IP, and version details from Neo4j."""
        return WazuhMCPToolHandler.list_agents(status_filter)

    @mcp.tool()
    def get_agent_vulnerabilities(agent_id: str):
        """Get security vulnerabilities (CVEs), severity ratings, and affected software packages for a specified Wazuh agent ID (e.g., '001' or '000')."""
        return WazuhMCPToolHandler.get_agent_vulnerabilities(agent_id)

    @mcp.tool()
    def search_assets(query: str):
        """Search the Neo4j IT Asset Knowledge Graph by IP, CVE, OS name, package, or agent name."""
        return WazuhMCPToolHandler.search_assets(query)

    @mcp.tool()
    def refresh_wazuh_data():
        """Trigger a live telemetry fetch from Wazuh REST API to refresh and sync the Neo4j knowledge graph."""
        return WazuhMCPToolHandler.refresh_wazuh_data()

    def run_mcp_server():
        mcp.run()

except ImportError:
    # Standard JSON-RPC stdio MCP fallback
    def run_mcp_server():
        logger.info("FastMCP not installed. Running fallback stdio MCP server...")
        print(json.dumps({
            "status": "ready",
            "server": "Wazuh Asset Management MCP Server (Neo4j Backend)",
            "available_tools": [
                "get_asset_summary",
                "list_agents",
                "get_agent_vulnerabilities",
                "search_assets",
                "refresh_wazuh_data"
            ]
        }))

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--summary":
        print(json.dumps(WazuhMCPToolHandler.get_asset_summary(), indent=2))
    else:
        run_mcp_server()
