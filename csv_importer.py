#!/usr/bin/env python3
"""
CSV Asset Importer for IT Asset Management & Neo4j Knowledge Graph.
Parses CSV files containing unmanaged or external devices (PCs, laptops, servers, network hardware)
and ingests them into Neo4j and the graph visualizer.
"""

import csv
import io
import json
import logging
import os
import sys
from typing import Dict, Any, List, Optional
from config import GRAPH_JSON_PATH
from neo4j_client import neo4j_manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CSVImporter")


def parse_csv_rows(csv_file_or_content: io.TextIOBase) -> List[Dict[str, str]]:
    """Parse CSV content and return normalized dictionaries."""
    reader = csv.DictReader(csv_file_or_content)
    rows = []
    for row in reader:
        # Normalize and strip whitespace from keys and values
        clean_row = {
            k.strip().lower(): v.strip() for k, v in row.items() if k is not None and v is not None
        }
        if clean_row.get("device_id") or clean_row.get("name") or clean_row.get("ip"):
            rows.append(clean_row)
    return rows


def build_graph_from_csv(rows: List[Dict[str, str]]) -> Dict[str, Any]:
    """Convert CSV rows into graph nodes and relationships."""
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, str]] = []
    edge_set = set()

    def add_node(node_id: str, label: str, node_type: str, category: str = "asset", properties: Optional[Dict[str, Any]] = None):
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "label": label,
                "type": node_type,
                "category": category,
                "properties": properties or {}
            }
        elif properties:
            nodes[node_id]["properties"].update(properties)

    def add_edge(source_id: str, target_id: str, relationship: str, label: Optional[str] = None):
        key = (source_id, target_id, relationship)
        if key not in edge_set:
            edge_set.add(key)
            edges.append({
                "source": source_id,
                "target": target_id,
                "relationship": relationship,
                "label": label or relationship
            })

    for row in rows:
        device_id = row.get("device_id") or row.get("id") or f"unmanaged_{row.get('ip', 'dev').replace('.', '_')}"
        name = row.get("name") or row.get("hostname") or f"Device-{device_id}"
        ip = row.get("ip") or row.get("ip_address") or ""
        device_type = row.get("device_type") or row.get("type") or "EndpointAgent"
        os_name = row.get("os_name") or row.get("os") or ""
        os_version = row.get("os_version") or row.get("version") or ""
        status = row.get("status") or "unmanaged"
        group = row.get("group") or row.get("department") or ""
        cpu = row.get("cpu") or row.get("processor") or ""
        ram_gb = row.get("ram_gb") or row.get("ram") or ""
        mac = row.get("mac_address") or row.get("mac") or ""
        open_ports = row.get("open_ports") or row.get("ports") or ""
        description = row.get("description") or row.get("desc") or ""

        # Main Device Node
        dev_node_id = f"device_{device_id.replace('-', '_').replace(' ', '_')}"
        dev_props = {
            "agent_id": device_id,
            "name": name,
            "ip": ip,
            "status": status,
            "source": "csv_import",
            "is_managed": False,
            "date_added": row.get("date_added", "Manual Import")
        }
        if description:
            dev_props["description"] = description

        add_node(
            node_id=dev_node_id,
            label=f"{name} ({ip})" if ip else name,
            node_type=device_type,
            category="agent",
            properties=dev_props
        )

        # Operating System Node
        if os_name:
            os_id = f"os_{dev_node_id}"
            os_label = f"{os_name} {os_version}".strip()
            add_node(
                node_id=os_id,
                label=os_label,
                node_type="OperatingSystem",
                category="os",
                properties={
                    "name": os_name,
                    "version": os_version,
                    "source": "csv_import"
                }
            )
            add_edge(dev_node_id, os_id, "hasOS", "has OS")

        # IP Address Node
        if ip and ip not in ("127.0.0.1", "0.0.0.0"):
            ip_id = f"ip_{ip.replace('.', '_').replace(':', '_')}"
            add_node(
                node_id=ip_id,
                label=f"IP: {ip}",
                node_type="IPAddress",
                category="network",
                properties={
                    "ip": ip,
                    "mac": mac,
                    "type": "Static/Manual",
                    "source": "csv_import"
                }
            )
            add_edge(dev_node_id, ip_id, "hasIP", "has IP")

        # Hardware Specs Node
        if cpu or ram_gb:
            hw_id = f"hw_{dev_node_id}"
            hw_label = f"HW: {cpu or 'Hardware'}"
            if ram_gb:
                hw_label += f" ({ram_gb}GB)"
            add_node(
                node_id=hw_id,
                label=hw_label,
                node_type="HardwareSpec",
                category="hardware",
                properties={
                    "cpu_name": cpu,
                    "ram_total": f"{ram_gb} GB" if ram_gb and not str(ram_gb).endswith("GB") else str(ram_gb),
                    "source": "csv_import"
                }
            )
            add_edge(dev_node_id, hw_id, "hasHardware", "has hardware")

        # Group Node
        if group:
            grp_id = f"group_{group.lower().replace(' ', '_').replace('-', '_')}"
            add_node(
                node_id=grp_id,
                label=f"Group: {group}",
                node_type="AgentGroup",
                category="group",
                properties={"group_name": group, "source": "csv_import"}
            )
            add_edge(dev_node_id, grp_id, "belongsToGroup", "belongs to group")

        # Open Ports
        if open_ports:
            # Ports can be semicolon or comma delimited: "80,443,3389"
            clean_ports = [p.strip() for p in open_ports.replace(";", ",").split(",") if p.strip()]
            for p in clean_ports:
                port_id = f"port_{p}_tcp_{dev_node_id}"
                add_node(
                    node_id=port_id,
                    label=f"Port {p}/tcp",
                    node_type="NetworkPort",
                    category="port",
                    properties={"port": p, "protocol": "tcp", "source": "csv_import"}
                )
                add_edge(dev_node_id, port_id, "hasPort", "has port")

    return {
        "nodes": list(nodes.values()),
        "edges": edges
    }


def sync_imported_graph(new_graph_data: Dict[str, Any]) -> Dict[str, Any]:
    """Merge imported graph into Neo4j and update JSON snapshot cache."""
    nodes = new_graph_data.get("nodes", [])
    edges = new_graph_data.get("edges", [])

    if not nodes:
        return {"status": "error", "message": "No valid assets found in CSV data."}

    # 1. Ingest into Neo4j Database
    neo4j_synced = False
    if neo4j_manager.is_connected():
        neo4j_synced = neo4j_manager.sync_graph_data(new_graph_data)

    # 2. Update local asset_graph.json cache to merge with existing data
    cached_graph = {"nodes": [], "edges": []}
    if os.path.exists(GRAPH_JSON_PATH):
        try:
            with open(GRAPH_JSON_PATH, "r", encoding="utf-8") as f:
                cached_graph = json.load(f)
        except Exception as e:
            logger.warning(f"Could not load existing cache: {e}")

    existing_node_map = {n["id"]: n for n in cached_graph.get("nodes", [])}
    for n in nodes:
        existing_node_map[n["id"]] = n

    existing_edge_set = {(e["source"], e["target"], e["relationship"]) for e in cached_graph.get("edges", [])}
    merged_edges = list(cached_graph.get("edges", []))
    for e in edges:
        key = (e["source"], e["target"], e["relationship"])
        if key not in existing_edge_set:
            existing_edge_set.add(key)
            merged_edges.append(e)

    updated_graph = {
        "metadata": {
            "total_nodes": len(existing_node_map),
            "total_edges": len(merged_edges),
            "source": "Neo4j Database (CSV + Wazuh)"
        },
        "nodes": list(existing_node_map.values()),
        "edges": merged_edges
    }

    try:
        with open(GRAPH_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(updated_graph, f, indent=2)
    except Exception as e:
        logger.warning(f"Failed to write updated asset_graph.json cache: {e}")

    logger.info(f"Imported {len(nodes)} nodes and {len(edges)} relationships from CSV.")
    return {
        "status": "success",
        "imported_nodes": len(nodes),
        "imported_relationships": len(edges),
        "neo4j_synced": neo4j_synced,
        "total_nodes": len(existing_node_map),
        "total_relationships": len(merged_edges)
    }


def import_csv_file(file_path: str) -> Dict[str, Any]:
    """Import assets from a CSV file on disk."""
    if not os.path.exists(file_path):
        return {"status": "error", "message": f"File not found: {file_path}"}
    with open(file_path, "r", encoding="utf-8-sig") as f:
        rows = parse_csv_rows(f)
    graph_data = build_graph_from_csv(rows)
    return sync_imported_graph(graph_data)


def import_csv_content(csv_text: str) -> Dict[str, Any]:
    """Import assets from a raw CSV string."""
    buf = io.StringIO(csv_text)
    rows = parse_csv_rows(buf)
    graph_data = build_graph_from_csv(rows)
    return sync_imported_graph(graph_data)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 csv_importer.py <path_to_assets.csv>")
        sys.exit(1)

    csv_path = sys.argv[1]
    res = import_csv_file(csv_path)
    print(json.dumps(res, indent=2))
