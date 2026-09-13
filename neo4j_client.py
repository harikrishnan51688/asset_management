import logging
import os
from typing import Dict, List, Any, Optional
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD

logger = logging.getLogger("Neo4jClient")

try:
    from neo4j import GraphDatabase, Driver
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    logger.warning("neo4j package not installed. Install with 'pip install neo4j'.")


class Neo4jGraphManager:
    """Manager for Neo4j Graph Database interactions."""

    def __init__(self, uri: str = NEO4J_URI, user: str = NEO4J_USER, password: str = NEO4J_PASSWORD):
        self.uri = uri
        self.user = user
        self.password = password
        self._driver: Optional[Any] = None

    def connect(self) -> bool:
        """Establish connection to Neo4j database."""
        if not NEO4J_AVAILABLE:
            logger.error("Neo4j driver is not installed.")
            return False

        try:
            self._driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self._driver.verify_connectivity()
            logger.info(f"Connected successfully to Neo4j at {self.uri}")
            self.init_schema()
            return True
        except Exception as e:
            logger.warning(f"Could not connect to Neo4j at {self.uri}: {e}")
            self._driver = None
            return False

    def close(self):
        """Close driver connection."""
        if self._driver:
            self._driver.close()
            self._driver = None

    def is_connected(self) -> bool:
        if not self._driver:
            return self.connect()
        try:
            self._driver.verify_connectivity()
            return True
        except Exception:
            return False

    def init_schema(self):
        """Create constraints and indexes in Neo4j."""
        if not self._driver:
            return
        
        constraints = [
            "CREATE CONSTRAINT asset_id_unique IF NOT EXISTS FOR (n:AssetNode) REQUIRE n.id IS UNIQUE;",
            "CREATE INDEX asset_type_idx IF NOT EXISTS FOR (n:AssetNode) ON (n.node_type);",
            "CREATE INDEX agent_id_idx IF NOT EXISTS FOR (n:AssetNode) ON (n.agent_id);"
        ]
        
        try:
            with self._driver.session() as session:
                for c in constraints:
                    session.run(c)
            logger.info("Neo4j schema constraints and indexes initialized.")
        except Exception as e:
            logger.warning(f"Failed to initialize Neo4j constraints: {e}")

    def sync_graph_data(self, graph_data: Dict[str, Any]) -> bool:
        """Ingest graph nodes and relationships from collector into Neo4j."""
        if not self.is_connected():
            logger.error("Cannot sync to Neo4j: Database not connected.")
            return False

        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])

        if not nodes:
            logger.warning("No nodes to sync to Neo4j.")
            return False

        try:
            # Group nodes by type for type-specific Cypher MERGE queries
            nodes_by_type: Dict[str, List[Dict[str, Any]]] = {}
            for n in nodes:
                node_type = n.get("type", "AssetNode")
                # Sanitize type name for Cypher label (alphanumeric only)
                clean_type = "".join(c for c in node_type if c.isalnum()) or "AssetNode"
                
                props = dict(n.get("properties", {}))
                props["id"] = n["id"]
                props["label"] = n["label"]
                props["node_type"] = n["type"]
                props["category"] = n.get("category", "asset")
                
                nodes_by_type.setdefault(clean_type, []).append(props)

            with self._driver.session() as session:
                # Merge Nodes by Type Label
                for node_type, batch in nodes_by_type.items():
                    cypher = f"""
                    UNWIND $batch AS props
                    MERGE (n:AssetNode:{node_type} {{id: props.id}})
                    SET n += props
                    """
                    session.run(cypher, batch=batch)

                # Group Edges by Relationship Type
                edges_by_rel: Dict[str, List[Dict[str, Any]]] = {}
                for e in edges:
                    rel_name = e.get("relationship", "RELATED_TO")
                    # Convert camelCase / text to UPPER_SNAKE_CASE for Cypher relationship
                    clean_rel = "".join(c if c.isalnum() else "_" for c in rel_name).upper()
                    if clean_rel.startswith("HAS"):
                        clean_rel = clean_rel.replace("HAS", "HAS_")
                    clean_rel = clean_rel.replace("__", "_").strip("_")
                    
                    edges_by_rel.setdefault(clean_rel, []).append({
                        "source": e["source"],
                        "target": e["target"],
                        "label": e.get("label", rel_name)
                    })

                # Merge Edges
                for rel_type, batch in edges_by_rel.items():
                    cypher = f"""
                    UNWIND $batch AS edge
                    MATCH (source:AssetNode {{id: edge.source}})
                    MATCH (target:AssetNode {{id: edge.target}})
                    MERGE (source)-[r:{rel_type}]->(target)
                    SET r.label = edge.label
                    """
                    session.run(cypher, batch=batch)

            logger.info(f"Successfully synced {len(nodes)} nodes and {len(edges)} relationships to Neo4j.")
            return True
        except Exception as e:
            logger.error(f"Error syncing data to Neo4j: {e}", exc_info=True)
            return False

    def fetch_full_graph(self) -> Dict[str, Any]:
        """Fetch full graph in Vis.js JSON structure from Neo4j."""
        if not self.is_connected():
            return {"nodes": [], "edges": [], "error": "Neo4j connection unavailable"}

        try:
            nodes_map = {}
            edges_list = []
            edge_set = set()

            with self._driver.session() as session:
                # Query nodes
                node_result = session.run("MATCH (n:AssetNode) RETURN n")
                for record in node_result:
                    n = record["n"]
                    props = dict(n)
                    node_id = props.pop("id", None)
                    label = props.pop("label", node_id)
                    node_type = props.pop("node_type", "AssetNode")
                    category = props.pop("category", "asset")

                    if node_id:
                        nodes_map[node_id] = {
                            "id": node_id,
                            "label": label,
                            "type": node_type,
                            "category": category,
                            "properties": props
                        }

                # Query relationships
                rel_result = session.run("""
                MATCH (source:AssetNode)-[r]->(target:AssetNode) 
                RETURN source.id AS source, target.id AS target, type(r) AS rel_type, coalesce(r.label, type(r)) AS label
                """)
                for record in rel_result:
                    src = record["source"]
                    tgt = record["target"]
                    rel_type = record["rel_type"]
                    label = record["label"] or rel_type

                    edge_key = (src, tgt, rel_type)
                    if edge_key not in edge_set:
                        edge_set.add(edge_key)
                        edges_list.append({
                            "source": src,
                            "target": tgt,
                            "relationship": rel_type,
                            "label": label
                        })

            return {
                "metadata": {
                    "total_nodes": len(nodes_map),
                    "total_edges": len(edges_list),
                    "source": "Neo4j Database"
                },
                "nodes": list(nodes_map.values()),
                "edges": edges_list
            }
        except Exception as e:
            logger.error(f"Failed to fetch graph from Neo4j: {e}")
            return {"nodes": [], "edges": [], "error": str(e)}

    def get_asset_summary(self) -> Dict[str, Any]:
        """Aggregate high-level summary metrics from Neo4j."""
        if not self.is_connected():
            return {"error": "Neo4j connection unavailable"}

        try:
            with self._driver.session() as session:
                # Node counts by type
                agent_res = session.run("""
                MATCH (a:AssetNode) 
                WHERE a.node_type IN ['Agent', 'ManagerAgent', 'EndpointAgent', 'Workstation', 'Server', 'Device'] 
                RETURN count(a) AS total, 
                       sum(CASE WHEN a.status = 'active' THEN 1 ELSE 0 END) AS active,
                       collect({id: a.agent_id, name: a.name, ip: a.ip, status: a.status, type: a.node_type}) AS agents
                """).single()


                ip_res = session.run("""
                MATCH (i:AssetNode) WHERE i.node_type = 'IPAddress' 
                RETURN count(i) AS total, collect(i.ip) AS ips
                """).single()

                os_res = session.run("""
                MATCH (o:AssetNode) WHERE o.node_type = 'OperatingSystem'
                RETURN collect(o.label) AS os_labels
                """).single()

                total_nodes_res = session.run("MATCH (n:AssetNode) RETURN count(n) AS total").single()
                total_rels_res = session.run("MATCH ()-[r]->() RETURN count(r) AS total").single()

                return {
                    "summary": "Wazuh IT Asset Management Overview (Neo4j)",
                    "database": "Neo4j Graph Database",
                    "total_nodes": total_nodes_res["total"] if total_nodes_res else 0,
                    "total_relationships": total_rels_res["total"] if total_rels_res else 0,
                    "agents": {
                        "total": agent_res["total"] if agent_res else 0,
                        "active": agent_res["active"] if agent_res else 0,
                        "list": agent_res["agents"] if agent_res else []
                    },
                    "network": {
                        "total_unique_ips": ip_res["total"] if ip_res else 0,
                        "ip_addresses": [ip for ip in (ip_res["ips"] if ip_res else []) if ip]
                    },
                    "operating_systems": os_res["os_labels"] if os_res else []
                }
        except Exception as e:
            logger.error(f"Error executing Neo4j summary query: {e}")
            return {"error": str(e)}

    def list_agents(self, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """List agents from Neo4j graph."""
        if not self.is_connected():
            return []

        try:
            query = """
            MATCH (a:AssetNode) 
            WHERE a.node_type IN ['Agent', 'ManagerAgent', 'EndpointAgent', 'Workstation', 'Server', 'Device']
            """
            params = {}
            if status_filter:
                query += " AND a.status = $status_filter"
                params["status_filter"] = status_filter

            query += """
            RETURN a.agent_id AS agent_id, a.name AS name, a.node_type AS node_type,
                   a.status AS status, a.ip AS ip, a.version AS wazuh_version,
                   a.register_ip AS registered_ip, a.last_keep_alive AS last_keep_alive
            """

            with self._driver.session() as session:
                result = session.run(query, **params)
                return [dict(record) for record in result]
        except Exception as e:
            logger.error(f"Error listing agents from Neo4j: {e}")
            return []

    def search_assets(self, query: str) -> List[Dict[str, Any]]:
        """Search Neo4j nodes by keyword matching."""
        if not self.is_connected():
            return []

        try:
            q = str(query).lower().strip()
            with self._driver.session() as session:
                result = session.run("""
                MATCH (n:AssetNode)
                WHERE toLower(n.id) CONTAINS $q
                   OR toLower(n.label) CONTAINS $q
                   OR toLower(coalesce(n.name, '')) CONTAINS $q
                   OR toLower(coalesce(n.ip, '')) CONTAINS $q
                RETURN n LIMIT 30
                """, q=q)

                matching_nodes = []
                for record in result:
                    n = dict(record["n"])
                    nid = n.pop("id", "")
                    label = n.pop("label", nid)
                    ntype = n.pop("node_type", "AssetNode")
                    category = n.pop("category", "asset")
                    matching_nodes.append({
                        "id": nid,
                        "label": label,
                        "type": ntype,
                        "category": category,
                        "properties": n
                    })

                return matching_nodes
        except Exception as e:
            logger.error(f"Error searching assets in Neo4j: {e}")
            return []


# Global singleton instance
neo4j_manager = Neo4jGraphManager()
