import json
import logging
import urllib3
import requests
import os
from config import WAZUH_HOST, WAZUH_USER, WAZUH_PASSWORD, VERIFY_SSL, GRAPH_JSON_PATH
from neo4j_client import neo4j_manager


# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("WazuhCollector")

class WazuhAPIClient:
    """Client for Wazuh REST API."""
    def __init__(self, host=WAZUH_HOST, user=WAZUH_USER, password=WAZUH_PASSWORD, verify_ssl=VERIFY_SSL):
        self.host = host.rstrip("/")
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl
        self.token = None
        self.session = requests.Session()
        self.session.verify = verify_ssl

    def authenticate(self):
        """Authenticate with Wazuh REST API and store JWT token."""
        auth_url = f"{self.host}/security/user/authenticate"
        try:
            logger.info(f"Authenticating to Wazuh API at {auth_url}...")
            res = self.session.post(auth_url, auth=(self.user, self.password), timeout=10)
            res.raise_for_status()
            data = res.json()
            if data.get("error") == 0 and "token" in data.get("data", {}):
                self.token = data["data"]["token"]
                self.session.headers.update({"Authorization": f"Bearer {self.token}"})
                logger.info("Successfully authenticated to Wazuh API.")
                return True
            else:
                logger.error(f"Authentication failed: {data}")
                return False
        except Exception as e:
            logger.error(f"Failed to connect/authenticate to Wazuh API: {e}")
            return False

    def _get(self, endpoint, params=None, silent=False):
        if not self.token:
            if not self.authenticate():
                return None
        url = f"{self.host}{endpoint}"
        try:
            res = self.session.get(url, params=params, timeout=15)
            if res.status_code == 401:
                logger.info("Token expired. Re-authenticating...")
                if self.authenticate():
                    res = self.session.get(url, params=params, timeout=15)
            res.raise_for_status()
            return res.json()
        except Exception as e:
            if not silent:
                logger.warning(f"Failed GET request for {endpoint}: {e}")
            return None

    def get_agents(self):
        data = self._get("/agents")
        return data.get("data", {}).get("affected_items", []) if data else []

    def get_hardware(self, agent_id):
        data = self._get(f"/syscollector/{agent_id}/hardware", silent=True)
        return data.get("data", {}).get("affected_items", []) if data else []

    def get_netaddr(self, agent_id):
        data = self._get(f"/syscollector/{agent_id}/netaddr", silent=True)
        return data.get("data", {}).get("affected_items", []) if data else []

    def get_vulnerabilities(self, agent_id):
        endpoints = [
            f"/vulnerability/{agent_id}",
            f"/vulnerability/{agent_id}/cve",
            f"/vulnerability/agents/{agent_id}",
            f"/syscollector/{agent_id}/vulnerabilities"
        ]
        for ep in endpoints:
            data = self._get(ep, silent=True)
            if data and data.get("data") and data["data"].get("affected_items"):
                return data["data"]["affected_items"]
        return []

    def get_ports(self, agent_id):
        data = self._get(f"/syscollector/{agent_id}/ports", silent=True)
        return data.get("data", {}).get("affected_items", []) if data else []

    def get_packages(self, agent_id, limit=50):
        data = self._get(f"/syscollector/{agent_id}/packages", params={"limit": limit})
        return data.get("data", {}).get("affected_items", []) if data else []


class WazuhOntologyGraphBuilder:
    """Transforms Wazuh API data into Asset Management Knowledge Graph."""
    
    def __init__(self, api_client: WazuhAPIClient):
        self.api = api_client
        self.nodes = {}
        self.edges = []
        self.edge_set = set()

    def _add_node(self, node_id, label, node_type, properties=None, category="asset"):
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "label": label,
                "type": node_type,
                "category": category,
                "properties": properties or {}
            }
        else:
            # Merge properties
            if properties:
                self.nodes[node_id]["properties"].update(properties)

    def _add_edge(self, source_id, target_id, relationship, label=None):
        edge_key = (source_id, target_id, relationship)
        if edge_key not in self.edge_set:
            self.edge_set.add(edge_key)
            self.edges.append({
                "source": source_id,
                "target": target_id,
                "relationship": relationship,
                "label": label or relationship
            })

    def build_graph(self):
        """Fetch all agents and detailed telemetry from Wazuh to build graph."""
        agents = self.api.get_agents()
        logger.info(f"Retrieved {len(agents)} agents from Wazuh.")

        manager_node_id = None

        # First pass: Create Agent Nodes
        for agent in agents:
            agent_id = str(agent.get("id"))
            name = agent.get("name", f"Agent-{agent_id}")
            is_manager = (agent_id == "000" or "manager" in name.lower())
            
            node_type = "ManagerAgent" if is_manager else "EndpointAgent"
            node_id = f"agent_{agent_id}"

            if is_manager:
                manager_node_id = node_id

            agent_props = {
                "agent_id": agent_id,
                "name": name,
                "status": agent.get("status", "unknown"),
                "ip": agent.get("ip", ""),
                "register_ip": agent.get("registerIP", ""),
                "version": agent.get("version", ""),
                "node_name": agent.get("node_name", ""),
                "last_keep_alive": agent.get("lastKeepAlive", ""),
                "date_added": agent.get("dateAdd", "")
            }

            self._add_node(
                node_id=node_id,
                label=f"{name} ({agent.get('ip', 'N/A')})",
                node_type=node_type,
                properties=agent_props,
                category="agent"
            )

            # OS Information
            os_info = agent.get("os", {})
            if os_info:
                os_name = os_info.get("name", "Unknown OS")
                os_ver = os_info.get("version", "")
                os_label = f"{os_name} {os_ver}".strip()
                os_id = f"os_{agent_id}"

                self._add_node(
                    node_id=os_id,
                    label=os_label,
                    node_type="OperatingSystem",
                    properties={
                        "name": os_name,
                        "version": os_ver,
                        "arch": os_info.get("arch", ""),
                        "platform": os_info.get("platform", ""),
                        "uname": os_info.get("uname", ""),
                        "codename": os_info.get("codename", "")
                    },
                    category="os"
                )
                self._add_edge(node_id, os_id, "hasOS", "has OS")

            # Agent Groups
            groups = agent.get("group", [])
            if isinstance(groups, str):
                groups = [groups]
            for grp in groups:
                grp_id = f"group_{grp}"
                self._add_node(
                    node_id=grp_id,
                    label=f"Group: {grp}",
                    node_type="AgentGroup",
                    properties={"group_name": grp},
                    category="group"
                )
                self._add_edge(node_id, grp_id, "belongsToGroup", "belongs to group")

            # Primary Agent IP
            primary_ip = agent.get("ip")
            if primary_ip and primary_ip != "127.0.0.1" and primary_ip != "any":
                ip_node_id = f"ip_{primary_ip.replace('.', '_')}"
                self._add_node(
                    node_id=ip_node_id,
                    label=f"IP: {primary_ip}",
                    node_type="IPAddress",
                    properties={"ip": primary_ip, "type": "Primary"},
                    category="network"
                )
                self._add_edge(node_id, ip_node_id, "hasIP", "has IP")

        # Connect Endpoint Agents to Manager
        if manager_node_id:
            for node_id, node_data in self.nodes.items():
                if node_data["type"] == "EndpointAgent":
                    self._add_edge(node_id, manager_node_id, "managedBy", "managed by")

        # Second Pass: Telemetry collector (Hardware, Network Interfaces, Vulnerabilities, Ports)
        for agent in agents:
            agent_id = str(agent.get("id"))
            agent_node_id = f"agent_{agent_id}"

            # 1. Hardware
            hw_items = self.api.get_hardware(agent_id)
            for hw in hw_items:
                cpu_name = hw.get("cpu_name") or hw.get("cpu", {}).get("name", "Unknown CPU")
                ram_total = hw.get("ram_total") or hw.get("memory", {}).get("total", "Unknown RAM")
                hw_id = f"hw_{agent_id}"
                self._add_node(
                    node_id=hw_id,
                    label=f"HW: {cpu_name}",
                    node_type="HardwareSpec",
                    properties={
                        "cpu_name": cpu_name,
                        "ram_total": str(ram_total),
                        "board_serial": hw.get("board_serial", ""),
                        "cores": hw.get("cpu_cores", "")
                    },
                    category="hardware"
                )
                self._add_edge(agent_node_id, hw_id, "hasHardware", "has hardware")

            # 2. Network Addresses
            net_items = self.api.get_netaddr(agent_id)
            for net in net_items:
                ip_addr = net.get("ip") or net.get("address")
                mac_addr = net.get("mac")
                if ip_addr and ip_addr not in ("127.0.0.1", "0.0.0.0"):
                    ip_id = f"ip_{ip_addr.replace('.', '_')}"
                    self._add_node(
                        node_id=ip_id,
                        label=f"IP: {ip_addr}",
                        node_type="IPAddress",
                        properties={
                            "ip": ip_addr,
                            "mac": mac_addr or "",
                            "proto": net.get("proto", ""),
                            "netmask": net.get("netmask", "")
                        },
                        category="network"
                    )
                    self._add_edge(agent_node_id, ip_id, "hasIP", "has IP")

            # 3. Open Ports
            ports = self.api.get_ports(agent_id)
            for port in ports[:15]: # Limit to top 15 ports per agent to keep graph clean
                port_num = port.get("port")
                protocol = port.get("protocol", "tcp")
                process_name = port.get("process", port.get("name", ""))
                if port_num:
                    port_id = f"port_{port_num}_{protocol}_{agent_id}"
                    self._add_node(
                        node_id=port_id,
                        label=f"Port {port_num}/{protocol} ({process_name})".strip(),
                        node_type="NetworkPort",
                        properties={
                            "port": port_num,
                            "protocol": protocol,
                            "process": process_name,
                            "state": port.get("state", "listen")
                        },
                        category="port"
                    )
                    self._add_edge(agent_node_id, port_id, "hasPort", "has port")

            # 4. Vulnerabilities
            vulns = self.api.get_vulnerabilities(agent_id)
            logger.info(f"Found {len(vulns)} vulnerabilities for Agent {agent_id}.")
            for v in vulns:
                cve_id = v.get("cve") or v.get("cve_id", "CVE-UNKNOWN")
                severity = (v.get("severity") or "Medium").capitalize()
                title = v.get("title") or v.get("description", cve_id)
                cvss = v.get("cvss3_score") or v.get("cvss2_score") or v.get("score") or "N/A"
                pkg_name = v.get("pkg_name") or v.get("package", {}).get("name", "")
                pkg_ver = v.get("pkg_version") or v.get("package", {}).get("version", "")

                vuln_id = f"vuln_{cve_id.replace('-', '_')}_{agent_id}"

                self._add_node(
                    node_id=vuln_id,
                    label=f"{cve_id} [{severity}]",
                    node_type="Vulnerability",
                    properties={
                        "cve_id": cve_id,
                        "severity": severity,
                        "title": title,
                        "cvss_score": str(cvss),
                        "package_name": pkg_name,
                        "package_version": pkg_ver,
                        "rationale": v.get("rationale", "")
                    },
                    category="vulnerability"
                )
                self._add_edge(agent_node_id, vuln_id, "hasVulnerability", "has vulnerability")

                # If package is associated, link to SoftwarePackage node
                if pkg_name:
                    pkg_id = f"pkg_{pkg_name.lower()}_{agent_id}"
                    self._add_node(
                        node_id=pkg_id,
                        label=f"Pkg: {pkg_name}",
                        node_type="SoftwarePackage",
                        properties={"name": pkg_name, "version": pkg_ver},
                        category="package"
                    )
                    self._add_edge(agent_node_id, pkg_id, "installedPackage", "installed package")
                    self._add_edge(vuln_id, pkg_id, "affectsPackage", "affects package")

        return {
            "metadata": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "agent_count": len(agents),
                "wazuh_host": self.api.host
            },
            "nodes": list(self.nodes.values()),
            "edges": self.edges
        }

def fetch_and_generate_graph():
    """Main function to query Wazuh API, save JSON snapshot, and sync into Neo4j graph database."""
    client = WazuhAPIClient()
    graph_data = None
    if client.authenticate():
        builder = WazuhOntologyGraphBuilder(client)
        graph_data = builder.build_graph()

        # Save to JSON
        with open(GRAPH_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(graph_data, f, indent=2)
        logger.info(f"Exported Knowledge Graph JSON to {GRAPH_JSON_PATH}")
    else:
        logger.warning("Wazuh API authentication/connection failed.")
        if os.path.exists(GRAPH_JSON_PATH):
            try:
                logger.info(f"Seeding from existing graph snapshot at {GRAPH_JSON_PATH}...")
                with open(GRAPH_JSON_PATH, "r", encoding="utf-8") as f:
                    graph_data = json.load(f)
            except Exception as e:
                logger.error(f"Failed to read existing {GRAPH_JSON_PATH}: {e}")

    # Sync to Neo4j Graph Database
    if graph_data and neo4j_manager.is_connected():
        logger.info("Syncing telemetry graph into Neo4j database...")
        neo4j_manager.sync_graph_data(graph_data)
    else:
        logger.warning("Neo4j database connection unavailable or graph data is empty.")

    return graph_data

if __name__ == "__main__":
    fetch_and_generate_graph()



