"""
Knowledge Graph — Infrastructure Topology
Threat Intelligence Pillar | Team SY-A9 | Shanteshwar
"""

import os
import networkx as nx


# GraphML output path (relative to repo root)
GRAPHML_PATH = os.path.join(os.path.dirname(__file__), "infra_graph.graphml")


class KnowledgeGraph:
    """
    Represents the organisation's infrastructure as a directed weighted graph.
    Nodes are network assets; edge weights model lateral movement difficulty
    (lower weight = easier for an attacker to traverse).
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self._build_topology()
        self._persist()

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    def _build_topology(self):
        """Hardcode the 18-node corporate topology defined in the playbook."""

        # ── NODES ──────────────────────────────────────────────────────
        self.graph.add_node("INTERNET_GW",   node_type="INTERNET_GATEWAY", critical_asset=False)
        self.graph.add_node("FIREWALL_1",    node_type="SERVER",            critical_asset=False)
        self.graph.add_node("WEB_SERVER",    node_type="SERVER",            critical_asset=False)
        self.graph.add_node("APP_SERVER",    node_type="SERVER",            critical_asset=False)
        self.graph.add_node("DB_PROD",       node_type="DATABASE",          critical_asset=True)
        self.graph.add_node("DOMAIN_CTRL",   node_type="DOMAIN_CONTROLLER", critical_asset=True)
        self.graph.add_node("BACKUP_SERVER", node_type="SERVER",            critical_asset=False)
        self.graph.add_node("SIEM_SERVER",   node_type="SERVER",            critical_asset=False)
        self.graph.add_node("JUMP_BOX",      node_type="SERVER",            critical_asset=False)
        self.graph.add_node("HONEYPOT_1",    node_type="HONEYPOT",          critical_asset=False)
        self.graph.add_node("HONEYPOT_2",    node_type="HONEYPOT",          critical_asset=False)
        # Extra realistic nodes to reach 18-node topology (playbook §3.1)
        self.graph.add_node("HR_SERVER",     node_type="SERVER",            critical_asset=False)
        self.graph.add_node("FINANCE_WS",    node_type="WORKSTATION",       critical_asset=False)

        # WS_1 – WS_5
        for i in range(1, 6):
            self.graph.add_node(f"WS_{i}", node_type="WORKSTATION", critical_asset=False)

        # ── EDGES ──────────────────────────────────────────────────────
        # Internet entry points
        self.graph.add_edge("INTERNET_GW", "FIREWALL_1",   weight=4, protocol="SSH")
        self.graph.add_edge("INTERNET_GW", "HONEYPOT_1",   weight=3, protocol="RDP")
        self.graph.add_edge("INTERNET_GW", "HONEYPOT_2",   weight=4, protocol="SSH")

        # Core server chain
        self.graph.add_edge("FIREWALL_1",  "WEB_SERVER",   weight=3, protocol="RDP")
        self.graph.add_edge("WEB_SERVER",  "APP_SERVER",   weight=2, protocol="SMB")
        self.graph.add_edge("APP_SERVER",  "DB_PROD",      weight=1, protocol="DB")
        self.graph.add_edge("APP_SERVER",  "DOMAIN_CTRL",  weight=2, protocol="SMB")
        self.graph.add_edge("APP_SERVER",  "BACKUP_SERVER",weight=2, protocol="SMB")

        # Domain controller → workstations
        for i in range(1, 6):
            self.graph.add_edge("DOMAIN_CTRL", f"WS_{i}", weight=3, protocol="RDP")

        # Workstations → app server (lateral movement back path)
        for i in range(1, 6):
            self.graph.add_edge(f"WS_{i}", "APP_SERVER", weight=2, protocol="SMB")

        # Jump box direct access
        self.graph.add_edge("JUMP_BOX", "DOMAIN_CTRL", weight=2, protocol="SMB")
        self.graph.add_edge("JUMP_BOX", "DB_PROD",     weight=1, protocol="DB")

        # SIEM monitoring link
        self.graph.add_edge("SIEM_SERVER", "APP_SERVER", weight=4, protocol="SSH")

        # HR and finance nodes (additional realism)
        self.graph.add_edge("DOMAIN_CTRL", "HR_SERVER",  weight=3, protocol="RDP")
        self.graph.add_edge("DOMAIN_CTRL", "FINANCE_WS", weight=3, protocol="RDP")

    def _persist(self):
        """Write the graph to GraphML for reproducibility."""
        nx.write_graphml(self.graph, GRAPHML_PATH)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_critical_nodes(self) -> list:
        """Return a list of node IDs where critical_asset=True."""
        return [
            node
            for node, attrs in self.graph.nodes(data=True)
            if attrs.get("critical_asset") is True
        ]

    def get_node_type(self, node_id: str) -> str:
        """Return the node_type attribute for a given node."""
        return self.graph.nodes[node_id].get("node_type", "UNKNOWN")

    def summary(self) -> dict:
        """Quick sanity summary for verification."""
        return {
            "total_nodes": nx.number_of_nodes(self.graph),
            "total_edges": nx.number_of_edges(self.graph),
            "critical_nodes": self.get_critical_nodes(),
        }


# ------------------------------------------------------------------
# Quick smoke-test when run directly
# ------------------------------------------------------------------
if __name__ == "__main__":
    kg = KnowledgeGraph()
    print(kg.summary())
    print("GraphML written to:", GRAPHML_PATH)
