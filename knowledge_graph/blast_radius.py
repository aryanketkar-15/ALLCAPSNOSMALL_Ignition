"""
Blast Radius Analyser — Pre-Computed Sub-Millisecond Path Lookups
Threat Intelligence Pillar | Team SY-A9 | Shanteshwar
"""

import time
from datetime import datetime, timedelta, timezone
from collections import defaultdict

import networkx as nx

from knowledge_graph.graph import KnowledgeGraph


class BlastRadiusAnalyser:
    """
    Pre-computes all-pairs Dijkstra at startup so that every query-time
    lookup is an O(1) dict access (sub-millisecond).
    """

    def __init__(self):
        kg = KnowledgeGraph()
        self.graph = kg.graph
        self.critical_nodes = kg.get_critical_nodes()

        # ── PRE-COMPUTE all shortest paths at startup ──────────────
        # dict structure: { source: (distances_dict, paths_dict) }
        self.all_paths = dict(
            nx.all_pairs_dijkstra(self.graph, weight="weight")
        )

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def calculate(self, compromised_node: str, alert_history: list = None) -> dict:
        """
        Compute the blast radius for a compromised node.

        Parameters
        ----------
        compromised_node : str
            Node ID of the compromised asset.
        alert_history : list[dict], optional
            Recent alerts with keys: source_ip, dest_node, timestamp (ISO 8601).

        Returns
        -------
        dict with blast_radius_score, affected_nodes, path_to_nearest_critical,
        movement_pattern, nearest_critical_node, nearest_critical_distance.
        """

        # Guard: unknown node → safe default, never crash
        if compromised_node not in self.graph:
            return {
                "blast_radius_score": 0.0,
                "affected_nodes": [],
                "path_to_nearest_critical": [],
                "movement_pattern": "UNKNOWN",
                "nearest_critical_node": None,
                "nearest_critical_distance": float("inf"),
            }

        lengths, paths = self.all_paths[compromised_node]

        # ── Affected nodes (all reachable from compromised_node) ───
        affected_nodes = list(lengths.keys())

        # ── Blast radius score ─────────────────────────────────────
        score = 0.0
        nearest_critical_node = None
        nearest_critical_distance = float("inf")
        path_to_nearest_critical = []

        for crit in self.critical_nodes:
            if crit in lengths:
                dist = lengths[crit]
                if dist > 0:
                    score += 1.0 / dist
                # Track nearest critical asset
                if dist < nearest_critical_distance:
                    nearest_critical_distance = dist
                    nearest_critical_node = crit
                    path_to_nearest_critical = paths.get(crit, [])

        # ── Temporal lateral movement detection ────────────────────
        movement_pattern = "DIRECT_ATTACK"

        if alert_history:
            movement_pattern = self._detect_lateral_movement(alert_history)

        # Apply 1.5x multiplier for lateral movement
        if movement_pattern == "LATERAL_MOVEMENT":
            score *= 1.5

        return {
            "blast_radius_score": round(score, 4),
            "affected_nodes": affected_nodes,
            "path_to_nearest_critical": path_to_nearest_critical,
            "movement_pattern": movement_pattern,
            "nearest_critical_node": nearest_critical_node,
            "nearest_critical_distance": nearest_critical_distance,
        }

    # ------------------------------------------------------------------
    # Lateral movement detection
    # ------------------------------------------------------------------

    def _detect_lateral_movement(self, alert_history: list) -> str:
        """
        If the same source_ip has hit 3+ DIFFERENT dest_nodes in the
        last 10 minutes → LATERAL_MOVEMENT, else DIRECT_ATTACK.
        """
        now = datetime.now(timezone.utc)
        window = timedelta(minutes=10)

        ip_destinations = defaultdict(set)

        for alert in alert_history:
            src_ip = alert.get("source_ip", "")
            dest = alert.get("dest_node", "")
            ts_raw = alert.get("timestamp", "")

            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                continue

            if now - ts <= window:
                ip_destinations[src_ip].add(dest)

        # Any IP hitting 3+ distinct destinations → lateral movement
        for destinations in ip_destinations.values():
            if len(destinations) >= 3:
                return "LATERAL_MOVEMENT"

        return "DIRECT_ATTACK"

    # ------------------------------------------------------------------
    # Performance verification
    # ------------------------------------------------------------------

    def verify_precompute_speed(self):
        """Confirm a single lookup takes under 1ms."""
        node = list(self.graph.nodes())[0]

        start = time.perf_counter()
        _ = self.all_paths[node]
        elapsed_ms = (time.perf_counter() - start) * 1000

        status = "PASS" if elapsed_ms < 1.0 else "FAIL"
        print(f"Lookup time: {elapsed_ms:.4f}ms — {status} (threshold: < 1.000ms)")
        return elapsed_ms


# ------------------------------------------------------------------
# Quick smoke-test when run directly
# ------------------------------------------------------------------
if __name__ == "__main__":
    b = BlastRadiusAnalyser()
    print("Pre-computed paths for", len(b.all_paths), "nodes")
    b.verify_precompute_speed()
    result = b.calculate("WS_1")
    print("\nBlast radius for WS_1:")
    for k, v in result.items():
        print(f"  {k}: {v}")
