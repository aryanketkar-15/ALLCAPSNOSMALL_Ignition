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

    def calculate(self, compromised_node: str) -> dict:
        """
        Compute the blast radius for a compromised node.
        """

        # Guard: unknown node
        if compromised_node not in self.graph:
            return {
                "blast_radius_score": 0.0,
                "affected_nodes": [],
                "path_to_nearest_critical": [],
                "movement_pattern": "UNKNOWN"
            }

        lengths, paths = self.all_paths[compromised_node]
        affected_nodes = list(lengths.keys())

        # ── Blast radius score ─────────────────────────────────────
        score = 0.0
        nearest_critical_node = None
        nearest_critical_distance = float("inf")
        path_to_nearest_critical = []

        for crit in self.critical_nodes:
            if crit in lengths:
                dist = lengths[crit]
                score += 1.0 / (dist + 1.0)
                # Track nearest critical asset
                if dist < nearest_critical_distance:
                    nearest_critical_distance = dist
                    nearest_critical_node = crit
                    path_to_nearest_critical = paths.get(crit, [])

        movement_pattern = "LATERAL_MOVEMENT" if len(affected_nodes) > 1 else "DIRECT_ATTACK"

        return {
            "blast_radius_score": round(score, 4),
            "affected_nodes": affected_nodes,
            "path_to_nearest_critical": path_to_nearest_critical,
            "movement_pattern": movement_pattern
        }

    def simulate_path(self, source_node: str, target_node: str) -> dict:
        """
        Simulate an attack path between source and target node.
        """
        if source_node not in self.graph or target_node not in self.graph:
            return {"hops": 0, "path": [], "risk_exposure": 0.0}
            
        lengths, paths = self.all_paths[source_node]
        if target_node not in lengths:
            return {"hops": 0, "path": [], "risk_exposure": 0.0}
            
        path = paths[target_node]
        hops = max(0, len(path) - 1)
        dist = lengths[target_node]
        
        # Calculate risk exposure on 0-100 scale (closer distance = higher exposure)
        risk_exposure = max(0.0, 100.0 - (dist * 10))
        
        return {
            "hops": hops,
            "path": path,
            "risk_exposure": round(risk_exposure, 2)
        }

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
    
    sim = b.simulate_path("INTERNET_GW", "DB_PROD")
    print("\nSimulation INTERNET_GW -> DB_PROD:")
    print(sim)
