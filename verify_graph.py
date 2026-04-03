from knowledge_graph.graph import KnowledgeGraph
import networkx as nx
import os

g = KnowledgeGraph()

print("=== PLAYBOOK VERIFY CHECKS ===")

# CHECK 1
count = g.graph.number_of_nodes()
status1 = "PASS" if count == 18 else "FAIL"
print(f"CHECK 1 - Node count: {count}  --> {status1}")

# CHECK 2
crits = g.get_critical_nodes()
status2 = "PASS" if set(crits) == {"DB_PROD", "DOMAIN_CTRL"} else "FAIL"
print(f"CHECK 2 - Critical nodes: {crits}  --> {status2}")

# CHECK 3
path = "knowledge_graph/infra_graph.graphml"
size = os.path.getsize(path)
status3 = "PASS" if size > 2048 else "FAIL"
print(f"CHECK 3 - GraphML size: {size} bytes  --> {status3}")

# CHECK 4
edge = g.graph["APP_SERVER"]["DB_PROD"]
status4 = "PASS" if edge["weight"] == 1 and edge["protocol"] == "DB" else "FAIL"
print(f"CHECK 4 - APP_SERVER->DB_PROD edge: {edge}  --> {status4}")

# CHECK 5
G2 = nx.read_graphml(path)
status5 = "PASS" if G2.number_of_nodes() == 18 else "FAIL"
print(f"CHECK 5 - GraphML reload: nodes={G2.number_of_nodes()}  --> {status5}")

all_pass = all(s == "PASS" for s in [status1, status2, status3, status4, status5])
print(f"\nOVERALL: {'ALL CHECKS PASSED' if all_pass else 'SOME CHECKS FAILED'}")
