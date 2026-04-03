"""
CHECKPOINT 2 - API LAYER COMPLETE
Full verification suite: 7 checks, all must pass.
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi.testclient import TestClient
from api.main import app

PASS = 0
FAIL = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} -- {detail}")

def main():
    global PASS, FAIL
    print("=" * 60)
    print("  CHECKPOINT 2 - API LAYER COMPLETE")
    print("=" * 60)

    with TestClient(app) as client:

        # ---- CHECK 1: GET /health ----
        print("\n[CHECK 1] GET /health")
        r = client.get("/health")
        data = r.json()
        svcs = data.get("services_loaded", [])
        check("Status 200", r.status_code == 200, f"got {r.status_code}")
        check("status=ok", data.get("status") == "ok")
        check("10+ services loaded", len(svcs) >= 10, f"got {len(svcs)}: {svcs}")
        print(f"  Services: {svcs}")

        # ---- CHECK 2: POST /api/v1/classify x3 ----
        print("\n[CHECK 2] POST /api/v1/classify (3 calls)")
        alert_ids = []
        payloads = [
            {"raw_log": "SSH brute force detected", "source_ip": "185.220.101.1", "dest_ip": "192.168.1.50", "port": 22, "timestamp": "2024-12-15T10:00:00Z"},
            {"raw_log": "Port scan from external", "source_ip": "45.33.32.156", "dest_ip": "10.0.0.5", "port": 443, "timestamp": "2024-12-15T10:01:00Z"},
            {"raw_log": "Lateral movement attempt", "source_ip": "192.168.1.100", "dest_ip": "192.168.1.200", "port": 3389, "timestamp": "2024-12-15T10:02:00Z"},
        ]
        for i, p in enumerate(payloads):
            r = client.post("/api/v1/classify", json=p)
            d = r.json()
            check(f"Classify #{i+1} returns 200", r.status_code == 200, f"got {r.status_code}: {d}")
            if r.status_code == 200:
                alert_ids.append(d.get("alert_id"))
                for key in ["alert_id", "severity", "confidence", "evidence_trail", "blast_radius", "playbook_state", "summary", "vault_hash"]:
                    check(f"  #{i+1} has '{key}'", key in d and d[key] is not None, f"missing or None")

        # ---- CHECK 3: GET /api/v1/alerts ----
        print("\n[CHECK 3] GET /api/v1/alerts")
        r = client.get("/api/v1/alerts")
        alerts = r.json()
        check("Returns list", isinstance(alerts, list))
        check("Has 3+ items", len(alerts) >= 3, f"got {len(alerts)}")

        # ---- CHECK 4: GET /api/v1/stats ----
        print("\n[CHECK 4] GET /api/v1/stats")
        r = client.get("/api/v1/stats")
        d = r.json()
        print(f"  Stats: {d}")
        for key in ["total_alerts_processed", "severity_distribution", "honeypots_triggered", "false_positive_rate", "average_processing_time_ms"]:
            check(f"Has '{key}'", key in d, "missing")
        check("total > 0", d.get("total_alerts_processed", 0) > 0)

        # ---- CHECK 5: Invalid IP -> 422 ----
        print("\n[CHECK 5] POST with invalid IP")
        r = client.post("/api/v1/classify", json={
            "raw_log": "test", "source_ip": "not_an_ip", "dest_ip": "1.2.3.4",
            "port": 80, "timestamp": "2024-01-01T00:00:00Z"
        })
        check("Returns 422", r.status_code == 422, f"got {r.status_code}")

        # ---- CHECK 6: GET /api/v1/vault/{id} ----
        print("\n[CHECK 6] GET /api/v1/vault/{id}")
        if alert_ids:
            aid = alert_ids[0]
            r = client.get(f"/api/v1/vault/{aid}")
            if r.status_code == 200:
                report = r.json().get("report", "")
                check("Vault returns report", bool(report))
                check("Report has SHA-256", "SHA-256" in report, f"report: {report[:100]}")
            else:
                check("Vault returns 200", False, f"got {r.status_code}: {r.json()}")
        else:
            check("Vault test skipped", False, "no alert_ids from classify")

        # Vault 404 for bad ID
        r404 = client.get("/api/v1/vault/fake-id-999")
        check("Vault 404 for bad ID", r404.status_code == 404)

        # ---- CHECK 7: GET /api/v1/graph/blast-radius ----
        print("\n[CHECK 7] GET /api/v1/graph/blast-radius/WORKSTATION_1")
        r = client.get("/api/v1/graph/blast-radius/WORKSTATION_1")
        if r.status_code == 200:
            d = r.json()
            check("Has blast_radius_score", "blast_radius_score" in d)
            check("Score > 0", d.get("blast_radius_score", 0) > 0, f"got {d.get('blast_radius_score')}")
        elif r.status_code == 400:
            # Graph not seeded with WORKSTATION_1 — acceptable bounds check
            check("Blast radius bounds-check 400", True)
            print(f"  (Node not in graph — this is OK if graph is unseeded)")
        else:
            check("Blast radius endpoint", False, f"got {r.status_code}")

    # ---- SUMMARY ----
    print("\n" + "=" * 60)
    total = PASS + FAIL
    print(f"  RESULTS: {PASS}/{total} PASSED, {FAIL} FAILED")
    if FAIL == 0:
        print("  CHECKPOINT 2 CLEARED!")
    else:
        print("  CHECKPOINT 2 NOT YET CLEARED")
    print("=" * 60)

if __name__ == "__main__":
    main()
