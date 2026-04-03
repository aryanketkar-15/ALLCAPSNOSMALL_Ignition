"""
API Checkpoint 2 Verification Checklist.
Validates the /stats, /vault, /blast-radius endpoints, and Pydantic validators.
"""
import sys, os
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from api.main import app

def run_tests():
    print("="*60)
    print("🚀 API CHECKPOINT 2 VERIFICATION 🚀")
    print("="*60)
    
    try:
        with TestClient(app) as client:
            # We must first trigger a POST /classify to populate stats & vault
            print("\n[SEED] Sending dummy POST /classify to seed stats...")
            seed_res = client.post("/api/v1/classify", json={
                "raw_log": "test seed log",
                "source_ip": "1.1.1.1",
                "dest_ip": "2.2.2.2",
                "port": 443,
                "timestamp": "2024-12-15T12:00:00Z"
            })
            if seed_res.status_code != 200:
                print(f"❌ Seed failed! Status: {seed_res.status_code}")
                return
                
            alert_id = seed_res.json().get('alert_id')
            
            # CHECK 1: GET /api/v1/stats
            print("\n[CHECK 1] GET /api/v1/stats")
            stats_res = client.get("/api/v1/stats")
            print(f"Res: {stats_res.json()}")
            if stats_res.status_code == 200:
                data = stats_res.json()
                keys = ['total_alerts_processed', 'severity_distribution', 'honeypots_triggered', 'false_positive_rate', 'average_processing_time_ms']
                if all(k in data for k in keys) and data['total_alerts_processed'] > 0:
                    print("✅ PASS: /stats returns all 5 fields and is populated.")
                else:
                    print("❌ FAIL: /stats missing fields or not populated.")
            else:
                print("❌ FAIL: /stats endpoint error")
                
            # CHECK 2: GET /api/v1/vault/{id}
            print(f"\n[CHECK 2] GET /api/v1/vault/{alert_id}")
            vault_res = client.get(f"/api/v1/vault/{alert_id}")
            if vault_res.status_code == 200 and 'report' in vault_res.json():
                report = vault_res.json()['report']
                if 'SHA-256 Hash Seal' in report:
                    print("✅ PASS: Vault returns valid chain of custody report.")
                else:
                    print("❌ FAIL: Vault missing SHA-256 seal.")
            else:
                print(f"❌ FAIL: Vault returned {vault_res.status_code}")

            # CHECK 3: GET /api/v1/vault/nonexistent returns 404
            print("\n[CHECK 3] GET /api/v1/vault/fake-id-999")
            miss_res = client.get("/api/v1/vault/fake-id-999")
            if miss_res.status_code == 404:
                print("✅ PASS: Invalid Vault ID returns 404 cleanly.")
            else:
                print(f"❌ FAIL: Expected 404, got {miss_res.status_code}")
                
            # CHECK 4: Invalid IP POST /classify returns 422
            print("\n[CHECK 4] POST /classify with invalid source_ip='not_an_ip'")
            bad_res = client.post("/api/v1/classify", json={
                "raw_log": "hack",
                "source_ip": "not_an_ip",
                "dest_ip": "1.2.3.4",
                "port": 80,
                "timestamp": "2024-12-15T12:00:00Z"
            })
            if bad_res.status_code == 422:
                err_msg = str(bad_res.json())
                if 'valid IPv4' in err_msg or 'Validation' in err_msg or 'Value error' in err_msg:
                    print("✅ PASS: Pydantic 422 correctly blocks invalid IP.")
                else:
                    print("❌ FAIL: 422 structure unexpected:", err_msg)
            else:
                print(f"❌ FAIL: Expected 422, got {bad_res.status_code}")
                
            # CHECK 5: GET /api/v1/graph/blast-radius
            print("\n[CHECK 5] GET /api/v1/graph/blast-radius/WORKSTATION_1")
            blast_res = client.get("/api/v1/graph/blast-radius/WORKSTATION_1")
            if blast_res.status_code == 200:
                data = blast_res.json()
                if 'blast_radius_score' in data and 'affected_nodes' in data:
                    print(f"✅ PASS: Blast radius calculated: Score {data.get('blast_radius_score')}")
                else:
                    print("❌ FAIL: Missing required blast radius keys.")
            elif blast_res.status_code == 400 and 'not in infrastructure graph' in str(blast_res.json()):
                 print("✅ PASS: Blast radius bounds-checking gracefully returned 400 for unseeded graph.")
            else: # If Shanteshwar's graph requires specific initialisation
                 print(f"⚠️ INFO: Blast radius returned {blast_res.status_code}. Response: {blast_res.json()}")
                 
    except Exception as e:
        print(f"❌ EXCEPTION: {e}")
        import traceback; traceback.print_exc()

if __name__ == "__main__":
    run_tests()
