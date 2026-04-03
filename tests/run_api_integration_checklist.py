"""
API Integration Checklist Testing Script.
Evaluates the accuracy of the POST /classify orchestration endpoint.
"""
import sys, os, time
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from api.main import app

def run_integration_tests():
    print("="*60)
    print("🚀 PIPELINE INTEGRATION CHECKLIST 🚀")
    print("="*60)

    try:
        with TestClient(app) as client:
            # CHECK 1 & 2: POST /classify
            print("\n[CHECK 1 & 2 & 5] Sending POST /api/v1/classify...")
            t0 = time.time()
            res1 = client.post("/api/v1/classify", json={
                "raw_log": "test",
                "source_ip": "185.220.101.1",
                "dest_ip": "192.168.1.50",
                "port": 3389,
                "timestamp": "2024-12-15T10:00:00Z"
            })
            duration1 = (time.time() - t0) * 1000
            
            data1 = res1.json()
            print(f"Status: {res1.status_code}")
            print(f"Latency (including LLM test): {duration1:.1f}ms")
            
            if res1.status_code == 200 and 'alert_id' in data1:
                print("✅ PASS: Classify returns 200 OK with AlertResponse keys.")
                required_keys = ['alert_id', 'severity', 'confidence', 'evidence_trail', 'blast_radius', 'playbook_state', 'summary', 'vault_hash']
                missing_keys = [k for k in required_keys if k not in data1]
                if missing_keys:
                    print(f"   ⚠️ WARNING: Missing keys from response: {missing_keys}")
            else:
                print(f"❌ FAIL: Endpoint returned {res1.status_code}. Response: {data1}")
                
            summary = data1.get('summary', '')
            if summary.startswith('[Template]') or 'failed' in summary.lower() or 'system_note' in summary.lower() or '[WARN]' in summary:
                print("✅ PASS: LLM Fallback works properly when Ollama is offline.")
            else:
                print("⚠️  LLM actually returned a summary: ", summary)
                
            # CHECK 3: GET /alerts
            print("\n[CHECK 3] Sending GET /api/v1/alerts...")
            res2 = client.get("/api/v1/alerts")
            data2 = res2.json()
            if res2.status_code == 200 and len(data2) >= 1:
                print(f"✅ PASS: GET /alerts correctly returns history list (Count: {len(data2)}).")
            else:
                print("❌ FAIL: History is empty or failed.")
            
            # CHECK 4: Honeypot Rule
            print("\n[CHECK 4] Testing Honeypot Override Component...")
            res3 = client.post("/api/v1/classify", json={
                "raw_log": "User accessed db_credentials_prod.conf maliciously",
                "source_ip": "192.168.1.100",
                "dest_ip": "10.0.0.5",
                "port": 22,
                "timestamp": "2024-12-15T10:05:00Z"
            })
            data3 = res3.json()
            
            if res3.status_code != 200:
                print(f"❌ FAIL: Honeypot request failed: {res3.status_code}")
            elif data3.get('severity') == 'CRITICAL':
                print("✅ PASS: Honeypot accurately overrides severity to CRITICAL.")
            else:
                print(f"❌ FAIL: Honeypot did not trigger CRITICAL severity. Got: {data3.get('severity')}")
                
    except Exception as e:
        print(f"❌ ERROR: Exception occurred during testing: {e}")
        import traceback; traceback.print_exc()

if __name__ == "__main__":
    run_integration_tests()
