"""
API Application Shell Checklist Runner.
Verifies the FastAPI router scaffolding tests before Prompt 5.
"""
import sys, os
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from api.main import app

def run_checks():
    log_lines = []
    def log(msg=""):
        print(msg)
        log_lines.append(msg)
        
    log("=" * 60)
    log("Starting API Checklist Tests")
    log("=" * 60)
    
    # Context manager triggers the @app.on_event('startup') hooks automatically
    try:
        with TestClient(app) as client:
            log("CHECK 1 & 2 & 5: Health Endpoint & Services Loaded")
            response = client.get("/health")
            log(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                services = data.get('services_loaded', [])
                log(f"Response: {data}")
                expected_count = 10 # Prompt requires 10 (or 11 if KB included)
                log(f"Services Load Count: {len(services)}")
                
                # Check for any missing services
                all_expected = ['parser', 'ioc', 'verifier', 'classifier', 'blast', 'honeypot', 'kg', 'playbook', 'llm', 'vault', 'cacao']
                missing = [s for s in all_expected if s not in services]
                if not missing:
                    log("✅ ALL SERIVCES LOADED SUCCESSFULLY WITHOUT ANY NULLS OR MISSING MODULES!")
                else:
                    log(f"❌ FAIL: Missing services: {missing}")
            else:
                log("❌ FAIL: Health endpoint failed")
                
            log("\nCHECK 3 & 4: Swagger Docs and CORS Headers")
            # Docs
            docs_resp = client.get("/docs")
            if "SOC AI Classification System" in docs_resp.text:
                log("✅ PASS: Swagger Docs are up and correctly titled.")
            else:
                log("❌ FAIL: Swagger Docs Title Mismatch")
                
            # CORS
            opts_resp = client.options("/health", headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET"
            })
            cors_origin = opts_resp.headers.get("access-control-allow-origin")
            if cors_origin == "*":
                 log("✅ PASS: CORS Middleware correctly intercepts and assigns Origin: * header.")
            else:
                 log(f"❌ FAIL: CORS error (got origin: {cors_origin})")
                 
    except Exception as e:
        log(f"❌ EXCEPT: Failed running tests: {e}")
        import traceback; traceback.print_exc()

if __name__ == "__main__":
    run_checks()
