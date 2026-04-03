"""
Verification Engine Checklist Runner.
Runs the 5 playbook tests before Checkpoint 1.
"""
import sys, os
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ingestion.verification import VerificationEngine

log_lines = []
def log(msg=""):
    print(msg)
    log_lines.append(msg)

engine = VerificationEngine()
# Artificially set a timestamp for tests that structurally pass
valid_ts = datetime.now(timezone.utc)

log("=" * 60)
log("CHECK 1: verify() returns dict with all 3 required keys")
log("=" * 60)
try:
    r1 = engine.verify({'source_ip':'1.2.3.4','dest_ip':'192.168.1.50','port':3389,'event_type':'login','raw_log':'test','iocs':{}, 'timestamp': valid_ts, 'protocol': 'tcp'})
    keys = list(r1.keys())
    log(f"Keys returned: {keys}")
    if all(k in keys for k in ['verification_status', 'confidence_score', 'evidence_trail']):
        log("✅ PASS")
    else:
        log("❌ FAIL")
except Exception as e:
    log(f"❌ FAIL: {e}")

log("")
log("=" * 60)
log("CHECK 2: Known-bad IP returns confidence >= 70 (VERIFIED)")
log("=" * 60)
try:
    r2 = engine.verify({'source_ip':'185.220.101.5','dest_ip':'10.0.0.1','port':3389,'event_type':'rdp','raw_log':'test','iocs':{'ipv4':['185.220.101.5']}, 'timestamp': valid_ts, 'protocol': 'rdp'})
    c_score = r2['confidence_score']
    status = r2['verification_status']
    log(f"Confidence: {c_score}, Status: {status}")
    if c_score >= 70 and status == 'VERIFIED':
        log("✅ PASS")
    else:
        log("❌ FAIL")
except Exception as e:
    log(f"❌ FAIL: {e}")

log("")
log("=" * 60)
log("CHECK 3: evidence_trail is non-empty list of strings")
log("=" * 60)
try:
    r3 = engine.verify({'source_ip':'8.8.8.8','dest_ip':'192.168.1.1','port':445,'event_type':'smb','raw_log':'test','iocs':{}, 'timestamp': valid_ts, 'protocol': 'smb'})
    e_trail = r3['evidence_trail']
    log(f"Evidence trail: {e_trail}")
    if isinstance(e_trail, list) and len(e_trail) >= 1 and isinstance(e_trail[0], str):
        log("✅ PASS")
    else:
         log("❌ FAIL")
except Exception as e:
    log(f"❌ FAIL: {e}")

log("")
log("=" * 60)
log("CHECK 4: Private-IP-only benign alert returns FALSE_POSITIVE")
log("=" * 60)
try:
    # No structural points by missing timestamp explicitly to keep score below 30 if needed,
    # but even with +20 it stays <30. Let's give it structure points to be fair:
    r4 = engine.verify({'source_ip':'192.168.1.10','dest_ip':'192.168.1.20','port':80,'event_type':'http','raw_log':'normal','iocs':{}, 'timestamp': valid_ts, 'protocol': 'http'})
    status = r4['verification_status']
    score = r4['confidence_score']
    log(f"Status: {status} (Score: {score})")
    if status == 'FALSE_POSITIVE':
        log("✅ PASS")
    else:
        log("❌ FAIL")
except Exception as e:
    log(f"❌ FAIL: {e}")

log("")
log("=" * 60)
log("CHECK 5: honeypot_boost param correctly elevates confidence")
log("=" * 60)
try:
    r5 = engine.verify({'source_ip':'1.2.3.4','dest_ip':'10.0.0.1','port':80,'event_type':'http','raw_log':'test','iocs':{}, 'timestamp': valid_ts, 'protocol': 'http'}, honeypot_boost=50)
    score = r5['confidence_score']
    status = r5['verification_status']
    log(f"Score with boost: {score}")
    if score >= 70:
        log("✅ PASS")
    else:
         log("❌ FAIL")
except Exception as e:
    log(f"❌ FAIL: {e}")

log("")
log("All checks complete.")

with open('tests/verification_checklist_report.txt', 'w', encoding='utf-8') as f:
    f.write("\n".join(log_lines))
