"""
Unit tests for the Verification Engine to ensure rules and scoring map correctly.
"""
import sys, os
from datetime import datetime, timezone, timedelta
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ingestion.verification import VerificationEngine

log = []
def p(text):
    print(text)
    log.append(text)

p("=" * 60)
p("TEST 1: Init and KB Loader")
p("=" * 60)
try:
    engine = VerificationEngine('./data/test_kb.json')
    assert os.path.exists('./data/test_kb.json')
    assert 'bad_ips' in engine.kb
    p("✅ PASS: Engine initialized and JSON KB safely loaded/created.")
except Exception as e:
    p(f"❌ FAIL: {e}")

p("")
p("=" * 60)
p("TEST 2: Structural Pass (All fields present)")
p("=" * 60)
try:
    valid_alert = {
        'source_ip': '10.0.0.1',
        'event_type': 'ProcessCreation',
        'raw_log': 'foo',
        'timestamp': datetime.now(timezone.utc),
        'protocol': 'tcp'
    }
    c, e = engine._pass_structural(valid_alert)
    assert c == 20
    assert "passed" in e
    p("✅ PASS: Correctly awarded +20 baseline for structural integrity.")
except Exception as e:
    p(f"❌ FAIL: {e}")

p("")
p("=" * 60)
p("TEST 3: IOC Consistency Pass (External to Internal SMB)")
p("=" * 60)
try:
    alert = {
        'dest_ip': '185.220.101.5', # external
        'port': 445, # SMB
        'iocs': {'lateral_movement': ['10.0.0.5']}
    }
    c, e_list = engine._pass_ioc_consistency(alert)
    assert c == 45 # 30 (port targeting) + 15 (lateral movement)
    assert len(e_list) == 2
    p("✅ PASS: Awarded +45 for malicious external port targeting + horizontal move.")
except Exception as e:
    p(f"❌ FAIL: {e}")

p("")
p("=" * 60)
p("TEST 4: Knowledge Base Lookup Match")
p("=" * 60)
try:
    alert = {
        'iocs': {
            'ipv4': ['194.165.16.55', '8.8.8.8'],
            'cve': ['CVE-2017-0144'],
            'process': ['Mimikatz']
        }
    }
    c, e_list = engine._pass_knowledge_base(alert)
    assert c == 90 # 30 (ip) + 30 (cve) + 30 (mimikatz)
    assert len(e_list) == 3
    p("✅ PASS: Detected known bad IP, known CVE, and known Malware perfectly (+90).")
except Exception as e:
    p(f"❌ FAIL: {e}")

p("")
p("=" * 60)
p("TEST 5: Full verify() workflow cap + status mapping")
p("=" * 60)
try:
    god_alert = {
        'source_ip': '10.0.0.1',
        'event_type': 'Process',
        'raw_log': 'x',
        'timestamp': datetime.now(timezone.utc),
        'protocol': 'tcp',
        'dest_ip': '185.220.101.5',
        'port': 3389,
        'iocs': {
            'ipv4': ['45.33.32.99'],
            'cve': ['CVE-2021-44228']
        }
    }
    res = engine.verify(god_alert)
    assert res['confidence_score'] == 100 # Capped at 100 despite earning 110
    assert res['verification_status'] == 'VERIFIED'
    assert len(res['evidence_trail']) == 4
    p("✅ PASS: Perfect verify() cap and 'VERIFIED' status routing.")
except Exception as e:
    p(f"❌ FAIL: {e}")
    import traceback; traceback.print_exc()

import shutil
if os.path.exists('./data/test_kb.json'):
    os.remove('./data/test_kb.json')
