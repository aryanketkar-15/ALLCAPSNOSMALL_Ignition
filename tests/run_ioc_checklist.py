"""
Verification checklist runner for IOCExtractor (Prompt 2).
Uses the BETH dataset instead of UNSW because UNSW is not present locally.
"""
import sys
import os
import time
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ingestion.ioc_extractor import IOCExtractor

log_lines = []
def log(msg=""):
    print(msg)
    log_lines.append(msg)

# Setup dataset
BETH_FILE = './data/beth/labelled_training_data.csv'

log("=" * 60)
log("CHECK 1: extract_all() on 1,000 rows completes under 500ms")
log("=" * 60)
try:
    df1 = pd.read_csv(BETH_FILE, nrows=1000)
    # The BETH dataset requires 'raw_log' column. The LogParser would normally create it, 
    # but the instructions test extractall directly with pd.read_csv. Let's create 'raw_log' 
    # artificially for the test exactly how LogParser does it:
    df1['raw_log'] = df1.apply(lambda row: str(row.to_dict()), axis=1)
    
    e1 = IOCExtractor()
    t1 = time.perf_counter()
    e1.extract_all(df1)
    elapsed1 = time.perf_counter() - t1
    
    log(f"Elapsed: {elapsed1:.3f}s")
    if elapsed1 < 0.500:
        log("✅ PASS")
    else:
        log("❌ FAIL: Took longer than 500ms")
except Exception as e:
    log(f"❌ FAIL: {e}")

log("")
log("=" * 60)
log("CHECK 2: iocs column is a dict per row")
log("=" * 60)
try:
    df2 = pd.read_csv(BETH_FILE, nrows=100)
    df2['raw_log'] = df2.apply(lambda row: str(row.to_dict()), axis=1)
    
    r2 = IOCExtractor().extract_all(df2)
    iocs_type = type(r2['iocs'].iloc[0])
    log(f"Type: {iocs_type}")
    if issubclass(iocs_type, dict):
        log("✅ PASS")
    else:
        log("❌ FAIL: Not a dict")
except Exception as e:
    log(f"❌ FAIL: {e}")

log("")
log("=" * 60)
log("CHECK 3: RFC 1918 filter strips private IPs to lateral_movement key")
log("=" * 60)
try:
    e3 = IOCExtractor()
    r3 = e3.false_positive_filter({'ipv4': ['192.168.1.50', '185.220.101.1']})
    log(f"Result: {r3}")
    if '192.168.1.50' in r3.get('lateral_movement', []) and '185.220.101.1' in r3.get('ipv4', []) and '192.168.1.50' not in r3.get('ipv4', []):
         log("✅ PASS")
    else:
         log("❌ FAIL: IPs not separated correctly")
except Exception as e:
    log(f"❌ FAIL: {e}")

log("")
log("=" * 60)
log("CHECK 4: Known external IP stays in ipv4 bucket")
log("=" * 60)
try:
    e4 = IOCExtractor()
    r4 = e4.false_positive_filter({'ipv4': ['185.220.101.1']})
    res_lat = r4.get('lateral_movement', 'clean')
    log(f"Result lateral_movement: {res_lat}")
    if res_lat == 'clean' and '185.220.101.1' in r4.get('ipv4', []):
        log("✅ PASS")
    else:
        log("❌ FAIL: External IP moved or lateral_movement exists")
except Exception as e:
    log(f"❌ FAIL: {e}")

log("")
log("=" * 60)
log("CHECK 5: Benchmark prints result under 3s on 10k rows")
log("=" * 60)
try:
    df5 = pd.read_csv(BETH_FILE, nrows=10000)
    df5['raw_log'] = df5.apply(lambda row: str(row.to_dict()), axis=1)
    e5 = IOCExtractor()
    # Capturing stdout to check if WARNING line prints
    from io import StringIO
    captured_out = StringIO()
    original_out = sys.stdout
    sys.stdout = captured_out
    e5.benchmark(df5)
    sys.stdout = original_out
    
    out_val = captured_out.getvalue()
    log("Benchmark output:")
    for l in out_val.splitlines():
        log("  > " + l)
        
    if "WARNING" not in out_val and "IOC extraction:" in out_val:
        # Check elapsed time explicitly as well
        time_str = [l for l in out_val.splitlines() if "IOC extraction:" in l][0]
        # "IOC extraction: X.XXs for 10,000 rows"
        time_float = float(time_str.split(" ")[2].replace("s", ""))
        if time_float < 3.0:
            log("✅ PASS: Under 3s and no warning")
        else:
            log("❌ FAIL: Time > 3s")
    else:
        log("❌ FAIL: Warning line found or format incorrect")
except Exception as e:
    sys.stdout = original_out
    log(f"❌ FAIL: {e}")

log("")
log("All checks complete.")

with open('tests/ioc_checklist_report.txt', 'w', encoding='utf-8') as f:
    f.write("\n".join(log_lines))
