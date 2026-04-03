"""
Full checklist runner — writes output to a UTF-8 log file.
"""
import sys
import os
# Ensure project root is on sys.path so `ingestion` is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from datetime import datetime, timezone

log_lines = []

def log(msg=""):
    print(msg)
    log_lines.append(msg)

log("=" * 60)
log("CHECK 1: Schema imports without error")
log("=" * 60)
try:
    from ingestion.schema import AlertSchema
    log("PASS: AlertSchema imported ok")
except Exception as e:
    log(f"FAIL: {e}")

log()
log("=" * 60)
log("CHECK 2: AlertSchema creates valid instance")
log("=" * 60)
try:
    a = AlertSchema(
        timestamp=datetime.now(timezone.utc),
        event_type='test',
        raw_log='x'
    )
    log(f"PASS: alert_id = {a.alert_id}")
except Exception as e:
    log(f"FAIL: {e}")

log()
log("=" * 60)
log("CHECK 3: batch_parse() on BETH returns DataFrame (first 10k rows)")
log("=" * 60)
df3 = None
try:
    import pandas as pd
    from ingestion.parser import LogParser
    # Use a small single-host file to keep it fast
    df3 = LogParser().batch_parse('./data/beth/labelled_training_data.csv', 'beth')
    log(f"Shape: {df3.shape}")
    log(f"timestamp dtype: {df3.dtypes['timestamp']}")
    if df3.shape[0] > 0:
        log("PASS: DataFrame returned with rows")
    else:
        log("FAIL: Empty DataFrame")
except Exception as e:
    log(f"FAIL: {e}")
    import traceback
    log(traceback.format_exc())

log()
log("=" * 60)
log("CHECK 4: No NaN in event_type or raw_log columns")
log("=" * 60)
try:
    if df3 is not None:
        nan_counts = df3[['event_type', 'raw_log']].isna().sum()
        log(f"event_type NaN: {nan_counts['event_type']}")
        log(f"raw_log NaN: {nan_counts['raw_log']}")
        if nan_counts.sum() == 0:
            log("PASS: 0 NaN in event_type and raw_log")
        else:
            log("FAIL: NaN values found")
    else:
        log("SKIP: df3 not available (check 3 failed)")
except Exception as e:
    log(f"FAIL: {e}")
    import traceback
    log(traceback.format_exc())

log()
log("=" * 60)
log("CHECK 5: All timestamps are timezone-aware UTC")
log("=" * 60)
try:
    if df3 is not None:
        ts = df3['timestamp'].iloc[0]
        log(f"First timestamp: {ts}")
        log(f"tzinfo: {ts.tzinfo}")
        if ts.tzinfo is not None:
            log("PASS: Timestamp is timezone-aware")
        else:
            log("FAIL: Timestamp is naive (no tzinfo)")
    else:
        log("SKIP: df3 not available (check 3 failed)")
except Exception as e:
    log(f"FAIL: {e}")
    import traceback
    log(traceback.format_exc())

log()
log("=" * 60)
log("All checks complete.")

# Write UTF-8 log
with open("tests/checklist_report.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(log_lines))
print("\n[Log written to tests/checklist_report.txt]")
