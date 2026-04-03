"""
Test the IOCExtractor against the real BETH training data.
Runs: import check, extraction on a small sample, false_positive_filter, and benchmark.
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
from ingestion.parser import LogParser
from ingestion.ioc_extractor import IOCExtractor

log = []
def p(msg=""):
    print(msg)
    log.append(msg)

p("=" * 60)
p("TEST 1: IOCExtractor imports without error")
p("=" * 60)
try:
    ext = IOCExtractor()
    p("PASS: IOCExtractor imported and instantiated\n")
except Exception as e:
    p(f"FAIL: {e}\n")
    sys.exit(1)

p("=" * 60)
p("TEST 2: Parse BETH data then extract IOCs (first 1000 rows)")
p("=" * 60)
try:
    parser = LogParser()
    raw_df = pd.read_csv('./data/beth/labelled_training_data.csv', nrows=1000)
    raw_df = raw_df.rename(columns=str.strip)
    # Parse rows into standardised schema
    parsed = raw_df.apply(lambda row: parser.parse(row.to_dict(), 'beth'), axis=1)
    df = pd.DataFrame(parsed.tolist())
    # Carry over BETH structured columns for direct assignment
    df['processName'] = raw_df['processName'].values[:len(df)]

    result = ext.extract_all(df)
    p(f"Shape after extraction: {result.shape}")
    p(f"'iocs' column exists: {'iocs' in result.columns}")
    non_empty = result['iocs'].apply(lambda x: len(x) > 0 if isinstance(x, dict) else False).sum()
    p(f"Rows with at least 1 IOC: {non_empty} / {len(result)}")
    # Show a sample IOC dict
    for i, row in result.iterrows():
        if isinstance(row['iocs'], dict) and len(row['iocs']) > 0:
            p(f"Sample IOC (row {i}): {row['iocs']}")
            break
    p("PASS\n")
except Exception as e:
    p(f"FAIL: {e}")
    import traceback; traceback.print_exc()
    p("")

p("=" * 60)
p("TEST 3: false_positive_filter separates private IPs")
p("=" * 60)
try:
    test_iocs = {
        'ipv4': ['192.168.1.50', '10.0.0.1', '185.220.101.1', '8.8.8.8'],
        'md5': ['d41d8cd98f00b204e9800998ecf8427e']
    }
    filtered = ext.false_positive_filter(test_iocs)
    p(f"Input IPs: {test_iocs['ipv4']}")
    p(f"External (ipv4): {filtered.get('ipv4', [])}")
    p(f"Lateral movement: {filtered.get('lateral_movement', [])}")
    p(f"MD5 preserved: {filtered.get('md5', [])}")
    assert '185.220.101.1' in filtered.get('ipv4', [])
    assert '8.8.8.8' in filtered.get('ipv4', [])
    assert '192.168.1.50' in filtered.get('lateral_movement', [])
    assert '10.0.0.1' in filtered.get('lateral_movement', [])
    p("PASS\n")
except AssertionError as e:
    p(f"FAIL: Assertion failed - {e}\n")
except Exception as e:
    p(f"FAIL: {e}\n")

p("=" * 60)
p("TEST 4: Benchmark on 10,000 BETH rows")
p("=" * 60)
try:
    raw_bench = pd.read_csv('./data/beth/labelled_training_data.csv', nrows=10000)
    raw_bench = raw_bench.rename(columns=str.strip)
    parsed_bench = raw_bench.apply(lambda row: parser.parse(row.to_dict(), 'beth'), axis=1)
    df_bench = pd.DataFrame(parsed_bench.tolist())
    df_bench['processName'] = raw_bench['processName'].values[:len(df_bench)]
    elapsed = ext.benchmark(df_bench)
    p(f"Elapsed: {elapsed:.2f}s\n")
except Exception as e:
    p(f"FAIL: {e}")
    import traceback; traceback.print_exc()
    p("")

p("=" * 60)
p("All IOC tests complete.")

with open("tests/ioc_report.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(log))
p("[Report written to tests/ioc_report.txt]")
