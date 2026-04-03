"""
Checkpoint 1 - End-to-End full pipeline validation.
Runs a pure sequence: Parse CSV -> Extract IOCs -> Verify single alert.
"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
import pandas as pd
from ingestion.parser import LogParser
from ingestion.ioc_extractor import IOCExtractor
from ingestion.verification import VerificationEngine

def run_integration():
    print("="*60)
    print("CHECKPOINT 1: FULL PIPELINE INTEGRATION TEST")
    print("="*60)
    
    try:
        t0 = time.perf_counter()
        # 1. Parse
        print("1. Parsing BETH Data (100 rows)...")
        parser = LogParser()
        raw_df = pd.read_csv('./data/beth/labelled_training_data.csv', nrows=100)
        raw_df = raw_df.rename(columns=str.strip)
        parsed_df = pd.DataFrame(raw_df.apply(lambda r: parser.parse(r.to_dict(), 'beth'), axis=1).tolist())
        parsed_df['processName'] = raw_df['processName'].values[:len(parsed_df)]
        
        # 2. Extract IOCs
        print("2. Extracting IOCs...")
        extractor = IOCExtractor()
        extracted_df = extractor.extract_all(parsed_df)
        
        # 3. Verify
        print("3. Verifying Results (Running Verification Engine)...")
        engine = VerificationEngine()
        
        results = []
        for index, row in extracted_df.iterrows():
            # Convert row to dict
            alert_dict = row.to_dict()
            v_res = engine.verify(alert_dict)
            results.append(v_res)
            
        print(f"✅ Successfully passed {len(results)} rows through all 3 stages without exception.")
        print(f"Total time elapsed: {time.perf_counter() - t0:.2f} seconds.")
        print("="*60)
        print("CHECKPOINT 1 OFFICIALLY CLEAR!")
        
    except Exception as e:
        print(f"❌ PIPELINE FAILURE: {e}")
        import traceback; traceback.print_exc()

if __name__ == '__main__':
    run_integration()
