"""
Script to parse the entire BETH dataset (Training + Testing + Validation) 
and export it to a clean CSV for Aryan's ML model, ensuring positive classes
are included in the dataset.
"""
import sys, os
import pandas as pd
import numpy as np
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ingestion.parser import LogParser
from ingestion.ioc_extractor import IOCExtractor

def export_dataset():
    files_to_parse = [
        './data/beth/labelled_training_data.csv',
        './data/beth/labelled_validation_data.csv',
        './data/beth/labelled_testing_data.csv'   # This one holds the attack labels!
    ]
    output_csv = './data/beth/processed_training_data.csv'
    
    print("="*60)
    print("🚀 GENERATING COMPREHENSIVE ML DATASET FOR ARYAN 🚀")
    print("="*60)

    parser = LogParser()
    all_parsed_dfs = []
    all_raw_procs = []
    
    t_start = time.perf_counter()
    
    for f in files_to_parse:
        if not os.path.exists(f):
            print(f"      ⚠️ Warning: {f} not found, skipping...")
            continue
            
        print(f"[1/3] Reading and batch parsing {f}...")
        t0 = time.perf_counter()
        df = parser.batch_parse(f, 'beth')
        all_parsed_dfs.append(df)
        
        try:
            # We must strip columns for BETH to find processName safely
            raw_cols = pd.read_csv(f)
            raw_cols = raw_cols.rename(columns=str.strip)
            if 'processName' in raw_cols.columns:
                all_raw_procs.append(raw_cols['processName'].values[:len(df)])
            else:
                all_raw_procs.append(np.array([None] * len(df)))
        except Exception as e:
            print(f"      ⚠️ Note: Could not attach processName: {e}")
            all_raw_procs.append(np.array([None] * len(df)))
            
        print(f"      ✅ Parsed {len(df):,} rows from this file in {time.perf_counter() - t0:.1f}s.")

    print("\nConcatenating DataFrames...")
    final_df = pd.concat(all_parsed_dfs, ignore_index=True)
    final_procs = np.concatenate(all_raw_procs)
    final_df['processName'] = final_procs

    print(f"\n[2/3] Extracting IOCs across {len(final_df):,} total rows (this may take ~2-3 mins)...")
    t1 = time.perf_counter()
    extractor = IOCExtractor()
    final_df = extractor.extract_all(final_df)
    print(f"      ✅ IOC Extraction complete in {time.perf_counter() - t1:.1f}s")

    print("\nLabel Distribution in final dataset:")
    print(final_df['label'].value_counts())

    print(f"\n[3/3] Stringifying dictionaries and saving to {output_csv}...")
    final_df['iocs'] = final_df['iocs'].astype(str)
    
    t2 = time.perf_counter()
    final_df.to_csv(output_csv, index=False)
    print(f"      ✅ Saved in {time.perf_counter() - t2:.1f}s")
    
    file_size_mb = os.path.getsize(output_csv) / (1024 * 1024)
    print("="*60)
    print(f"🎉 EXPORT COMPLETE 🎉")
    print(f"Total Time: {time.perf_counter() - t_start:.1f}s")
    print(f"File Path: {output_csv}")
    print(f"File Size: {file_size_mb:.2f} MB")
    print("="*60)

if __name__ == '__main__':
    export_dataset()
