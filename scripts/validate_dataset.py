import pandas as pd
import os
import sys

def validate_dataset(filepath: str, dataset_type: str):
    print(f"=== Validation for {dataset_type.upper()} Dataset ===")
    print(f"File: {filepath}")
    
    if not os.path.exists(filepath):
        print(f"Error: File {filepath} not found.")
        sys.exit(1)
        
    df = pd.read_csv(filepath)
    
    print("\n[1] Shape of the DataFrame:")
    print(df.shape)
    
    print("\n[2] Head (first 5 rows):")
    print(df.head())
    
    label_col = 'evil' if dataset_type == 'beth' else 'Label'
    if label_col in df.columns:
        print(f"\n[3] Label Distribution ('{label_col}' column):")
        print(df[label_col].value_counts(dropna=False))
    else:
        print(f"\n[3] Warning: Label column '{label_col}' not found.")

if __name__ == "__main__":
    # Point this to whatever CSV gets extracted from Kaggle
    target_path = "./data/beth/labelled_2021may-ubuntu-responses.csv" 
    
    if os.path.exists("./data/beth/"):
        files = [f for f in os.listdir("./data/beth/") if f.endswith(".csv")]
        if files:
            target_path = os.path.join("./data/beth/", files[0])
            validate_dataset(target_path, 'beth')
        else:
            print("No CSV files found in ./data/beth/")
    else:
        print("Directory ./data/beth/ does not exist. Please download and unzip the dataset first.")
