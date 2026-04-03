import sys
import pandas as pd


DATASET_CONFIGS = {
    "beth": {
        "path": "data/beth/processed_training_data.csv",
        "feature_cols": [
            "severity_raw",
            "event_type", "processName",
        ],
        "cat_cols": ["event_type", "processName"],
        "target": "label",
    },
    "unsw": {
        "path": "data/unsw/UNSW_NB15_training-set.csv",
        "feature_cols": [
            "dur", "sbytes", "dbytes", "sttl", "dttl",
            "sloss", "dloss", "sload", "dload", "spkts", "dpkts",
            "smeansz", "dmeansz", "ct_srv_src", "ct_state_ttl",
            "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
            "ct_dst_src_ltm", "proto", "service", "state",
        ],
        "cat_cols": ["proto", "service", "state"],
        "target": "label",
    },
}


class DatasetLoader:
    """Loads and validates BETH or UNSW-NB15 alert datasets."""

    def __init__(self, dataset: str):
        dataset = dataset.lower()
        if dataset not in DATASET_CONFIGS:
            raise ValueError(
                f"Unknown dataset '{dataset}'. Choose 'beth' or 'unsw'."
            )
        cfg = DATASET_CONFIGS[dataset]
        self.dataset = dataset
        self.path = cfg["path"]
        self.feature_cols = cfg["feature_cols"]
        self.cat_cols = cfg["cat_cols"]
        self.target = cfg["target"]

    def load(self) -> pd.DataFrame:
        """Reads CSV with encoding fallback, drops null labels, fills numeric NaNs with median."""
        try:
            df = pd.read_csv(self.path)
        except UnicodeDecodeError:
            try:
                print("[DatasetLoader] UTF-8 failed — retrying with latin-1 encoding.")
                df = pd.read_csv(self.path, encoding="latin-1")
            except UnicodeDecodeError:
                print("[DatasetLoader] latin-1 failed — retrying with cp1252 encoding.")
                df = pd.read_csv(self.path, encoding="cp1252")

        if 'label' not in df.columns:
            if 'evil' in df.columns:
                df['label'] = df['evil'].astype(int)
            elif 'sus' in df.columns:
                df['label'] = df['sus'].astype(int)

        before = len(df)
        df = df.dropna(subset=[self.target])
        dropped = before - len(df)
        if dropped:
            print(f"[DatasetLoader] Dropped {dropped} rows with NaN label.")

        # Fill numeric columns with column median
        num_cols = df.select_dtypes(include="number").columns.tolist()
        for col in num_cols:
            if df[col].isna().any():
                df[col] = df[col].fillna(df[col].median())

        return df

    def validate(self, df: pd.DataFrame) -> dict:
        """Returns validation stats and prints a human-readable summary."""
        class_dist = df[self.target].value_counts()
        total = len(df)
        minority_count = class_dist.min() if len(class_dist) > 0 else 0
        smote_needed = (minority_count / total) < 0.10 if total > 0 else False

        present_cols = set(df.columns.tolist())
        missing_feature_cols = [c for c in self.feature_cols if c not in present_cols]

        null_count = int(df.isnull().sum().sum())

        report = {
            "shape": df.shape,
            "null_count": null_count,
            "class_distribution": class_dist,
            "missing_feature_cols": missing_feature_cols,
            "smote_needed": smote_needed,
        }

        # Human-readable summary
        print("\n" + "=" * 60)
        print(f"  DatasetLoader Validation Report — [{self.dataset.upper()}]")
        print("=" * 60)
        print(f"  Rows x Cols   : {df.shape[0]:,} x {df.shape[1]}")
        print(f"  Total NaNs    : {null_count:,}")
        print(f"  SMOTE needed  : {'⚠️  YES' if smote_needed else '✅  NO'}")
        print(f"\n  Class Distribution ('{self.target}'):")
        for label, count in class_dist.items():
            pct = 100.0 * count / total
            print(f"    Class {label}: {count:>10,}  ({pct:.1f}%)")
        if missing_feature_cols:
            print(f"\n  ❌ MISSING FEATURE COLS: {missing_feature_cols}")
        else:
            print(f"\n  ✅ All {len(self.feature_cols)} expected feature columns present.")
        print("=" * 60 + "\n")

        return report


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("beth", "unsw"):
        print("Usage: python -m classifier.dataset_loader [beth|unsw]")
        sys.exit(1)

    dataset_name = sys.argv[1]
    loader = DatasetLoader(dataset_name)
    print(f"[DatasetLoader] Loading '{dataset_name}' from: {loader.path}")

    df = loader.load()
    report = loader.validate(df)

    print(f"Shape             : {report['shape']}")
    print(f"Null count        : {report['null_count']}")
    print(f"SMOTE needed      : {report['smote_needed']}")
    print(f"Missing feat cols : {report['missing_feature_cols']}")
    print(f"Class distribution:\n{report['class_distribution']}")

    if report["missing_feature_cols"]:
        print(
            f"\n[FATAL] Missing columns: {report['missing_feature_cols']}. "
            "Cannot proceed with training."
        )
        sys.exit(1)

    print("\n[DatasetLoader] Validation complete. Ready for feature engineering.")
