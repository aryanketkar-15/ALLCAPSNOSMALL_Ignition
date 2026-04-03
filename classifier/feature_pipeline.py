import os
import sys
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from imblearn.over_sampling import SMOTE


PIPELINE_CONFIGS = {
    "beth": {
        "num_cols": [
            "severity_raw",
        ],
        "cat_cols": ["event_type", "processName"],
    },
    "unsw": {
        "num_cols": [
            "dur", "sbytes", "dbytes", "sttl", "dttl",
            "sloss", "dloss", "sload", "dload", "spkts", "dpkts",
            "smeansz", "dmeansz", "ct_srv_src", "ct_state_ttl",
            "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
            "ct_dst_src_ltm",
        ],
        "cat_cols": ["proto", "service", "state"],
    },
}

ARTIFACTS_DIR = os.path.join("classifier", "artifacts")


class FeaturePipeline:
    """End-to-end feature engineering: encode → split → scale → SMOTE."""

    def __init__(self, dataset: str):
        dataset = dataset.lower()
        if dataset not in PIPELINE_CONFIGS:
            raise ValueError(
                f"Unknown dataset '{dataset}'. Choose 'beth' or 'unsw'."
            )
        cfg = PIPELINE_CONFIGS[dataset]
        self.dataset = dataset
        self.num_cols = cfg["num_cols"]
        self.cat_cols = cfg["cat_cols"]
        self.target = "label"

        # One LabelEncoder per categorical column
        self.encoders: dict[str, LabelEncoder] = {
            col: LabelEncoder() for col in self.cat_cols
        }
        self.scaler = StandardScaler()

        # Ensure artifacts directory exists
        os.makedirs(ARTIFACTS_DIR, exist_ok=True)

        # Loaded-from-disk flag for inference
        self._artifacts_loaded = False

    # ------------------------------------------------------------------ #
    #  TRAINING PATH
    # ------------------------------------------------------------------ #
    def fit_transform(self, df: pd.DataFrame) -> tuple:
        """
        Full training pipeline:
        1. Extract X / y
        2. Fill NaN in numeric cols with median
        3. LabelEncode categorical cols
        4. Stratified 70/15/15 split
        5. StandardScaler on X_train only
        6. SMOTE on X_train only
        7. Save artifacts
        Returns (X_train_sm, X_val, X_test, y_train_sm, y_val, y_test, feature_names)
        """
        # --- Extract features and target ---
        feature_cols = self.num_cols + self.cat_cols
        X = df[feature_cols].copy()
        y = df[self.target].copy()

        # --- Fill numeric NaN with column median ---
        for col in self.num_cols:
            if X[col].isna().any():
                X[col] = X[col].fillna(X[col].median())

        # --- Encode categoricals ---
        for col in self.cat_cols:
            X[col] = X[col].astype(str)
            X[col] = self.encoders[col].fit_transform(X[col])

        feature_names = list(X.columns)

        # --- Stratified split: 70 train / 15 val / 15 test ---
        n_classes_full = y.nunique() if hasattr(y, 'nunique') else len(set(y))
        stratify_y = y if n_classes_full >= 2 else None
        stratify_label = "stratified" if stratify_y is not None else "random (single class)"
        print(f"[FeaturePipeline] Split mode: {stratify_label}")

        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=0.30, stratify=stratify_y, random_state=42
        )
        stratify_temp = y_temp if n_classes_full >= 2 else None
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.50, stratify=stratify_temp, random_state=42
        )

        # --- Scale numeric columns (fit on train ONLY) ---
        X_train[self.num_cols] = self.scaler.fit_transform(X_train[self.num_cols])
        X_val[self.num_cols] = self.scaler.transform(X_val[self.num_cols])
        X_test[self.num_cols] = self.scaler.transform(X_test[self.num_cols])

        # --- Print class distribution BEFORE SMOTE ---
        print("\n[FeaturePipeline] Class distribution BEFORE SMOTE (train set):")
        _print_class_dist(y_train)

        # --- SMOTE on X_train ONLY (never val/test — that is data leakage) ---
        n_classes = y_train.nunique() if hasattr(y_train, 'nunique') else len(set(y_train))
        if n_classes < 2:
            print("[FeaturePipeline] ⚠️  WARNING: Only one class in training data — skipping SMOTE.")
            print("[FeaturePipeline] Injecting synthetic attack samples (5% of train size) for training.")
            n_synthetic = max(int(len(X_train) * 0.05), 10)
            rng = np.random.RandomState(42)
            idx = rng.choice(len(X_train), size=n_synthetic, replace=True)
            X_synthetic = X_train.iloc[idx].copy() if hasattr(X_train, 'iloc') else X_train[idx].copy()
            # Add noise to make synthetic attacks slightly different
            for col in self.num_cols:
                col_idx = feature_names.index(col) if col in feature_names else None
                if col_idx is not None and hasattr(X_synthetic, 'iloc'):
                    X_synthetic[col] = X_synthetic[col] + rng.normal(0, 0.1, n_synthetic)
            y_synthetic = pd.Series([1] * n_synthetic)
            if hasattr(X_train, 'iloc'):
                X_train_sm = pd.concat([X_train, X_synthetic], ignore_index=True)
            else:
                X_train_sm = np.vstack([X_train, X_synthetic])
            y_train_sm = pd.concat([y_train.reset_index(drop=True), y_synthetic], ignore_index=True)
        else:
            try:
                smote = SMOTE(random_state=42)
                X_train_sm, y_train_sm = smote.fit_resample(X_train, y_train)
            except ValueError:
                print("[FeaturePipeline] SMOTE k_neighbors error — retrying with k_neighbors=1")
                smote = SMOTE(random_state=42, k_neighbors=1)
                X_train_sm, y_train_sm = smote.fit_resample(X_train, y_train)

        # --- Print class distribution AFTER SMOTE ---
        print("[FeaturePipeline] Class distribution AFTER SMOTE (train set):")
        _print_class_dist(y_train_sm)

        # --- Save artifacts ---
        joblib.dump(self.scaler, os.path.join(ARTIFACTS_DIR, "scaler.pkl"))
        joblib.dump(self.encoders, os.path.join(ARTIFACTS_DIR, "encoders.pkl"))
        print(f"[FeaturePipeline] Artifacts saved to {ARTIFACTS_DIR}/")

        return (
            X_train_sm.values if hasattr(X_train_sm, "values") else X_train_sm,
            X_val.values,
            X_test.values,
            y_train_sm.values if hasattr(y_train_sm, "values") else y_train_sm,
            y_val.values,
            y_test.values,
            feature_names,
        )

    # ------------------------------------------------------------------ #
    #  INFERENCE PATH
    # ------------------------------------------------------------------ #
    def transform_single(self, alert_dict: dict) -> np.ndarray:
        """
        Transforms a single alert dict at inference time using saved
        scaler and encoders.  Returns a 2-D numpy array ready for
        model.predict_proba().
        """
        if not self._artifacts_loaded:
            self.scaler = joblib.load(os.path.join(ARTIFACTS_DIR, "scaler.pkl"))
            self.encoders = joblib.load(os.path.join(ARTIFACTS_DIR, "encoders.pkl"))
            self._artifacts_loaded = True

        feature_cols = self.num_cols + self.cat_cols
        row = {}
        for col in feature_cols:
            val = alert_dict.get(col)
            row[col] = 0 if val is None or pd.isna(val) else val
        df = pd.DataFrame([row])
        
        for col in self.num_cols:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        df.fillna(0, inplace=True)

        # Encode categoricals
        for col in self.cat_cols:
            df[col] = df[col].astype(str)
            try:
                df[col] = self.encoders[col].transform(df[col])
            except ValueError:
                # Unseen label at inference — default to -1
                df[col] = -1

        # Scale numeric columns
        df[self.num_cols] = self.scaler.transform(df[self.num_cols])

        return df[feature_cols].values


# ------------------------------------------------------------------ #
#  Helpers
# ------------------------------------------------------------------ #
def _print_class_dist(y) -> None:
    """Print class counts and percentages."""
    series = pd.Series(y)
    counts = series.value_counts().sort_index()
    total = len(series)
    for label, count in counts.items():
        pct = 100.0 * count / total
        print(f"    Class {label}: {count:>10,}  ({pct:.1f}%)")


if __name__ == "__main__":
    from classifier.dataset_loader import DatasetLoader

    ds = sys.argv[1] if len(sys.argv) > 1 else "beth"
    print(f"[FeaturePipeline] Running pipeline for dataset: {ds}")

    loader = DatasetLoader(ds)
    df = loader.load()
    loader.validate(df)

    pipeline = FeaturePipeline(ds)
    X_tr, X_v, X_te, y_tr, y_v, y_te, feat = pipeline.fit_transform(df)

    print(f"\nTrain shape : {X_tr.shape}")
    print(f"Val shape   : {X_v.shape}")
    print(f"Test shape  : {X_te.shape}")
    print(f"Features    : {feat}")
    print("\n[FeaturePipeline] Pipeline complete. Ready for model training.")
