"""
classifier/train.py — End-to-end ML training runner.

Usage:
    python classifier/train.py --dataset beth
    python classifier/train.py --dataset unsw
"""

import argparse
import sys
import os

# Make project root importable when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from classifier.dataset_loader import DatasetLoader
from classifier.feature_pipeline import FeaturePipeline
from classifier.model_trainer import ModelTrainer


def main():
    parser = argparse.ArgumentParser(
        description="Train SOC alert classifier end-to-end."
    )
    parser.add_argument(
        "--dataset",
        choices=["beth", "unsw"],
        required=True,
        help="Dataset to train on: 'beth' or 'unsw'",
    )
    args = parser.parse_args()
    dataset = args.dataset

    print(f"\n{'='*60}")
    print(f"  SOC ML Training Runner — Dataset: {dataset.upper()}")
    print(f"{'='*60}\n")

    # ── 1. Load & validate data ──────────────────────────────────────────
    print("[train.py] Step 1: Loading dataset ...")
    loader = DatasetLoader(dataset)
    df = loader.load()
    report = loader.validate(df)

    if report["missing_feature_cols"]:
        print(
            f"[train.py] FATAL: Missing columns: {report['missing_feature_cols']}"
        )
        sys.exit(1)

    # ── 2. Feature engineering (encode + split + scale + SMOTE) ─────────
    print("\n[train.py] Step 2: Applying FeaturePipeline ...")
    pipeline = FeaturePipeline(dataset)
    X_tr, X_v, X_te, y_tr, y_v, y_te, feature_names = pipeline.fit_transform(df)

    # ── 3. Train models ──────────────────────────────────────────────────
    print("\n[train.py] Step 3: Training all models ...")
    trainer = ModelTrainer(feature_names)
    trainer.train_all(X_tr, y_tr, X_v, y_v)

    # ── 4. Select best model ─────────────────────────────────────────────
    print("\n[train.py] Step 4: Selecting best model ...")
    best_name, best_model = trainer.select_best()

    # ── 5. Final test evaluation ─────────────────────────────────────────
    print("\n[train.py] Step 5: Final test evaluation ...")
    trainer.final_test_eval(best_model, X_te, y_te)

    # ── 6. Save artifacts ────────────────────────────────────────────────
    print("\n[train.py] Step 6: Saving artifacts ...")
    trainer.save_artifacts(best_model, best_name)

    print("\nTraining complete. Artifacts saved to classifier/artifacts/")


if __name__ == "__main__":
    main()
