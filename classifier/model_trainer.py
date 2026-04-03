import json
import os
import time
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

ARTIFACTS_DIR = os.path.join("classifier", "artifacts")


class ModelTrainer:
    """Trains, compares, and selects the best alert classification model."""

    SEVERITY_THRESHOLDS = {
        "BENIGN":   (0.0, 0.2),
        "LOW":      (0.2, 0.4),
        "MEDIUM":   (0.4, 0.6),
        "HIGH":     (0.6, 0.8),
        "CRITICAL": (0.8, 1.0),
    }

    def __init__(self, feature_names: list):
        self.feature_names = feature_names
        self.models = {
            "RandomForest": RandomForestClassifier(
                n_estimators=100, n_jobs=-1, random_state=42
            ),
            "GradientBoosting": GradientBoostingClassifier(
                n_estimators=30, max_depth=4, random_state=42
            ),
            "LogisticRegression": LogisticRegression(
                solver="saga", max_iter=3000, random_state=42
            ),
        }
        # results[name] = {model, time_sec, val_report}
        self.results: dict = {}

    # ------------------------------------------------------------------ #
    #  TRAINING
    # ------------------------------------------------------------------ #
    def train_all(
        self,
        X_train, y_train,
        X_val, y_val,
    ) -> dict:
        """Train all candidate models, evaluate on val set, return results dict."""
        for name, model in self.models.items():
            print(f"\n[ModelTrainer] Training {name} ...")
            t0 = time.perf_counter()

            model.fit(X_train, y_train)

            elapsed = time.perf_counter() - t0
            if elapsed > 300:
                print(
                    f"[ModelTrainer] ⚠️  WARNING: {name} took {elapsed:.1f}s "
                    f"(>300 s). Consider reducing n_estimators to 50."
                )

            val_report = classification_report(
                y_val, model.predict(X_val), output_dict=True
            )

            self.results[name] = {
                "model": model,
                "time_sec": elapsed,
                "val_report": val_report,
            }

            macro_f1 = val_report["macro avg"]["f1-score"]
            attack_recall = val_report.get("1", val_report.get(1, {})).get(
                "recall", 0.0
            )
            print(
                f"  ✅ {name:<22} | "
                f"Time: {elapsed:5.1f}s | "
                f"Macro F1: {macro_f1:.3f} | "
                f"Attack recall: {attack_recall:.3f}"
            )

        return self.results

    # ------------------------------------------------------------------ #
    #  MODEL SELECTION
    # ------------------------------------------------------------------ #
    def select_best(self) -> tuple:
        """
        Returns (best_model_name, best_model_object).
        Primary criterion : highest attack-class (class '1') recall on val set.
        Filter            : macro F1 > 0.85 (falls back to 0.75 with WARNING).
        """
        if not self.results:
            raise RuntimeError("Call train_all() before select_best().")

        def _get_metrics(name):
            rpt = self.results[name]["val_report"]
            macro_f1 = rpt["macro avg"]["f1-score"]
            attack_recall = rpt.get("1", rpt.get(1, {})).get("recall", 0.0)
            return macro_f1, attack_recall

        threshold = 0.85
        qualified = [
            n for n in self.results if _get_metrics(n)[0] > threshold
        ]

        if not qualified:
            print(
                "[ModelTrainer] ⚠️  WARNING: No model achieved macro F1 > 0.85. "
                "Lowering threshold to 0.75."
            )
            threshold = 0.75
            qualified = [
                n for n in self.results if _get_metrics(n)[0] > threshold
            ]

        if not qualified:
            # Last resort: pick best by recall regardless of F1
            qualified = list(self.results.keys())

        best_name = max(qualified, key=lambda n: _get_metrics(n)[1])
        best_model = self.results[best_name]["model"]
        macro_f1, attack_recall = _get_metrics(best_name)

        print(
            f"\n[ModelTrainer] Selected model: {best_name} | "
            f"Attack recall: {attack_recall:.3f} | "
            f"Macro F1: {macro_f1:.3f}"
        )
        return best_name, best_model

    # ------------------------------------------------------------------ #
    #  FINAL TEST EVALUATION
    # ------------------------------------------------------------------ #
    def final_test_eval(self, model, X_test, y_test) -> dict:
        """
        Evaluates winning model on held-out test set.
        Prints full classification report and confusion matrix.
        Warns (does not raise) if attack recall < 0.70.
        Returns the report dict.
        """
        y_pred = model.predict(X_test)
        report = classification_report(y_test, y_pred, output_dict=True)
        cm = confusion_matrix(y_test, y_pred)

        print("\n" + "=" * 60)
        print("  Final Test Evaluation")
        print("=" * 60)
        print(classification_report(y_test, y_pred))
        print("Confusion Matrix:")
        print(cm)
        print("=" * 60)

        attack_recall = report.get("1", report.get(1, {})).get("recall", 0.0)
        if attack_recall <= 0.70:
            print(
                f"[ModelTrainer] ⚠️  WARNING: Attack recall on test set is "
                f"{attack_recall:.3f} (below 0.70). "
                "Consider retraining with more estimators or tuning hyperparameters."
            )
        else:
            print(
                f"[ModelTrainer] ✅ Attack recall on test set: {attack_recall:.3f}"
            )

        return report

    # ------------------------------------------------------------------ #
    #  SEVERITY MAPPING
    # ------------------------------------------------------------------ #
    @staticmethod
    def probability_to_severity(p_attack: float) -> str:
        """
        Maps an attack probability float in [0, 1] to a severity label.
        Raises ValueError for out-of-range inputs.
        Edge case: p_attack == 1.0 returns 'CRITICAL'.
        """
        if p_attack < 0 or p_attack > 1:
            raise ValueError(
                f"p_attack must be in [0, 1], got {p_attack}"
            )
        if p_attack == 1.0:
            return "CRITICAL"
        for label, (lo, hi) in ModelTrainer.SEVERITY_THRESHOLDS.items():
            if lo <= p_attack < hi:
                return label
        return "CRITICAL"  # fallback safety

    # ------------------------------------------------------------------ #
    #  ARTIFACT SAVING
    # ------------------------------------------------------------------ #
    def save_artifacts(self, model, model_name: str) -> None:
        """
        Saves model.pkl, feature_importance.json, and model_name.txt
        to classifier/artifacts/.
        Raises RuntimeError if model file exceeds 500 MB.
        """
        os.makedirs(ARTIFACTS_DIR, exist_ok=True)

        # Save model
        model_path = os.path.join(ARTIFACTS_DIR, "model.pkl")
        joblib.dump(model, model_path)
        size_mb = os.path.getsize(model_path) / (1024 ** 2)
        print(f"[ModelTrainer] model.pkl saved ({size_mb:.2f} MB)")
        if size_mb > 500:
            raise RuntimeError(
                f"model.pkl is {size_mb:.1f} MB — exceeds 500 MB limit."
            )

        # Save feature importances (tree-based models only)
        if hasattr(model, "feature_importances_"):
            importances = dict(
                zip(self.feature_names, model.feature_importances_.tolist())
            )
            importances = dict(
                sorted(importances.items(), key=lambda x: x[1], reverse=True)
            )
            fi_path = os.path.join(ARTIFACTS_DIR, "feature_importance.json")
            with open(fi_path, "w") as f:
                json.dump(importances, f, indent=2)
            top5 = list(importances.items())[:5]
            print("[ModelTrainer] Top 5 features by importance:")
            for feat, imp in top5:
                print(f"    {feat:<30}  {imp:.4f}")

        # Save model name string
        name_path = os.path.join(ARTIFACTS_DIR, "model_name.txt")
        with open(name_path, "w") as f:
            f.write(model_name)
        print(f"[ModelTrainer] Artifacts saved to {ARTIFACTS_DIR}/")
