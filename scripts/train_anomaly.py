"""Anomaly Model Training Script.

Trains the Isolation Forest model on normal traffic features.
"""

import sys
import json
import numpy as np
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.detection.anomaly.model import AnomalyModel
from app.detection.anomaly.trainer import AnomalyTrainer


def main():
    """Train the anomaly detection model."""
    print("=" * 60)
    print("SOVA-WAF Anomaly Model Training")
    print("=" * 60)

    # Load training features
    features_path = "data/features/train_features.npy"
    metadata_path = "data/features/train_metadata.json"

    if not Path(features_path).exists():
        print(f"Error: {features_path} not found.")
        print("Run scripts/build_features.py first.")
        return

    print("\n[1/4] Loading training data...")
    features = np.load(features_path)
    with open(metadata_path) as f:
        metadata = json.load(f)

    labels = metadata.get("labels", [])
    print(f"  Loaded {features.shape[0]} samples, {features.shape[1]} features")

    # Separate normal traffic for training
    normal_indices = [i for i, l in enumerate(labels) if l == "NORMAL"]
    normal_features = features[normal_indices]
    print(f"  Normal traffic samples: {len(normal_indices)}")

    # Load test data for evaluation
    test_features_path = "data/features/test_features.npy"
    test_metadata_path = "data/features/test_metadata.json"

    test_features = None
    test_labels = None
    if Path(test_features_path).exists():
        test_features = np.load(test_features_path)
        with open(test_metadata_path) as f:
            test_metadata = json.load(f)
        test_labels = test_metadata.get("labels", [])
        print(f"  Test samples: {test_features.shape[0]}")

    # Train model
    print("\n[2/4] Training Isolation Forest...")
    trainer = AnomalyTrainer(config={
        "contamination": 0.1,
        "n_estimators": 100,
        "random_state": 42,
    })

    stats = trainer.train_from_features(normal_features)
    for key, value in stats.items():
        print(f"  {key}: {value}")

    # Save model
    print("\n[3/4] Saving model...")
    model_path = "data/models/anomaly_model.joblib"
    trainer.save(model_path)

    # Evaluate
    print("\n[4/4] Evaluating model...")
    if test_features is not None:
        attack_indices = [i for i, l in enumerate(test_labels) if l == "ATTACK"]
        normal_test_indices = [i for i, l in enumerate(test_labels) if l == "NORMAL"]

        if attack_indices and normal_test_indices:
            attack_features = test_features[attack_indices]
            normal_test_features = test_features[normal_test_indices]

            from app.detection.anomaly.evaluator import AnomalyEvaluator
            evaluator = AnomalyEvaluator()

            eval_results = evaluator.evaluate(
                trainer.model,
                normal_test_features,
                attack_features,
            )

            print("\nEvaluation Results:")
            for key, value in eval_results.items():
                if isinstance(value, float):
                    print(f"  {key}: {value:.4f}")
                else:
                    print(f"  {key}: {value}")

            # Threshold evaluation
            threshold_results = evaluator.evaluate_thresholds(
                trainer.model,
                normal_test_features,
                attack_features,
            )
            print("\nThreshold Analysis:")
            for key, metrics in threshold_results.items():
                print(f"  {key}: {metrics}")

    print("\n" + "=" * 60)
    print("Training complete!")
    print(f"Model saved to: {model_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
