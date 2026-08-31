"""Evaluation Script.

Evaluates the full detection pipeline (rules + anomaly + behavioral).
"""

import sys
import json
import numpy as np
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.request_processing.parser import HTTPRequest
from app.feature_engine.pipeline import FeaturePipeline
from app.detection.rules.base import RuleEngine
from app.detection.anomaly.detector import AnomalyDetector
from app.detection.behavioral.detector import BehavioralDetector
from app.detection.common.models import ThreatType


def load_jsonl(filepath: str) -> list[dict]:
    """Load a JSONL file."""
    records = []
    if not Path(filepath).exists():
        return records
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def dict_to_request(data: dict) -> HTTPRequest:
    """Convert a normalized dict to HTTPRequest."""
    return HTTPRequest(
        request_id=data.get("request_id", "EVAL"),
        source_id=data.get("source_id", "EVAL"),
        method=data.get("method", "GET"),
        path=data.get("path", "/"),
        query=data.get("query", {}),
        query_string=data.get("query_string", ""),
        headers=data.get("headers", {}),
        body_fields=data.get("body_fields", []),
        body_size=data.get("body_size", 0),
        session_id=data.get("session_id", "EVAL"),
        content_type=data.get("content_type", ""),
        user_agent=data.get("headers", {}).get("user-agent", ""),
    )


def main():
    """Run evaluation on test data."""
    print("=" * 60)
    print("SOVA-WAF Pipeline Evaluation")
    print("=" * 60)

    # Load test data
    test_records = load_jsonl("data/normalized/test.jsonl")
    if not test_records:
        print("No test data found. Run scripts/preprocess_data.py first.")
        return

    print(f"\nLoaded {len(test_records)} test records")

    # Initialize pipeline components
    pipeline = FeaturePipeline()
    rule_engine = RuleEngine()
    anomaly_detector = AnomalyDetector()
    behavioral_detector = BehavioralDetector()

    # Track results
    results = {
        "total": 0,
        "normal": {"total": 0, "detected_by_rules": 0, "detected_by_anomaly": 0, "false_positives": 0},
        "attack": {"total": 0, "detected_by_rules": 0, "detected_by_anomaly": 0, "missed": 0},
    }

    # Per-type results
    attack_types = {}

    for record in test_records:
        request = dict_to_request(record)
        label = record.get("label", "UNKNOWN")
        attack_type = record.get("attack_type", "NONE")

        # Feature extraction
        feature_vector = pipeline.extract(request)

        # Rule detection
        rule_results = rule_engine.analyze(request)
        max_rule_score = max((r.score for r in rule_results), default=0)
        rule_detected = max_rule_score > 0.5

        # Anomaly detection
        anomaly_result = anomaly_detector.detect(feature_vector)
        anomaly_detected = (anomaly_result.classification == "ANOMALOUS"
                           if anomaly_result else False)

        # Behavioral detection
        behavioral_result = behavioral_detector.detect(request)

        # Track results
        results["total"] += 1

        if label == "NORMAL":
            results["normal"]["total"] += 1
            if rule_detected:
                results["normal"]["detected_by_rules"] += 1
            if anomaly_detected:
                results["normal"]["detected_by_anomaly"] += 1
            if rule_detected or anomaly_detected:
                results["normal"]["false_positives"] += 1
        elif label == "ATTACK":
            results["attack"]["total"] += 1

            if attack_type not in attack_types:
                attack_types[attack_type] = {"total": 0, "rule_detected": 0, "anomaly_detected": 0}

            attack_types[attack_type]["total"] += 1

            if rule_detected:
                results["attack"]["detected_by_rules"] += 1
                attack_types[attack_type]["rule_detected"] += 1
            if anomaly_detected:
                results["attack"]["detected_by_anomaly"] += 1
                attack_types[attack_type]["anomaly_detected"] += 1
            if not rule_detected and not anomaly_detected:
                results["attack"]["missed"] += 1

    # Print results
    print("\n" + "=" * 60)
    print("EVALUATION RESULTS")
    print("=" * 60)

    print(f"\nTotal test records: {results['total']}")

    print(f"\n--- Normal Traffic ---")
    n = results["normal"]
    print(f"  Total:              {n['total']}")
    print(f"  False Positives:    {n['false_positives']}")
    fp_rate = n["false_positives"] / max(1, n["total"])
    print(f"  False Positive Rate: {fp_rate:.2%}")

    print(f"\n--- Attack Traffic ---")
    a = results["attack"]
    print(f"  Total:              {a['total']}")
    print(f"  Rule Detected:      {a['detected_by_rules']}")
    print(f"  Anomaly Detected:   {a['detected_by_anomaly']}")
    print(f"  Missed:             {a['missed']}")

    detection_rate = 1 - (a["missed"] / max(1, a["total"]))
    print(f"  Detection Rate:     {detection_rate:.2%}")

    print(f"\n--- Per Attack Type ---")
    for atype, stats in attack_types.items():
        if atype:
            total = stats["total"]
            rule_pct = stats["rule_detected"] / max(1, total)
            anomaly_pct = stats["anomaly_detected"] / max(1, total)
            print(f"  {atype}:")
            print(f"    Total: {total}, Rule: {rule_pct:.0%}, Anomaly: {anomaly_pct:.0%}")

    # Save results
    eval_path = "data/evaluation/evaluation_results.json"
    Path(eval_path).parent.mkdir(parents=True, exist_ok=True)
    with open(eval_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {eval_path}")

    print("\n" + "=" * 60)
    print("Evaluation complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
