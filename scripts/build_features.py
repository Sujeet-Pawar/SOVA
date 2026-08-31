"""Feature Building Script.

Extracts feature vectors from normalized request data.
"""

import sys
import json
import numpy as np
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.request_processing.parser import HTTPRequest
from app.feature_engine.pipeline import FeaturePipeline


def load_jsonl(filepath: str) -> list[dict]:
    """Load a JSONL file."""
    records = []
    if not Path(filepath).exists():
        print(f"  Warning: {filepath} not found")
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
        request_id=data.get("request_id", "IMPORTED"),
        source_id=data.get("source_id", "IMPORTED"),
        method=data.get("method", "GET"),
        path=data.get("path", "/"),
        query=data.get("query", {}),
        query_string=data.get("query_string", ""),
        headers=data.get("headers", {}),
        body_fields=data.get("body_fields", []),
        body_size=data.get("body_size", 0),
        session_id=data.get("session_id", "IMPORTED"),
        content_type=data.get("content_type", ""),
        user_agent=data.get("headers", {}).get("user-agent", ""),
    )


def main():
    """Build feature vectors from normalized data."""
    print("=" * 60)
    print("SOVA-WAF Feature Building")
    print("=" * 60)

    pipeline = FeaturePipeline()
    feature_names = pipeline.get_feature_names()
    print(f"\nFeature vector size: {len(feature_names)}")
    print(f"Features: {feature_names}")

    # Process each split
    for split_name in ["train", "validation", "test"]:
        filepath = f"data/normalized/{split_name}.jsonl"
        print(f"\n[{split_name.upper()}] Processing {filepath}...")

        records = load_jsonl(filepath)
        if not records:
            continue

        requests = [dict_to_request(r) for r in records]
        features = pipeline.extract_batch(requests)

        # Save features
        output_path = f"data/features/{split_name}_features.npy"
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        np.save(output_path, features)

        # Save metadata
        metadata = {
            "feature_names": feature_names,
            "num_samples": len(features),
            "num_features": features.shape[1],
            "labels": [r.get("label", "UNKNOWN") for r in records],
            "attack_types": [r.get("attack_type") for r in records],
        }
        meta_path = f"data/features/{split_name}_metadata.json"
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)

        print(f"  Saved {len(features)} feature vectors to {output_path}")
        print(f"  Shape: {features.shape}")

    print("\n" + "=" * 60)
    print("Feature building complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
