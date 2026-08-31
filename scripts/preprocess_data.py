"""Data Preprocessing Script.

Pipeline: Raw Data → Parsing → Normalization → Sanitization → Deduplication → Validation → Labeling → Normalized Dataset
"""

import json
import hashlib
from pathlib import Path
from datetime import datetime


def load_jsonl(filepath: str) -> list[dict]:
    """Load a JSONL file."""
    records = []
    if not Path(filepath).exists():
        print(f"  Warning: {filepath} not found, skipping")
        return records
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def normalize_record(record: dict) -> dict:
    """Normalize a single request record."""
    normalized = {
        "request_id": record.get("request_id", ""),
        "timestamp": record.get("timestamp", datetime.utcnow().isoformat()),
        "method": record.get("method", "GET").upper(),
        "path": record.get("path", "/"),
        "query_string": record.get("query_string", ""),
        "query": record.get("query", {}),
        "headers": {k.lower(): v for k, v in record.get("headers", {}).items()},
        "body_fields": record.get("body_fields", []),
        "body_size": record.get("body_size", 0),
        "session_id": record.get("session_id", ""),
        "source_id": record.get("source_id", ""),
        "content_type": record.get("content_type", ""),
        "label": record.get("label", "UNKNOWN"),
        "attack_type": record.get("attack_type", None),
    }
    return normalized


def deduplicate(records: list[dict]) -> list[dict]:
    """Remove exact duplicate requests."""
    seen = set()
    unique = []
    duplicates = 0

    for record in records:
        # Create a dedup key from the most important fields
        key_data = f"{record['method']}:{record['path']}:{record['query_string']}:{record['label']}:{record.get('attack_type', '')}"
        key = hashlib.md5(key_data.encode()).hexdigest()

        if key not in seen:
            seen.add(key)
            unique.append(record)
        else:
            duplicates += 1

    return unique, duplicates


def validate_record(record: dict) -> bool:
    """Validate that a record has required fields."""
    required_fields = ["request_id", "method", "path", "label"]
    return all(record.get(field) for field in required_fields)


def split_dataset(records: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """Split dataset into train/validation/test.

    - TRAIN: Normal traffic + some attack variations
    - VALIDATION: Held-out examples
    - TEST: Known attacks + modified attacks + novel scenarios
    """
    normal = [r for r in records if r["label"] == "NORMAL"]
    attacks = [r for r in records if r["label"] == "ATTACK"]

    # Split normal: 70% train, 15% val, 15% test
    n_normal = len(normal)
    normal_train = normal[:int(n_normal * 0.7)]
    normal_val = normal[int(n_normal * 0.7):int(n_normal * 0.85)]
    normal_test = normal[int(n_normal * 0.85):]

    # Split attacks: 50% train (known patterns), 25% val, 25% test
    n_attacks = len(attacks)
    attack_train = attacks[:int(n_attacks * 0.5)]
    attack_val = attacks[int(n_attacks * 0.5):int(n_attacks * 0.75)]
    attack_test = attacks[int(n_attacks * 0.75):]

    train = normal_train + attack_train
    val = normal_val + attack_val
    test = normal_test + attack_test

    return train, val, test


def save_jsonl(records: list[dict], filepath: str):
    """Save records to JSONL."""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")


def main():
    """Run the preprocessing pipeline."""
    print("=" * 60)
    print("SOVA-WAF Data Preprocessing")
    print("=" * 60)

    # Load all raw data
    print("\n[1/5] Loading raw data...")
    all_records = []

    raw_files = [
        "data/raw/normal/normal_traffic.jsonl",
        "data/raw/attacks/sqli.jsonl",
        "data/raw/attacks/xss.jsonl",
        "data/raw/attacks/traversal.jsonl",
        "data/raw/attacks/command.jsonl",
        "data/raw/attacks/malformed.jsonl",
    ]

    for filepath in raw_files:
        records = load_jsonl(filepath)
        print(f"  Loaded {len(records)} records from {filepath}")
        all_records.extend(records)

    print(f"\n  Total raw records: {len(all_records)}")

    # Normalize
    print("\n[2/5] Normalizing records...")
    normalized = [normalize_record(r) for r in all_records]
    print(f"  Normalized {len(normalized)} records")

    # Validate
    print("\n[3/5] Validating records...")
    valid = [r for r in normalized if validate_record(r)]
    invalid = len(normalized) - len(valid)
    print(f"  Valid: {len(valid)}, Invalid: {invalid}")

    # Deduplicate
    print("\n[4/5] Deduplicating records...")
    unique, duplicates = deduplicate(valid)
    print(f"  Unique: {len(unique)}, Duplicates removed: {duplicates}")

    # Save normalized dataset
    save_jsonl(unique, "data/normalized/all_requests.jsonl")

    # Split
    print("\n[5/5] Splitting dataset...")
    train, val, test = split_dataset(unique)

    save_jsonl(train, "data/normalized/train.jsonl")
    save_jsonl(val, "data/normalized/validation.jsonl")
    save_jsonl(test, "data/normalized/test.jsonl")

    # Summary
    print("\n" + "=" * 60)
    print("PREPROCESSING SUMMARY")
    print("=" * 60)
    print(f"Total records:   {len(unique)}")
    print(f"  Normal:        {sum(1 for r in unique if r['label'] == 'NORMAL')}")
    print(f"  Attacks:       {sum(1 for r in unique if r['label'] == 'ATTACK')}")
    print(f"\nSplit:")
    print(f"  Train:         {len(train)}")
    print(f"  Validation:    {len(val)}")
    print(f"  Test:          {len(test)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
