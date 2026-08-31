"""Malformed Request Attack Traffic Generator."""

import json
import uuid
import time
from datetime import datetime
from pathlib import Path


MALFORMED_PAYLOADS = {
    "invalid_method": [
        ("INVALID", "/"),
        ("", "/"),
        ("get", "/"),
        ("G" * 100, "/"),
    ],
    "control_chars": [
        ("\x00/test", "Null byte in path"),
        ("/test\x00.html", "Null byte extension"),
        ("\x01\x02\x03/test", "Control chars in path"),
        ("/test?q=\x00injection", "Null byte in query"),
    ],
    "oversized": [
        ("/" + "a" * 5000, "Oversized path"),
        ("/?q=" + "b" * 10000, "Oversized query"),
    ],
    "invalid_headers": [
        ({}, "Missing Host header"),
        ({"Content-Length": "-1"}, "Negative Content-Length"),
        ({"Content-Length": "abc"}, "Invalid Content-Length"),
    ],
    "duplicate_headers": [
        ({"Content-Type": "text/html", "content-type": "application/json"}, "Duplicate Content-Type"),
    ],
}


def generate_malformed_requests(num_requests: int = 100) -> list[dict]:
    """Generate malformed attack requests."""
    requests = []
    timestamp = time.time()
    techniques = list(MALFORMED_PAYLOADS.keys())

    for i in range(num_requests):
        technique = techniques[i % len(techniques)]
        payload_entry = MALFORMED_PAYLOADS[technique]
        payload = payload_entry[i % len(payload_entry)]

        request = {
            "request_id": f"REQ-MAL-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
            "method": "GET",
            "path": "/",
            "query_string": "",
            "query": {},
            "headers": {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "host": "127.0.0.1:8443",
            },
            "body_fields": [],
            "body_size": 0,
            "session_id": f"S-ATTACK-{uuid.uuid4().hex[:6].upper()}",
            "source_id": f"ATTACKER-{uuid.uuid4().hex[:4].upper()}",
            "content_type": "",
            "label": "ATTACK",
            "attack_type": "MALFORMED",
            "technique": technique,
        }

        # Apply the specific malformation
        if technique == "invalid_method":
            method, path = payload
            request["method"] = method
            request["path"] = path
        elif technique == "control_chars":
            path, description = payload
            request["path"] = path
        elif technique == "oversized":
            path, description = payload
            request["path"] = path[:2048]  # Cap for practical purposes
            request["query_string"] = path[1:] if path.startswith("/") else path
        elif technique == "invalid_headers":
            headers_update, description = payload
            request["headers"].update(headers_update)
        elif technique == "duplicate_headers":
            headers_update, description = payload
            request["headers"].update(headers_update)

        requests.append(request)
        timestamp += 0.1

    return requests


def save_dataset(requests: list[dict], filepath: str):
    """Save attack requests to JSONL."""
    Path(filepath).parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w") as f:
        for req in requests:
            f.write(json.dumps(req) + "\n")
    print(f"Saved {len(requests)} malformed requests to {filepath}")


if __name__ == "__main__":
    requests = generate_malformed_requests(100)
    save_dataset(requests, "data/raw/attacks/malformed.jsonl")
