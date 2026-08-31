"""Normal Traffic Generator - generates realistic normal HTTP traffic.

Creates sessions with varied browsing patterns against the test application.
"""

import json
import random
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional


# User agents for variety
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/605.1.15",
]

# Normal search queries
SEARCH_QUERIES = [
    "laptop", "phone", "tablet", "headphones", "watch",
    "camera", "speaker", "keyboard", "mouse", "monitor",
    "charger", "cable", "case", "stand", "adapter",
    "gaming", "wireless", "bluetooth", "usb", "hdmi",
]

# Product IDs
PRODUCT_IDS = [10, 11, 12, 20]


class NormalTrafficGenerator:
    """Generates normal HTTP traffic for the test application."""

    def __init__(self, backend_url: str = "http://127.0.0.1:8080"):
        self.backend_url = backend_url
        self.requests = []

    def generate_session(self, session_id: Optional[str] = None) -> list[dict]:
        """Generate a single session of normal traffic."""
        if not session_id:
            session_id = f"S{uuid.uuid4().hex[:6].upper()}"

        source_id = f"CLIENT-{random.randint(1, 100):03d}"
        user_agent = random.choice(USER_AGENTS)
        session_requests = []

        # Choose session type
        session_type = random.choice(["browse", "search", "shop", "mixed"])

        if session_type == "browse":
            session_requests = self._generate_browse_session(session_id, source_id, user_agent)
        elif session_type == "search":
            session_requests = self._generate_search_session(session_id, source_id, user_agent)
        elif session_type == "shop":
            session_requests = self._generate_shop_session(session_id, source_id, user_agent)
        else:
            session_requests = self._generate_mixed_session(session_id, source_id, user_agent)

        return session_requests

    def generate_dataset(self, num_sessions: int = 50) -> list[dict]:
        """Generate a full dataset of normal traffic."""
        all_requests = []
        for i in range(num_sessions):
            session_id = f"S{i+1:04d}"
            session = self.generate_session(session_id)
            all_requests.extend(session)
        self.requests = all_requests
        return all_requests

    def _generate_browse_session(self, session_id, source_id, user_agent) -> list[dict]:
        """Generate a browsing session."""
        requests = []
        timestamp = time.time()

        # Home page
        requests.append(self._make_request(
            "GET", "/", session_id, source_id, user_agent, timestamp, label="NORMAL"
        ))
        timestamp += random.uniform(0.5, 2.0)

        # Browse some products
        num_products = random.randint(1, 4)
        for _ in range(num_products):
            pid = random.choice(PRODUCT_IDS)
            requests.append(self._make_request(
                "GET", f"/products?id={pid}", session_id, source_id, user_agent,
                timestamp, label="NORMAL"
            ))
            timestamp += random.uniform(1.0, 3.0)

        # Maybe search
        if random.random() > 0.5:
            query = random.choice(SEARCH_QUERIES)
            requests.append(self._make_request(
                "GET", f"/search?q={query}", session_id, source_id, user_agent,
                timestamp, label="NORMAL"
            ))
            timestamp += random.uniform(1.0, 2.0)

        # Profile
        if random.random() > 0.6:
            requests.append(self._make_request(
                "GET", "/profile", session_id, source_id, user_agent,
                timestamp, label="NORMAL"
            ))

        return requests

    def _generate_search_session(self, session_id, source_id, user_agent) -> list[dict]:
        """Generate a search-focused session."""
        requests = []
        timestamp = time.time()

        # Home
        requests.append(self._make_request(
            "GET", "/", session_id, source_id, user_agent, timestamp, label="NORMAL"
        ))
        timestamp += random.uniform(0.5, 1.5)

        # Multiple searches
        num_searches = random.randint(2, 5)
        for _ in range(num_searches):
            query = random.choice(SEARCH_QUERIES)
            requests.append(self._make_request(
                "GET", f"/search?q={query}", session_id, source_id, user_agent,
                timestamp, label="NORMAL"
            ))
            timestamp += random.uniform(1.0, 3.0)

            # Sometimes click a product from search
            if random.random() > 0.5:
                pid = random.choice(PRODUCT_IDS)
                requests.append(self._make_request(
                    "GET", f"/products?id={pid}", session_id, source_id, user_agent,
                    timestamp, label="NORMAL"
                ))
                timestamp += random.uniform(1.0, 2.0)

        return requests

    def _generate_shop_session(self, session_id, source_id, user_agent) -> list[dict]:
        """Generate a shopping session with login."""
        requests = []
        timestamp = time.time()

        # Home
        requests.append(self._make_request(
            "GET", "/", session_id, source_id, user_agent, timestamp, label="NORMAL"
        ))
        timestamp += random.uniform(0.5, 1.5)

        # Login
        username = random.choice(["admin", "user", "test"])
        requests.append(self._make_request(
            "POST", "/login", session_id, source_id, user_agent, timestamp,
            label="NORMAL", body={"username": username, "password": f"{username}123"}
        ))
        timestamp += random.uniform(0.5, 1.0)

        # Browse products
        for _ in range(random.randint(1, 3)):
            pid = random.choice(PRODUCT_IDS)
            requests.append(self._make_request(
                "GET", f"/products?id={pid}", session_id, source_id, user_agent,
                timestamp, label="NORMAL"
            ))
            timestamp += random.uniform(1.0, 3.0)

        # Profile
        requests.append(self._make_request(
            "GET", "/profile", session_id, source_id, user_agent,
            timestamp, label="NORMAL"
        ))

        return requests

    def _generate_mixed_session(self, session_id, source_id, user_agent) -> list[dict]:
        """Generate a mixed browsing session."""
        requests = []
        timestamp = time.time()

        endpoints = [
            ("GET", "/"),
            ("GET", "/products"),
            lambda: ("GET", f"/search?q={random.choice(SEARCH_QUERIES)}"),
            lambda: ("GET", f"/products?id={random.choice(PRODUCT_IDS)}"),
            ("GET", "/profile"),
            ("GET", "/api/data"),
        ]

        num_requests = random.randint(3, 8)
        for _ in range(num_requests):
            ep = random.choice(endpoints)
            if callable(ep):
                method, path = ep()
            else:
                method, path = ep

            requests.append(self._make_request(
                method, path, session_id, source_id, user_agent,
                timestamp, label="NORMAL"
            ))
            timestamp += random.uniform(0.5, 3.0)

        return requests

    def _make_request(self, method, path, session_id, source_id, user_agent,
                      timestamp, label="NORMAL", body=None, attack_type=None):
        """Create a request record."""
        # Parse path and query
        if "?" in path:
            url_path, query_string = path.split("?", 1)
        else:
            url_path = path
            query_string = ""

        body_fields = []
        body_size = 0
        if body:
            body_fields = list(body.keys())
            body_size = len(json.dumps(body).encode())

        return {
            "request_id": f"REQ-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
            "method": method,
            "path": url_path,
            "query_string": query_string,
            "query": self._parse_query(query_string),
            "headers": {
                "user-agent": user_agent,
                "accept": "text/html,application/xhtml+xml",
                "accept-language": "en-US,en;q=0.9",
                "accept-encoding": "gzip, deflate",
            },
            "body_fields": body_fields,
            "body_size": body_size,
            "session_id": session_id,
            "source_id": source_id,
            "content_type": "application/x-www-form-urlencoded" if body else "",
            "label": label,
            "attack_type": attack_type,
        }

    def _parse_query(self, query_string: str) -> dict:
        """Parse query string into dict."""
        if not query_string:
            return {}
        result = {}
        for pair in query_string.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                result[key] = value
        return result

    def save_dataset(self, filepath: str):
        """Save the generated dataset to JSONL."""
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w") as f:
            for request in self.requests:
                f.write(json.dumps(request) + "\n")
        print(f"Saved {len(self.requests)} requests to {filepath}")


def main():
    """Generate normal traffic dataset."""
    generator = NormalTrafficGenerator()
    requests = generator.generate_dataset(num_sessions=100)
    generator.save_dataset("data/raw/normal/normal_traffic.jsonl")
    print(f"Generated {len(requests)} normal requests across 100 sessions")


if __name__ == "__main__":
    main()
