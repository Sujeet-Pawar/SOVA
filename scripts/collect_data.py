"""Data Collection Script.

Generates all traffic datasets (normal and attacks).
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from traffic_generator.normal.generator import NormalTrafficGenerator
from traffic_generator.attacks.sqli import generate_sqli_requests, save_dataset as save_sqli
from traffic_generator.attacks.xss import generate_xss_requests, save_dataset as save_xss
from traffic_generator.attacks.traversal import generate_traversal_requests, save_dataset as save_traversal
from traffic_generator.attacks.command import generate_command_requests, save_dataset as save_command
from traffic_generator.attacks.malformed import generate_malformed_requests, save_dataset as save_malformed


def main():
    """Generate all datasets."""
    print("=" * 60)
    print("SOVA-WAF Data Collection")
    print("=" * 60)

    # Normal traffic
    print("\n[1/6] Generating normal traffic...")
    normal_gen = NormalTrafficGenerator()
    normal_requests = normal_gen.generate_dataset(num_sessions=100)
    normal_gen.save_dataset("data/raw/normal/normal_traffic.jsonl")

    # SQL Injection
    print("\n[2/6] Generating SQL injection attacks...")
    sqli_requests = generate_sqli_requests(100)
    save_sqli(sqli_requests, "data/raw/attacks/sqli.jsonl")

    # XSS
    print("\n[3/6] Generating XSS attacks...")
    xss_requests = generate_xss_requests(100)
    save_xss(xss_requests, "data/raw/attacks/xss.jsonl")

    # Traversal
    print("\n[4/6] Generating path traversal attacks...")
    traversal_requests = generate_traversal_requests(100)
    save_traversal(traversal_requests, "data/raw/attacks/traversal.jsonl")

    # Command injection
    print("\n[5/6] Generating command injection attacks...")
    command_requests = generate_command_requests(100)
    save_command(command_requests, "data/raw/attacks/command.jsonl")

    # Malformed
    print("\n[6/6] Generating malformed requests...")
    malformed_requests = generate_malformed_requests(100)
    save_malformed(malformed_requests, "data/raw/attacks/malformed.jsonl")

    # Summary
    total_normal = len(normal_requests)
    total_attack = len(sqli_requests) + len(xss_requests) + len(traversal_requests) + len(command_requests) + len(malformed_requests)

    print("\n" + "=" * 60)
    print("COLLECTION SUMMARY")
    print("=" * 60)
    print(f"Normal traffic:     {total_normal:,} requests")
    print(f"SQL injection:      {len(sqli_requests):,} requests")
    print(f"XSS:                {len(xss_requests):,} requests")
    print(f"Path traversal:     {len(traversal_requests):,} requests")
    print(f"Command injection:  {len(command_requests):,} requests")
    print(f"Malformed:          {len(malformed_requests):,} requests")
    print(f"Total:              {total_normal + total_attack:,} requests")
    print("=" * 60)


if __name__ == "__main__":
    main()
