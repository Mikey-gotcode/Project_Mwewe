#!/usr/bin/env python3
"""
Provision a new RFeye node: generates a random 32-byte shared secret,
adds it to server/allowlist.json under the node's name, and prints the
exact config.py snippet to flash onto that node.

Run once per physical node, BEFORE flashing it, from the server/ dir:

    python3 tools/provision_node.py gate-north

Each node gets its own secret — never reuse one across nodes. A stolen
node then only compromises itself, not the fleet.
"""
import json
import secrets
import sys
from pathlib import Path

ALLOWLIST_PATH = Path(__file__).parent.parent / "allowlist.json"


def main():
    if len(sys.argv) != 2:
        print("Usage: provision_node.py <node-name>")
        print("  <node-name> must match ^[A-Za-z0-9_-]{1,32}$ (no spaces/pipes)")
        sys.exit(1)

    name = sys.argv[1]

    allowlist = {}
    if ALLOWLIST_PATH.exists():
        allowlist = json.loads(ALLOWLIST_PATH.read_text())

    if name in allowlist:
        print(f"⚠  '{name}' already exists in {ALLOWLIST_PATH.name}.")
        print("   Re-provisioning will invalidate the currently-flashed secret.")
        if input("   Continue and overwrite? [y/N] ").strip().lower() != "y":
            sys.exit(0)

    secret_hex = secrets.token_bytes(32).hex()
    allowlist[name] = secret_hex
    ALLOWLIST_PATH.write_text(json.dumps(allowlist, indent=2) + "\n")

    print(f"\n✓ Added '{name}' to {ALLOWLIST_PATH}\n")
    print("Add this to that node's pico/config.py before flashing:\n")
    print(f'    NODE_NAME   = "{name}"')
    print(f'    NODE_SECRET = bytes.fromhex("{secret_hex}")')
    print()


if __name__ == "__main__":
    main()
