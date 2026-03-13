#!/usr/bin/env python3
"""Sync users from config/users into Stalwart via its management API.

Reads the Dovecot passwd-file (email:{PLAIN}password) and provisions
matching accounts in Stalwart so both servers share the same credentials.

Usage:
    python3 scripts/sync_stalwart_users.py
    python3 scripts/sync_stalwart_users.py --url http://localhost:8443
"""

import argparse
import base64
import json
import sys
import urllib.error
import urllib.request
from lib import USERS_FILE

DEFAULT_URL = "http://localhost:8443"
ADMIN_USER = "admin"
ADMIN_PASS = "secret"


def _auth_header():
    creds = base64.b64encode(f"{ADMIN_USER}:{ADMIN_PASS}".encode()).decode()
    return f"Basic {creds}"


def _api(base_url, method, path, body=None):
    """Make an API request to Stalwart. Returns (status, response_body)."""
    url = f"{base_url}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", _auth_header())
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def parse_users_file():
    users = []
    for line in USERS_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        email, rest = line.split(":", 1)
        password = rest.replace("{PLAIN}", "")
        users.append((email.strip(), password.strip()))
    return users


def create_domain(base_url, domain):
    status, body = _api(base_url, "POST", "/api/principal", {
        "type": "domain",
        "name": domain,
    })
    resp = json.loads(body) if body else {}
    if resp.get("error") == "fieldAlreadyExists":
        print(f"  Domain '{domain}' already exists")
    elif status in (200, 201, 204) and "error" not in resp:
        print(f"  Domain '{domain}' created")
    else:
        print(f"  Warning: domain '{domain}' creation returned {status}: {body}")


def create_account(base_url, email, password):
    status, body = _api(base_url, "POST", "/api/principal", {
        "type": "individual",
        "name": email,
        "emails": [email],
        "secrets": [password],
        "roles": ["user"],
    })
    resp = json.loads(body) if body else {}
    if resp.get("error") == "fieldAlreadyExists":
        print(f"  Account '{email}' already exists")
    elif status in (200, 201, 204) and "error" not in resp:
        print(f"  Account '{email}' created")
    else:
        print(f"  Warning: account '{email}' creation returned {status}: {body}")


def main():
    parser = argparse.ArgumentParser(description="Sync Dovecot users into Stalwart")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"Stalwart base URL (default: {DEFAULT_URL})")
    args = parser.parse_args()

    users = parse_users_file()
    if not users:
        print("No users found in config/users")
        return

    print(f"Syncing {len(users)} user(s) to Stalwart at {args.url} ...")

    # Ensure domains exist
    domains = sorted(set(email.split("@")[1] for email, _ in users))
    for domain in domains:
        create_domain(args.url, domain)

    # Create accounts
    for email, password in users:
        create_account(args.url, email, password)

    print("Done.")


if __name__ == "__main__":
    main()
