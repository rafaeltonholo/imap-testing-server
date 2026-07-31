#!/usr/bin/env python3
"""Generate a self-signed TLS certificate for local development.

Run once after a fresh clone, before starting the containers.
"""

import subprocess
import sys
from lib import SSL_DIR


def main():
    SSL_DIR.mkdir(parents=True, exist_ok=True)

    cert = SSL_DIR / "tls.crt"
    key = SSL_DIR / "tls.key"

    if cert.exists() and key.exists():
        print("SSL certificates already exist in ssl/. Skipping generation.")
        print("To regenerate, delete ssl/tls.crt and ssl/tls.key first.")
        return

    subprocess.run(
        [
            "openssl", "req", "-x509", "-nodes",
            "-days", "365", "-newkey", "rsa:2048",
            "-keyout", str(key),
            "-out", str(cert),
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )

    print("SSL certificates generated in ssl/.")
    print("You can now run: docker-compose up -d")


if __name__ == "__main__":
    main()
