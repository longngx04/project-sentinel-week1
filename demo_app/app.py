#!/usr/bin/env python3
"""
Intentionally vulnerable demo app for testing the security scan workflow.
DO NOT deploy or use in production.
"""

from __future__ import annotations

import hashlib
import os
import pickle
import sqlite3
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# Hardcoded credentials / secrets (Semgrep: secrets, hardcoded password)
DB_PASSWORD = "admin123"
API_KEY = "sk-live-super-secret-key-do-not-share"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def weak_password_hash(password: str) -> str:
    # Weak hashing: MD5 for passwords
    return hashlib.md5(password.encode()).hexdigest()


def lookup_user(username: str) -> list:
    # SQL injection: unsanitized string formatting
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER, username TEXT, role TEXT)")
    cur.execute("INSERT INTO users VALUES (1, 'alice', 'user'), (2, 'admin', 'admin')")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return rows


def run_ping(host: str) -> str:
    # Command injection: shell=True with user input
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return output


def load_session(blob: bytes):
    # Insecure deserialization
    return pickle.loads(blob)


def read_user_file(filename: str) -> str:
    # Path traversal: joins user input onto a base directory without sanitizing
    base = "/tmp/uploads"
    path = os.path.join(base, filename)
    with open(path, encoding="utf-8") as f:
        return f.read()


def evaluate_expression(expr: str):
    # Dangerous dynamic evaluation
    return eval(expr)


class VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        path = parsed.path

        try:
            if path == "/user":
                username = params.get("name", ["guest"])[0]
                body = str(lookup_user(username))
            elif path == "/ping":
                host = params.get("host", ["127.0.0.1"])[0]
                body = run_ping(host)
            elif path == "/calc":
                expr = params.get("expr", ["1+1"])[0]
                body = str(evaluate_expression(expr))
            elif path == "/file":
                name = params.get("name", ["readme.txt"])[0]
                body = read_user_file(name)
            elif path == "/hash":
                password = params.get("password", ["password"])[0]
                body = weak_password_hash(password)
            else:
                body = (
                    "Vulnerable demo endpoints:\n"
                    "  /user?name=alice\n"
                    "  /ping?host=127.0.0.1\n"
                    "  /calc?expr=1+1\n"
                    "  /file?name=readme.txt\n"
                    "  /hash?password=secret\n"
                )
            status = 200
        except Exception as exc:  # noqa: BLE001 - demo only
            body = f"error: {exc}"
            status = 500

        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        # Missing security headers on purpose (for DAST demos)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:
        return


def main() -> None:
    # Debug mode / bind all interfaces intentionally for the demo
    host, port = "0.0.0.0", 8080
    print(f"Starting vulnerable demo on http://{host}:{port}")
    print(f"Using DB password={DB_PASSWORD} api_key={API_KEY}")
    HTTPServer((host, port), VulnerableHandler).serve_forever()


if __name__ == "__main__":
    main()
