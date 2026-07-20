#!/usr/bin/env python3
"""
Intentionally vulnerable demo app for SAST testing.
DO NOT deploy to production.
"""

from __future__ import annotations

import hashlib
import os
import pickle
import sqlite3
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# Hardcoded secrets (detectable by Semgrep)
DB_PASSWORD = "admin123"
API_KEY = "sk-live-super-secret-key-do-not-share"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def weak_password_hash(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def lookup_user(username: str) -> list:
    # SQL injection via string formatting
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
    # Command injection
    return subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)


def load_session(blob: bytes):
    # Insecure deserialization
    return pickle.loads(blob)


def read_user_file(filename: str) -> str:
    # Path traversal
    path = os.path.join("/tmp/uploads", filename)
    with open(path, encoding="utf-8") as f:
        return f.read()


def evaluate_expression(expr: str):
    # Dangerous eval
    return eval(expr)


class VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        path = parsed.path

        try:
            if path == "/health":
                body = "ok"
            elif path == "/user":
                body = str(lookup_user(params.get("name", ["guest"])[0]))
            elif path == "/ping":
                body = run_ping(params.get("host", ["127.0.0.1"])[0])
            elif path == "/calc":
                body = str(evaluate_expression(params.get("expr", ["1+1"])[0]))
            elif path == "/file":
                body = read_user_file(params.get("name", ["readme.txt"])[0])
            elif path == "/hash":
                body = weak_password_hash(params.get("password", ["password"])[0])
            else:
                body = (
                    "Vulnerable demo endpoints:\n"
                    "  GET /health\n"
                    "  GET /user?name=alice\n"
                    "  GET /ping?host=127.0.0.1\n"
                    "  GET /calc?expr=1+1\n"
                    "  GET /file?name=readme.txt\n"
                    "  GET /hash?password=secret\n"
                )
            status = 200
        except Exception as exc:  # noqa: BLE001 - demo only
            body = f"error: {exc}"
            status = 500

        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:
        return


def main() -> None:
    host, port = "0.0.0.0", 8080
    print(f"Starting vulnerable demo on http://{host}:{port}")
    print(f"Using DB password={DB_PASSWORD} api_key={API_KEY}")
    HTTPServer((host, port), VulnerableHandler).serve_forever()


if __name__ == "__main__":
    main()
