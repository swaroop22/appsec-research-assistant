"""
Lightweight Local Training Lab Server.

A zero-external-dependency local HTTP server (using standard library http.server)
that simulates common real-world web application patterns and misconfigurations
(such as those found in OWASP Juice Shop).
Allows immediate offline testing, validation, and educational study.
"""

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional


import json
from urllib.parse import parse_qs, urlparse

# Synthetic test accounts for educational local testing
SYNTHETIC_ACCOUNTS = {
    "1": {"id": 1, "username": "bob", "role": "user", "email": "bob@practice.lab", "balance": 150.00},
    "2": {"id": 2, "username": "alice", "role": "user", "email": "alice@practice.lab", "balance": 450.00},
    "99": {"id": 99, "username": "admin_charlie", "role": "admin", "email": "admin@practice.lab", "balance": 9999.00},
}


class MockLabHTTPHandler(BaseHTTPRequestHandler):
    """Handles requests for the local educational vulnerable lab."""

    def log_message(self, format, *args):
        # Suppress noisy standard server logs in console
        pass

    def do_POST(self):
        # Support POST for authentication exercises
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/auth/login", "/login"):
            content_length = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_length).decode("utf-8", errors="ignore") if content_length > 0 else ""
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            # Vulnerability simulation: Session Fixation (reusing existing session or issuing unhardened cookie)
            self.send_header("Set-Cookie", "session_id=sess_synth_alice_fixated_9912; Path=/")
            self.end_headers()
            resp = {
                "status": "authenticated",
                "message": "Simulated authentication successful for synthetic test user.",
                "user": SYNTHETIC_ACCOUNTS["2"],
                "session_fixed": True,
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
        else:
            self.do_GET()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            # Simulate a typical unhardened web app root
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "Express/4.17.1")
            self.send_header("X-Powered-By", "Express")
            self.send_header("Set-Cookie", "session_id=user_token_987213; Path=/")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b"""<!DOCTYPE html>
<html>
<head><title>Local AppSec Practice Lab</title></head>
<body>
<h1>Welcome to the Local AppSec Practice Lab</h1>
<p>This local server simulates typical security misconfigurations for defensive research.</p>
<ul>
    <li><a href="/api/Users/1">User Profile - Bob (Predictable ID)</a></li>
    <li><a href="/api/Users/2">User Profile - Alice (Predictable ID)</a></li>
    <li><a href="/rest/basket/1">User Basket</a></li>
    <li><a href="/admin">Administrative Panel (Unauthenticated)</a></li>
    <li><a href="/admin/login">Admin Login Page (Auth Challenge - Not Vulnerable)</a></li>
    <li><a href="/auth/login">Authentication Endpoint (Session Fixation Simulation)</a></li>
    <li><a href="/auth/session">Session State Inspector</a></li>
    <li><a href="/search?q=test">Search Input Endpoint (Input Reflection Simulation)</a></li>
    <li><a href="/policy">Program Policy & Scope Terms</a></li>
    <li><a href="/hardened">Hardened Endpoint (Defense-in-Depth Comparison)</a></li>
</ul>
</body>
</html>""")

        elif path.startswith("/api/Users/"):
            # IDOR pattern simulation using synthetic test accounts
            user_id = path.rstrip("/").split("/")[-1]
            account = SYNTHETIC_ACCOUNTS.get(user_id, {
                "id": int(user_id) if user_id.isdigit() else 0,
                "username": f"user_{user_id}",
                "role": "user",
                "email": f"user_{user_id}@practice.lab",
                "balance": 0.00,
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Server", "Express/4.17.1")
            self.send_header("Set-Cookie", "auth_token=jwt_xyz_demo; Path=/; SameSite=None")
            self.end_headers()
            self.wfile.write(json.dumps(account).encode("utf-8"))

        elif path.startswith("/rest/basket/"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"basketId": 1, "userId": 1, "products": [{"id": 1, "name": "Apple Juice", "quantity": 2}]}')

        elif path == "/admin":
            # Broken Access Control: Unauthenticated administrative endpoint
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Admin Dashboard</h1><p>Privileged management controls available without login.</p><p>user_management: enabled</p>")

        elif path == "/admin/login":
            # False positive test case: Admin login challenge requiring authentication
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<h1>Sign In to Admin Portal</h1>
<form action="/login" method="POST">
    <input type="text" name="username" placeholder="Username" />
    <input type="password" name="password" placeholder="Password" />
    <button type="submit">Sign In</button>
</form>""")

        elif path in ("/auth/login", "/login"):
            # GET on login endpoint: returns login instruction or demo form
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "pre_auth_cookie=pre_session_fixed_123; Path=/")
            self.end_headers()
            self.wfile.write(b"""<h1>Synthetic Auth Endpoint</h1>
<p>Simulates authentication and session lifecycle testing with synthetic accounts.</p>
<form action="/auth/login" method="POST">
    <input type="text" name="username" value="alice" />
    <input type="password" name="password" value="AlicePass123!" />
    <button type="submit">Authenticate</button>
</form>""")

        elif path == "/auth/session":
            # Session inspector endpoint
            cookie_hdr = self.headers.get("Cookie", "none")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "status": "active_session",
                "received_cookie": cookie_hdr,
                "authenticated_user": SYNTHETIC_ACCOUNTS["2"],
                "note": "Synthetic session inspector for authentication exercise.",
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))

        elif path == "/search":
            # Input validation exercise: safe simulated parameter reflection
            query_val = query.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            resp_html = f"""<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
<h1>Search Results</h1>
<p>Query searched: {query_val}</p>
<div class="results">No items matched your search query.</div>
</body>
</html>"""
            self.wfile.write(resp_html.encode("utf-8"))

        elif path == "/api/echo":
            # API input reflection exercise
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"echo_params": query, "target": "synthetic_lab"}).encode("utf-8"))

        elif path == "/policy":
            # VDP policy endpoint for local training
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            policy_info = {
                "program": "Local AppSec Practice Lab",
                "scope": ["http://127.0.0.1:5000/*", "http://localhost:5000/*"],
                "prohibited": ["DoS", "Brute Force (>10 rps)", "Social Engineering"],
                "rate_limit_rps": 5.0,
                "status": "authorized_educational_environment",
            }
            self.wfile.write(json.dumps(policy_info).encode("utf-8"))

        elif path == "/redirect-out-of-scope":
            # Boundary test case: Attempts to redirect to an unauthorized external target
            self.send_response(302)
            self.send_header("Location", "https://example.com/escaped")
            self.end_headers()

        elif path == "/redirect-internal":
            # Permitted loopback redirect
            self.send_response(302)
            self.send_header("Location", "/hardened")
            self.end_headers()

        elif path == "/hardened":
            # Fully hardened endpoint demonstrating secure defenses
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
            self.send_header("Set-Cookie", "__Host-session=sec_tok_123; Path=/; Secure; HttpOnly; SameSite=Strict")
            self.end_headers()
            self.wfile.write(b"<h1>Hardened Endpoint</h1><p>All recommended defensive headers and cookie flags applied.</p>")

        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")


class LocalLabServer:
    """Manages the background local mock training server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 5000):
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self.server:
            return
        self.server = HTTPServer((self.host, self.port), MockLabHTTPHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            self.thread = None

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"
