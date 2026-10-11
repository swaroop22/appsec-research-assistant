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


class MockLabHTTPHandler(BaseHTTPRequestHandler):
    """Handles requests for the local educational vulnerable lab."""

    def log_message(self, format, *args):
        # Suppress noisy standard server logs in console
        pass

    def do_GET(self):
        path = self.path

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
    <li><a href="/api/Users/1">User Profile (Predictable ID)</a></li>
    <li><a href="/rest/basket/1">User Basket</a></li>
    <li><a href="/admin">Administrative Panel (Unauthenticated)</a></li>
    <li><a href="/admin/login">Admin Login Page (Auth Challenge - Not Vulnerable)</a></li>
    <li><a href="/hardened">Hardened Endpoint (Defense-in-Depth Comparison)</a></li>
</ul>
</body>
</html>""")

        elif path.startswith("/api/Users/"):
            # IDOR pattern simulation
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Server", "Express/4.17.1")
            self.send_header("Set-Cookie", "auth_token=jwt_xyz_demo; Path=/; SameSite=None")
            self.end_headers()
            self.wfile.write(b'{"id": 1, "username": "admin@juice-sh.op", "role": "admin", "email": "admin@juice-sh.op"}')

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
