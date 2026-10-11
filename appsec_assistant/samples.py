"""
Sample Captured HTTP Responses for Testing and Demonstrations.

Provides realistic presets of insecure, partially configured, and fully hardened
HTTP responses to test the security headers and cookie analyzers.
"""

from typing import Dict, Any


SAMPLE_INSECURE_PHP = """HTTP/1.1 200 OK
Date: Sat, 10 Oct 2026 20:15:00 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
Content-Type: text/html; charset=UTF-8
Set-Cookie: PHPSESSID=d41d8cd98f00b204e9800998ecf8427e; path=/
Set-Cookie: user_role=standard_user; path=/

<!DOCTYPE html>
<html lang="en">
<head>
    <title>Internal Dashboard</title>
</head>
<body>
    <h1>Welcome, Employee</h1>
    <p>Internal employee portal session active.</p>
</body>
</html>"""


SAMPLE_API_EXPRESS = """HTTP/1.1 200 OK
Date: Sat, 10 Oct 2026 20:20:00 GMT
Server: express
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Content-Type: application/json; charset=utf-8
X-Content-Type-Options: nosniff
Set-Cookie: jwt_auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; Path=/api; Secure
Set-Cookie: preferences=theme_dark; Path=/

{
    "status": "success",
    "user_id": 402,
    "role": "editor",
    "profile": {
        "email": "researcher@example.local",
        "verified": true
    }
}"""


SAMPLE_WEAK_DIRECTIVES = """HTTP/1.1 200 OK
Date: Sat, 10 Oct 2026 20:25:00 GMT
Server: nginx
Content-Type: text/html; charset=UTF-8
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src *;
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer-when-downgrade
Set-Cookie: session_id=s%3A7a8b9c0d1e2f; Path=/; Secure; HttpOnly; SameSite=None

<!DOCTYPE html>
<html>
<head>
    <title>Staging App</title>
</head>
<body>
    <script>eval("console.log('Testing unsafe-eval')");</script>
</body>
</html>"""


SAMPLE_HARDENED = """HTTP/1.1 200 OK
Date: Sat, 10 Oct 2026 20:30:00 GMT
Content-Type: text/html; charset=UTF-8
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-EDNnf03nceI1nnq'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Set-Cookie: __Host-session=f98a72b6c10d3e5a; Path=/; Secure; HttpOnly; SameSite=Strict

<!DOCTYPE html>
<html lang="en">
<head>
    <title>Secure Banking Portal</title>
</head>
<body>
    <h1>Hardened Session Active</h1>
</body>
</html>"""


SAMPLE_PRESETS: Dict[str, Dict[str, Any]] = {
    "Insecure Legacy App (PHP/Apache)": {
        "description": "Missing all security headers (CSP, HSTS, X-Content-Type-Options, Referrer-Policy, XFO), leaks Server/PHP banners, and sets cookies without HttpOnly, Secure, or SameSite.",
        "expected_issues": "Critical/High cookie exposure, missing CSP, missing HSTS, missing XCTO, missing Referrer-Policy",
        "content": SAMPLE_INSECURE_PHP,
    },
    "Express API with CORS & Cookie Flaws": {
        "description": "Sets nosniff, but has wildcard CORS origin (*), leaks Express header, and sensitive JWT auth cookie is missing HttpOnly and SameSite.",
        "expected_issues": "High priority missing HttpOnly on jwt_auth_token, wildcard CORS, missing CSP & Referrer-Policy",
        "content": SAMPLE_API_EXPRESS,
    },
    "Partially Configured App with Weak Policies": {
        "description": "Has CSP and XFO, but CSP contains unsafe-inline and unsafe-eval, Referrer-Policy is permissive, and session cookie has SameSite=None.",
        "expected_issues": "Low priority weak CSP, weak Referrer-Policy, Medium priority SameSite=None",
        "content": SAMPLE_WEAK_DIRECTIVES,
    },
    "Fully Hardened Enterprise App": {
        "description": "Implements defense-in-depth with strict CSP (nonce), HSTS preload, XFO DENY, nosniff, strict-origin Referrer-Policy, Permissions-Policy, stripped server banners, and __Host- prefixed Strict cookie.",
        "expected_issues": "Zero security vulnerabilities; maximum defensive grade.",
        "content": SAMPLE_HARDENED,
    },
}
