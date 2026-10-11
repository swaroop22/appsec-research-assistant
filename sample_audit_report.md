# Local Web Application Security Audit

> **Defensive Application Security Assessment Report**
> *Confidential - Educational & Remediation Purpose Only*

## 1. Executive Summary

- **Target Application:** `http://127.0.0.1:5000`
- **Assessment Date:** 2026-10-11 00:25:42 UTC
- **Total Findings:** 27
- **Assessor Tool:** AppSec Research Assistant v1.0

### Severity Distribution

| Severity | Count | Risk Level |
| :--- | :---: | :--- |
| 🔴 **CRITICAL** | 1 | Immediate remediation required |
| 🟠 **HIGH**     | 4     | High business/security impact |
| 🟡 **MEDIUM**   | 12   | Defensive mitigation recommended |
| 🟢 **LOW**      | 10      | Security best practice hygiene |
| 🔵 **INFO**     | 0     | Informational observation |

---

## 2. Table of Findings

| ID | Title | Category | Severity | CWE |
| :--- | :--- | :--- | :--- | :--- |
| `SEC-AC-002` | Unauthenticated Access to Administrative Endpoint: '/admin' | Broken Access Control | 🔴 Critical | `CWE-306` |
| `SEC-CK-001-session_id` | Cookie Missing HttpOnly Flag: 'session_id' | Cookie Security | 🟠 High | `CWE-1004` |
| `SEC-CK-001-auth_token` | Cookie Missing HttpOnly Flag: 'auth_token' | Cookie Security | 🟠 High | `CWE-1004` |
| `SEC-AC-001` | Potential Insecure Direct Object Reference (IDOR) in '/Users/1' | Broken Access Control | 🟠 High | `CWE-639` |
| `SEC-AC-001` | Potential Insecure Direct Object Reference (IDOR) in '/basket/1' | Broken Access Control | 🟠 High | `CWE-639` |
| `SEC-HDR-001` | Missing Content-Security-Policy (CSP) Header | Security Headers | 🟡 Medium | `CWE-1021` |
| `SEC-HDR-003` | Missing Clickjacking Protection (X-Frame-Options / frame-ancestors) | Security Headers | 🟡 Medium | `CWE-1021` |
| `SEC-CK-002-session_id` | Cookie Missing Secure Flag: 'session_id' | Cookie Security | 🟡 Medium | `CWE-614` |
| `SEC-CK-003-session_id` | Cookie Missing or Weak SameSite Attribute: 'session_id' | Cookie Security | 🟡 Medium | `CWE-1275` |
| `SEC-HDR-001` | Missing Content-Security-Policy (CSP) Header | Security Headers | 🟡 Medium | `CWE-1021` |
| `SEC-HDR-003` | Missing Clickjacking Protection (X-Frame-Options / frame-ancestors) | Security Headers | 🟡 Medium | `CWE-1021` |
| `SEC-CK-002-auth_token` | Cookie Missing Secure Flag: 'auth_token' | Cookie Security | 🟡 Medium | `CWE-614` |
| `SEC-CK-003-auth_token` | Cookie Missing or Weak SameSite Attribute: 'auth_token' | Cookie Security | 🟡 Medium | `CWE-1275` |
| `SEC-HDR-001` | Missing Content-Security-Policy (CSP) Header | Security Headers | 🟡 Medium | `CWE-1021` |
| `SEC-HDR-003` | Missing Clickjacking Protection (X-Frame-Options / frame-ancestors) | Security Headers | 🟡 Medium | `CWE-1021` |
| `SEC-HDR-001` | Missing Content-Security-Policy (CSP) Header | Security Headers | 🟡 Medium | `CWE-1021` |
| `SEC-HDR-003` | Missing Clickjacking Protection (X-Frame-Options / frame-ancestors) | Security Headers | 🟡 Medium | `CWE-1021` |
| `SEC-HDR-004` | Missing X-Content-Type-Options: nosniff Header | Security Headers | 🟢 Low | `CWE-16` |
| `SEC-HDR-006` | Information Disclosure via Server / Framework Headers | Information Exposure | 🟢 Low | `CWE-200` |
| `SEC-HDR-007` | Wildcard Cross-Origin Resource Sharing (CORS) Origin | Access Control | 🟢 Low | `CWE-346` |
| `SEC-HDR-004` | Missing X-Content-Type-Options: nosniff Header | Security Headers | 🟢 Low | `CWE-16` |
| `SEC-HDR-006` | Information Disclosure via Server / Framework Headers | Information Exposure | 🟢 Low | `CWE-200` |
| `SEC-HDR-004` | Missing X-Content-Type-Options: nosniff Header | Security Headers | 🟢 Low | `CWE-16` |
| `SEC-HDR-006` | Information Disclosure via Server / Framework Headers | Information Exposure | 🟢 Low | `CWE-200` |
| `SEC-HDR-004` | Missing X-Content-Type-Options: nosniff Header | Security Headers | 🟢 Low | `CWE-16` |
| `SEC-HDR-006` | Information Disclosure via Server / Framework Headers | Information Exposure | 🟢 Low | `CWE-200` |
| `SEC-HDR-006` | Information Disclosure via Server / Framework Headers | Information Exposure | 🟢 Low | `CWE-200` |

---

## 3. Detailed Vulnerability Analyses

### 3.1. [SEC-AC-002] Unauthenticated Access to Administrative Endpoint: '/admin'

- **Severity:** **CRITICAL**
- **Category:** Broken Access Control
- **Affected URL:** `http://127.0.0.1:5000/admin`
- **OWASP Classification:** A01:2021-Broken Access Control
- **CWE Identifier:** CWE-306

#### Description
The sensitive endpoint '/admin' returned HTTP 200 OK without any Authorization header or authentication credentials provided in the request.

#### Security Impact
Direct administrative access without authentication allows unauthorized users to perform privileged operations, view confidential telemetry, or compromise the entire application.

#### Evidence & Reproduction Artifact
```text
GET /admin returned HTTP 200 OK without Authorization headers present.
```

#### Recommended Remediation
Enforce strict authentication and Role-Based Access Control (RBAC) middleware across all administrative routes. Ensure access is denied by default (401/403) unless an explicit administrative session is validated.

#### References & Standards
- [https://owasp.org/Top10/A01_2021-Broken_Access_Control/](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

### 3.2. [SEC-CK-001-session_id] Cookie Missing HttpOnly Flag: 'session_id'

- **Severity:** **HIGH**
- **Category:** Cookie Security
- **Affected URL:** `http://127.0.0.1:5000/`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-1004

#### Description
The cookie 'session_id' was set without the 'HttpOnly' attribute. This flag instructs client browsers that the cookie cannot be accessed via client-side scripts (e.g. `document.cookie`).

#### Security Impact
If any Cross-Site Scripting (XSS) vulnerability exists on the application, an attacker can directly read 'session_id' from JavaScript and exfiltrate user session tokens, leading directly to Account Takeover.

#### Evidence & Reproduction Artifact
```text
Cookie: session_id; Attributes: Secure=False, HttpOnly=False, SameSite=None
```

#### Recommended Remediation
Set the HttpOnly flag on 'session_id'.
Example in Express/Node.js:
`res.cookie('session_id', token, { httpOnly: true, secure: true, sameSite: 'lax' });`

#### References & Standards
- [https://owasp.org/www-community/HttpOnly](https://owasp.org/www-community/HttpOnly)
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies)

---

### 3.3. [SEC-CK-001-auth_token] Cookie Missing HttpOnly Flag: 'auth_token'

- **Severity:** **HIGH**
- **Category:** Cookie Security
- **Affected URL:** `http://127.0.0.1:5000/api/Users/1`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-1004

#### Description
The cookie 'auth_token' was set without the 'HttpOnly' attribute. This flag instructs client browsers that the cookie cannot be accessed via client-side scripts (e.g. `document.cookie`).

#### Security Impact
If any Cross-Site Scripting (XSS) vulnerability exists on the application, an attacker can directly read 'auth_token' from JavaScript and exfiltrate user session tokens, leading directly to Account Takeover.

#### Evidence & Reproduction Artifact
```text
Cookie: auth_token; Attributes: Secure=False, HttpOnly=False, SameSite=None
```

#### Recommended Remediation
Set the HttpOnly flag on 'auth_token'.
Example in Express/Node.js:
`res.cookie('auth_token', token, { httpOnly: true, secure: true, sameSite: 'lax' });`

#### References & Standards
- [https://owasp.org/www-community/HttpOnly](https://owasp.org/www-community/HttpOnly)
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies)

---

### 3.4. [SEC-AC-001] Potential Insecure Direct Object Reference (IDOR) in '/Users/1'

- **Severity:** **HIGH**
- **Category:** Broken Access Control
- **Affected URL:** `http://127.0.0.1:5000/api/Users/1`
- **OWASP Classification:** A01:2021-Broken Access Control
- **CWE Identifier:** CWE-639

#### Description
The endpoint references private user resources ('Users') via sequential, predictable integer identifiers ('1'). If the backend relies solely on the client-supplied identifier without verifying that the authenticated user owns this resource, horizontal or vertical privilege escalation occurs.

#### Security Impact
An attacker can iterate through sequential IDs (e.g., 1, 2, 3...) to view, modify, or delete other users' records, orders, or personally identifiable information (PII).

#### Evidence & Reproduction Artifact
```text
Request URL contains predictable resource identifier: /api/Users/1
```

#### Recommended Remediation
1. Implement server-side authorization checks on every data access call: verify `resource.owner_id == session.current_user_id`.
2. Use non-sequential, cryptographically unguessable identifiers (e.g., UUIDv4) instead of auto-incrementing database primary keys.
3. Rely on session context rather than client-supplied parameters for user identity.

#### References & Standards
- [https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [https://portswigger.net/web-security/access-control/idor](https://portswigger.net/web-security/access-control/idor)

---

### 3.5. [SEC-AC-001] Potential Insecure Direct Object Reference (IDOR) in '/basket/1'

- **Severity:** **HIGH**
- **Category:** Broken Access Control
- **Affected URL:** `http://127.0.0.1:5000/rest/basket/1`
- **OWASP Classification:** A01:2021-Broken Access Control
- **CWE Identifier:** CWE-639

#### Description
The endpoint references private user resources ('basket') via sequential, predictable integer identifiers ('1'). If the backend relies solely on the client-supplied identifier without verifying that the authenticated user owns this resource, horizontal or vertical privilege escalation occurs.

#### Security Impact
An attacker can iterate through sequential IDs (e.g., 1, 2, 3...) to view, modify, or delete other users' records, orders, or personally identifiable information (PII).

#### Evidence & Reproduction Artifact
```text
Request URL contains predictable resource identifier: /rest/basket/1
```

#### Recommended Remediation
1. Implement server-side authorization checks on every data access call: verify `resource.owner_id == session.current_user_id`.
2. Use non-sequential, cryptographically unguessable identifiers (e.g., UUIDv4) instead of auto-incrementing database primary keys.
3. Rely on session context rather than client-supplied parameters for user identity.

#### References & Standards
- [https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [https://portswigger.net/web-security/access-control/idor](https://portswigger.net/web-security/access-control/idor)

---

### 3.6. [SEC-HDR-001] Missing Content-Security-Policy (CSP) Header

- **Severity:** **MEDIUM**
- **Category:** Security Headers
- **Affected URL:** `http://127.0.0.1:5000/`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-1021

#### Description
The application does not enforce a Content-Security-Policy header. CSP is a critical defense-in-depth mechanism that instructs the browser which dynamic resources (scripts, styles, images, frames) are permitted to load.

#### Security Impact
Without CSP, the browser will execute any injected scripts, significantly increasing susceptibility to Cross-Site Scripting (XSS), data exfiltration, and unauthorized script execution.

#### Evidence & Reproduction Artifact
```text
HTTP/200 Response Headers contain no 'Content-Security-Policy'.
```

#### Recommended Remediation
Define and deploy a strict Content-Security-Policy. Start with a baseline policy:
`Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';`
Use nonce-based or hash-based CSP for modern single-page applications.

#### References & Standards
- [https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

### 3.7. [SEC-HDR-003] Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)

- **Severity:** **MEDIUM**
- **Category:** Security Headers
- **Affected URL:** `http://127.0.0.1:5000/`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-1021

#### Description
Neither 'X-Frame-Options' nor CSP 'frame-ancestors' was supplied. This permits third-party websites to embed this web application within an iframe.

#### Security Impact
Attackers can mount Clickjacking (UI Redressing) attacks, deceiving authenticated users into clicking hidden buttons or executing unintended transactions.

#### Evidence & Reproduction Artifact
```text
Headers contain neither 'X-Frame-Options' nor 'frame-ancestors' directive in CSP.
```

#### Recommended Remediation
Add the X-Frame-Options header with value 'DENY' or 'SAMEORIGIN':
`X-Frame-Options: DENY`
Or configure CSP: `frame-ancestors 'none';`

#### References & Standards
- [https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)

---

### 3.8. [SEC-CK-002-session_id] Cookie Missing Secure Flag: 'session_id'

- **Severity:** **MEDIUM**
- **Category:** Cookie Security
- **Affected URL:** `http://127.0.0.1:5000/`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-614

#### Description
The cookie 'session_id' does not include the 'Secure' attribute. The Secure flag ensures that the cookie is transmitted only over encrypted TLS (HTTPS) connections.

#### Security Impact
Without the Secure flag, browsers may transmit the cookie in plaintext if an unencrypted HTTP link is followed, allowing passive eavesdroppers on untrusted networks (e.g. public Wi-Fi) to intercept the cookie.

#### Evidence & Reproduction Artifact
```text
Cookie: session_id; Secure flag is False.
```

#### Recommended Remediation
Add the 'Secure' attribute to 'session_id': `Set-Cookie: session_id=...; Secure; HttpOnly; SameSite=Lax`

#### References & Standards
- [https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies_attributes](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies_attributes)

---

### 3.9. [SEC-CK-003-session_id] Cookie Missing or Weak SameSite Attribute: 'session_id'

- **Severity:** **MEDIUM**
- **Category:** Cookie Security
- **Affected URL:** `http://127.0.0.1:5000/`
- **OWASP Classification:** A01:2021-Broken Access Control
- **CWE Identifier:** CWE-1275

#### Description
The cookie 'session_id' either omits the SameSite attribute or sets it to 'None'. SameSite dictates whether cookies are sent along with cross-site requests.

#### Security Impact
Absence of SameSite protection makes the application vulnerable to Cross-Site Request Forgery (CSRF), allowing malicious external sites to perform unauthorized authenticated actions on behalf of the victim.

#### Evidence & Reproduction Artifact
```text
Cookie: session_id; SameSite=None
```

#### Recommended Remediation
Set `SameSite=Lax` (standard for web navigation) or `SameSite=Strict` for sensitive API cookies.

#### References & Standards
- [https://web.dev/articles/samesite-cookies-explained](https://web.dev/articles/samesite-cookies-explained)

---

### 3.10. [SEC-HDR-001] Missing Content-Security-Policy (CSP) Header

- **Severity:** **MEDIUM**
- **Category:** Security Headers
- **Affected URL:** `http://127.0.0.1:5000/api/Users/1`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-1021

#### Description
The application does not enforce a Content-Security-Policy header. CSP is a critical defense-in-depth mechanism that instructs the browser which dynamic resources (scripts, styles, images, frames) are permitted to load.

#### Security Impact
Without CSP, the browser will execute any injected scripts, significantly increasing susceptibility to Cross-Site Scripting (XSS), data exfiltration, and unauthorized script execution.

#### Evidence & Reproduction Artifact
```text
HTTP/200 Response Headers contain no 'Content-Security-Policy'.
```

#### Recommended Remediation
Define and deploy a strict Content-Security-Policy. Start with a baseline policy:
`Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';`
Use nonce-based or hash-based CSP for modern single-page applications.

#### References & Standards
- [https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

### 3.11. [SEC-HDR-003] Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)

- **Severity:** **MEDIUM**
- **Category:** Security Headers
- **Affected URL:** `http://127.0.0.1:5000/api/Users/1`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-1021

#### Description
Neither 'X-Frame-Options' nor CSP 'frame-ancestors' was supplied. This permits third-party websites to embed this web application within an iframe.

#### Security Impact
Attackers can mount Clickjacking (UI Redressing) attacks, deceiving authenticated users into clicking hidden buttons or executing unintended transactions.

#### Evidence & Reproduction Artifact
```text
Headers contain neither 'X-Frame-Options' nor 'frame-ancestors' directive in CSP.
```

#### Recommended Remediation
Add the X-Frame-Options header with value 'DENY' or 'SAMEORIGIN':
`X-Frame-Options: DENY`
Or configure CSP: `frame-ancestors 'none';`

#### References & Standards
- [https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)

---

### 3.12. [SEC-CK-002-auth_token] Cookie Missing Secure Flag: 'auth_token'

- **Severity:** **MEDIUM**
- **Category:** Cookie Security
- **Affected URL:** `http://127.0.0.1:5000/api/Users/1`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-614

#### Description
The cookie 'auth_token' does not include the 'Secure' attribute. The Secure flag ensures that the cookie is transmitted only over encrypted TLS (HTTPS) connections.

#### Security Impact
Without the Secure flag, browsers may transmit the cookie in plaintext if an unencrypted HTTP link is followed, allowing passive eavesdroppers on untrusted networks (e.g. public Wi-Fi) to intercept the cookie.

#### Evidence & Reproduction Artifact
```text
Cookie: auth_token; Secure flag is False.
```

#### Recommended Remediation
Add the 'Secure' attribute to 'auth_token': `Set-Cookie: auth_token=...; Secure; HttpOnly; SameSite=Lax`

#### References & Standards
- [https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies_attributes](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies_attributes)

---

### 3.13. [SEC-CK-003-auth_token] Cookie Missing or Weak SameSite Attribute: 'auth_token'

- **Severity:** **MEDIUM**
- **Category:** Cookie Security
- **Affected URL:** `http://127.0.0.1:5000/api/Users/1`
- **OWASP Classification:** A01:2021-Broken Access Control
- **CWE Identifier:** CWE-1275

#### Description
The cookie 'auth_token' either omits the SameSite attribute or sets it to 'None'. SameSite dictates whether cookies are sent along with cross-site requests.

#### Security Impact
Absence of SameSite protection makes the application vulnerable to Cross-Site Request Forgery (CSRF), allowing malicious external sites to perform unauthorized authenticated actions on behalf of the victim.

#### Evidence & Reproduction Artifact
```text
Cookie: auth_token; SameSite=None
```

#### Recommended Remediation
Set `SameSite=Lax` (standard for web navigation) or `SameSite=Strict` for sensitive API cookies.

#### References & Standards
- [https://web.dev/articles/samesite-cookies-explained](https://web.dev/articles/samesite-cookies-explained)

---

### 3.14. [SEC-HDR-001] Missing Content-Security-Policy (CSP) Header

- **Severity:** **MEDIUM**
- **Category:** Security Headers
- **Affected URL:** `http://127.0.0.1:5000/rest/basket/1`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-1021

#### Description
The application does not enforce a Content-Security-Policy header. CSP is a critical defense-in-depth mechanism that instructs the browser which dynamic resources (scripts, styles, images, frames) are permitted to load.

#### Security Impact
Without CSP, the browser will execute any injected scripts, significantly increasing susceptibility to Cross-Site Scripting (XSS), data exfiltration, and unauthorized script execution.

#### Evidence & Reproduction Artifact
```text
HTTP/200 Response Headers contain no 'Content-Security-Policy'.
```

#### Recommended Remediation
Define and deploy a strict Content-Security-Policy. Start with a baseline policy:
`Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';`
Use nonce-based or hash-based CSP for modern single-page applications.

#### References & Standards
- [https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

### 3.15. [SEC-HDR-003] Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)

- **Severity:** **MEDIUM**
- **Category:** Security Headers
- **Affected URL:** `http://127.0.0.1:5000/rest/basket/1`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-1021

#### Description
Neither 'X-Frame-Options' nor CSP 'frame-ancestors' was supplied. This permits third-party websites to embed this web application within an iframe.

#### Security Impact
Attackers can mount Clickjacking (UI Redressing) attacks, deceiving authenticated users into clicking hidden buttons or executing unintended transactions.

#### Evidence & Reproduction Artifact
```text
Headers contain neither 'X-Frame-Options' nor 'frame-ancestors' directive in CSP.
```

#### Recommended Remediation
Add the X-Frame-Options header with value 'DENY' or 'SAMEORIGIN':
`X-Frame-Options: DENY`
Or configure CSP: `frame-ancestors 'none';`

#### References & Standards
- [https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)

---

### 3.16. [SEC-HDR-001] Missing Content-Security-Policy (CSP) Header

- **Severity:** **MEDIUM**
- **Category:** Security Headers
- **Affected URL:** `http://127.0.0.1:5000/admin`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-1021

#### Description
The application does not enforce a Content-Security-Policy header. CSP is a critical defense-in-depth mechanism that instructs the browser which dynamic resources (scripts, styles, images, frames) are permitted to load.

#### Security Impact
Without CSP, the browser will execute any injected scripts, significantly increasing susceptibility to Cross-Site Scripting (XSS), data exfiltration, and unauthorized script execution.

#### Evidence & Reproduction Artifact
```text
HTTP/200 Response Headers contain no 'Content-Security-Policy'.
```

#### Recommended Remediation
Define and deploy a strict Content-Security-Policy. Start with a baseline policy:
`Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';`
Use nonce-based or hash-based CSP for modern single-page applications.

#### References & Standards
- [https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

### 3.17. [SEC-HDR-003] Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)

- **Severity:** **MEDIUM**
- **Category:** Security Headers
- **Affected URL:** `http://127.0.0.1:5000/admin`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-1021

#### Description
Neither 'X-Frame-Options' nor CSP 'frame-ancestors' was supplied. This permits third-party websites to embed this web application within an iframe.

#### Security Impact
Attackers can mount Clickjacking (UI Redressing) attacks, deceiving authenticated users into clicking hidden buttons or executing unintended transactions.

#### Evidence & Reproduction Artifact
```text
Headers contain neither 'X-Frame-Options' nor 'frame-ancestors' directive in CSP.
```

#### Recommended Remediation
Add the X-Frame-Options header with value 'DENY' or 'SAMEORIGIN':
`X-Frame-Options: DENY`
Or configure CSP: `frame-ancestors 'none';`

#### References & Standards
- [https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)

---

### 3.18. [SEC-HDR-004] Missing X-Content-Type-Options: nosniff Header

- **Severity:** **LOW**
- **Category:** Security Headers
- **Affected URL:** `http://127.0.0.1:5000/`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-16

#### Description
The 'X-Content-Type-Options: nosniff' header is missing or improperly configured. This header prevents browsers from MIME-sniffing a response away from the declared Content-Type.

#### Security Impact
An attacker may upload a file with an innocent MIME type (e.g. image/png) that contains executable script tags. Without 'nosniff', legacy browsers may execute it as HTML/JavaScript.

#### Evidence & Reproduction Artifact
```text
X-Content-Type-Options: Not Set
```

#### Recommended Remediation
Set `X-Content-Type-Options: nosniff` across all HTTP responses.

#### References & Standards
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)

---

### 3.19. [SEC-HDR-006] Information Disclosure via Server / Framework Headers

- **Severity:** **LOW**
- **Category:** Information Exposure
- **Affected URL:** `http://127.0.0.1:5000/`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-200

#### Description
The server advertises granular version or framework details in response headers: Server: BaseHTTP/0.6 Python/3.7.6, Express/4.17.1, X-Powered-By: Express.

#### Security Impact
Reveals server software and versions, allowing adversaries to look up published CVEs and tailor exploitation vectors against known technology stacks.

#### Evidence & Reproduction Artifact
```text
Server: BaseHTTP/0.6 Python/3.7.6, Express/4.17.1; X-Powered-By: Express
```

#### Recommended Remediation
Disable or obfuscate banner headers in your web server/reverse proxy configuration:
- Express.js: `app.disable('x-powered-by')`
- Nginx: `server_tokens off;`
- Apache: `ServerTokens Prod` and `ServerSignature Off`

#### References & Standards
- [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)

---

### 3.20. [SEC-HDR-007] Wildcard Cross-Origin Resource Sharing (CORS) Origin

- **Severity:** **LOW**
- **Category:** Access Control
- **Affected URL:** `http://127.0.0.1:5000/`
- **OWASP Classification:** A01:2021-Broken Access Control
- **CWE Identifier:** CWE-346

#### Description
The endpoint responds with `Access-Control-Allow-Origin: *`. Any origin in the world is permitted to read public responses from this API.

#### Security Impact
While acceptable for strictly public read-only content, wildcard origins on private or sensitive APIs can allow third-party scripts in a victim's browser to read sensitive data.

#### Evidence & Reproduction Artifact
```text
Access-Control-Allow-Origin: *
```

#### Recommended Remediation
Avoid wildcard origins on sensitive endpoints. Maintain an explicit allowlist of trusted domains and validate incoming `Origin` headers before responding.

#### References & Standards
- [https://portswigger.net/web-security/cors](https://portswigger.net/web-security/cors)

---

### 3.21. [SEC-HDR-004] Missing X-Content-Type-Options: nosniff Header

- **Severity:** **LOW**
- **Category:** Security Headers
- **Affected URL:** `http://127.0.0.1:5000/api/Users/1`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-16

#### Description
The 'X-Content-Type-Options: nosniff' header is missing or improperly configured. This header prevents browsers from MIME-sniffing a response away from the declared Content-Type.

#### Security Impact
An attacker may upload a file with an innocent MIME type (e.g. image/png) that contains executable script tags. Without 'nosniff', legacy browsers may execute it as HTML/JavaScript.

#### Evidence & Reproduction Artifact
```text
X-Content-Type-Options: Not Set
```

#### Recommended Remediation
Set `X-Content-Type-Options: nosniff` across all HTTP responses.

#### References & Standards
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)

---

### 3.22. [SEC-HDR-006] Information Disclosure via Server / Framework Headers

- **Severity:** **LOW**
- **Category:** Information Exposure
- **Affected URL:** `http://127.0.0.1:5000/api/Users/1`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-200

#### Description
The server advertises granular version or framework details in response headers: Server: BaseHTTP/0.6 Python/3.7.6, Express/4.17.1.

#### Security Impact
Reveals server software and versions, allowing adversaries to look up published CVEs and tailor exploitation vectors against known technology stacks.

#### Evidence & Reproduction Artifact
```text
Server: BaseHTTP/0.6 Python/3.7.6, Express/4.17.1
```

#### Recommended Remediation
Disable or obfuscate banner headers in your web server/reverse proxy configuration:
- Express.js: `app.disable('x-powered-by')`
- Nginx: `server_tokens off;`
- Apache: `ServerTokens Prod` and `ServerSignature Off`

#### References & Standards
- [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)

---

### 3.23. [SEC-HDR-004] Missing X-Content-Type-Options: nosniff Header

- **Severity:** **LOW**
- **Category:** Security Headers
- **Affected URL:** `http://127.0.0.1:5000/rest/basket/1`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-16

#### Description
The 'X-Content-Type-Options: nosniff' header is missing or improperly configured. This header prevents browsers from MIME-sniffing a response away from the declared Content-Type.

#### Security Impact
An attacker may upload a file with an innocent MIME type (e.g. image/png) that contains executable script tags. Without 'nosniff', legacy browsers may execute it as HTML/JavaScript.

#### Evidence & Reproduction Artifact
```text
X-Content-Type-Options: Not Set
```

#### Recommended Remediation
Set `X-Content-Type-Options: nosniff` across all HTTP responses.

#### References & Standards
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)

---

### 3.24. [SEC-HDR-006] Information Disclosure via Server / Framework Headers

- **Severity:** **LOW**
- **Category:** Information Exposure
- **Affected URL:** `http://127.0.0.1:5000/rest/basket/1`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-200

#### Description
The server advertises granular version or framework details in response headers: Server: BaseHTTP/0.6 Python/3.7.6.

#### Security Impact
Reveals server software and versions, allowing adversaries to look up published CVEs and tailor exploitation vectors against known technology stacks.

#### Evidence & Reproduction Artifact
```text
Server: BaseHTTP/0.6 Python/3.7.6
```

#### Recommended Remediation
Disable or obfuscate banner headers in your web server/reverse proxy configuration:
- Express.js: `app.disable('x-powered-by')`
- Nginx: `server_tokens off;`
- Apache: `ServerTokens Prod` and `ServerSignature Off`

#### References & Standards
- [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)

---

### 3.25. [SEC-HDR-004] Missing X-Content-Type-Options: nosniff Header

- **Severity:** **LOW**
- **Category:** Security Headers
- **Affected URL:** `http://127.0.0.1:5000/admin`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-16

#### Description
The 'X-Content-Type-Options: nosniff' header is missing or improperly configured. This header prevents browsers from MIME-sniffing a response away from the declared Content-Type.

#### Security Impact
An attacker may upload a file with an innocent MIME type (e.g. image/png) that contains executable script tags. Without 'nosniff', legacy browsers may execute it as HTML/JavaScript.

#### Evidence & Reproduction Artifact
```text
X-Content-Type-Options: Not Set
```

#### Recommended Remediation
Set `X-Content-Type-Options: nosniff` across all HTTP responses.

#### References & Standards
- [https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)

---

### 3.26. [SEC-HDR-006] Information Disclosure via Server / Framework Headers

- **Severity:** **LOW**
- **Category:** Information Exposure
- **Affected URL:** `http://127.0.0.1:5000/admin`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-200

#### Description
The server advertises granular version or framework details in response headers: Server: BaseHTTP/0.6 Python/3.7.6.

#### Security Impact
Reveals server software and versions, allowing adversaries to look up published CVEs and tailor exploitation vectors against known technology stacks.

#### Evidence & Reproduction Artifact
```text
Server: BaseHTTP/0.6 Python/3.7.6
```

#### Recommended Remediation
Disable or obfuscate banner headers in your web server/reverse proxy configuration:
- Express.js: `app.disable('x-powered-by')`
- Nginx: `server_tokens off;`
- Apache: `ServerTokens Prod` and `ServerSignature Off`

#### References & Standards
- [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)

---

### 3.27. [SEC-HDR-006] Information Disclosure via Server / Framework Headers

- **Severity:** **LOW**
- **Category:** Information Exposure
- **Affected URL:** `http://127.0.0.1:5000/hardened`
- **OWASP Classification:** A05:2021-Security Misconfiguration
- **CWE Identifier:** CWE-200

#### Description
The server advertises granular version or framework details in response headers: Server: BaseHTTP/0.6 Python/3.7.6.

#### Security Impact
Reveals server software and versions, allowing adversaries to look up published CVEs and tailor exploitation vectors against known technology stacks.

#### Evidence & Reproduction Artifact
```text
Server: BaseHTTP/0.6 Python/3.7.6
```

#### Recommended Remediation
Disable or obfuscate banner headers in your web server/reverse proxy configuration:
- Express.js: `app.disable('x-powered-by')`
- Nginx: `server_tokens off;`
- Apache: `ServerTokens Prod` and `ServerSignature Off`

#### References & Standards
- [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server)

---
