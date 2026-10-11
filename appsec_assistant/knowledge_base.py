"""
Educational Knowledge Base for Web Application Security.

Provides in-depth explanations, root causes, detection methodologies,
and defensive remediations for top web vulnerabilities:
- IDOR (Insecure Direct Object References)
- XSS (Cross-Site Scripting: Reflected, Stored, DOM)
- SQL Injection (SQLi)
- Authentication and Session Flaws
- Broken Access Control
- Security Misconfigurations
"""

from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class VulnerabilityGuide:
    """Educational guide for a vulnerability category."""
    title: str
    owasp_category: str
    cwe_id: str
    summary: str
    how_it_works: str
    detection_methodology: str
    defensive_remediation: str
    code_example: str
    references: List[str]


VULNERABILITY_CATALOG: Dict[str, VulnerabilityGuide] = {
    "idor": VulnerabilityGuide(
        title="Insecure Direct Object References (IDOR)",
        owasp_category="A01:2021-Broken Access Control",
        cwe_id="CWE-639",
        summary=(
            "IDOR occurs when an application exposes a reference to an internal object (e.g. database ID, "
            "file path, account number) in an HTTP request, and fails to verify whether the requesting user "
            "possesses authorization to access that specific object."
        ),
        how_it_works=(
            "When User A logs into their banking or ecommerce app, the UI requests `/api/invoices/1042`. "
            "If User A modifies the request to `/api/invoices/1041` (an invoice belonging to User B) and "
            "the server returns User B's invoice without validating that `invoice.customer_id == current_user.id`, "
            "an IDOR vulnerability exists. IDOR can be Horizontal (accessing another peer user's data) "
            "or Vertical (accessing an administrative record)."
        ),
        detection_methodology=(
            "1. Map out all endpoints accepting object identifiers in URL paths, query parameters, or JSON payloads.\n"
            "2. Establish two test accounts in the local training lab: User A and User B.\n"
            "3. Generate a resource using User A (e.g., an invoice or shopping cart).\n"
            "4. Authenticate as User B and attempt to read, update, or delete User A's resource ID.\n"
            "5. If User B receives HTTP 200 with User A's data, the access control is defective."
        ),
        defensive_remediation=(
            "1. Enforce strict object-level access control in backend data access layers: always verify ownership.\n"
            "2. Use indirect reference maps or non-sequential UUIDv4 values so identifiers cannot be trivially enumerated.\n"
            "3. Derive identity from trusted session state rather than client-supplied user IDs."
        ),
        code_example=(
            "# VULNERABLE (relying on client ID directly):\n"
            "@app.route('/api/orders/<int:order_id>')\n"
            "def get_order(order_id):\n"
            "    return Order.query.get(order_id).to_json()\n\n"
            "# SECURE (verifying ownership):\n"
            "@app.route('/api/orders/<int:order_id>')\n"
            "@login_required\n"
            "def get_order(order_id):\n"
            "    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()\n"
            "    return order.to_json()"
        ),
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/access-control/idor",
        ],
    ),

    "xss": VulnerabilityGuide(
        title="Cross-Site Scripting (XSS)",
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-79",
        summary=(
            "Cross-Site Scripting (XSS) occurs when an application includes untrusted, user-supplied data in a web page "
            "without proper validation, escaping, or encoding, allowing browser-executed scripts in victim sessions."
        ),
        how_it_works=(
            "There are three primary flavors of XSS:\n"
            "1. Reflected XSS: Untrusted input from the HTTP request (e.g. query param) is immediately reflected in the response.\n"
            "2. Stored XSS: Untrusted input is permanently saved in the database (e.g. user profile or comment) and later displayed to other users.\n"
            "3. DOM-based XSS: Vulnerability resides entirely in client-side JavaScript when an unsafe sink (e.g. `innerHTML`, `document.write`) "
            "receives input from a tainted source (e.g. `location.search`, `location.hash`)."
        ),
        detection_methodology=(
            "1. Identify all reflection points where input is rendered into HTML context, attributes, or script tags.\n"
            "2. Inspect the character encoding: verify whether `<`, `>`, `\"`, `'`, and `&` are HTML entity encoded.\n"
            "3. In local lab testing, verify whether standard contextual escaping prevents browser interpretation."
        ),
        defensive_remediation=(
            "1. Context-aware output encoding (HTML, Attribute, JavaScript, CSS encoding) before rendering data.\n"
            "2. Use modern web frameworks with automatic templating escaping (React, Angular, Vue, Jinja2 autoescape).\n"
            "3. Implement defense-in-depth: Deploy a strict Content-Security-Policy (CSP) and set `HttpOnly` on session cookies."
        ),
        code_example=(
            "# VULNERABLE (raw string formatting in HTML):\n"
            "@app.route('/search')\n"
            "def search():\n"
            "    q = request.args.get('q', '')\n"
            "    return f'<h1>Results for: {q}</h1>'  # Attacker inputs <script>alert(1)</script>\n\n"
            "# SECURE (template auto-escaping):\n"
            "@app.route('/search')\n"
            "def search():\n"
            "    q = request.args.get('q', '')\n"
            "    return render_template('results.html', query=q)  # Jinja2 escapes HTML characters"
        ),
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://owasp.org/www-community/attacks/xss/",
        ],
    ),

    "sqli": VulnerabilityGuide(
        title="SQL Injection (SQLi)",
        owasp_category="A03:2021-Injection",
        cwe_id="CWE-89",
        summary=(
            "SQL Injection occurs when untrusted user input is directly concatenated or interpolated into a dynamic database "
            "query string, allowing attackers to manipulate query logic, structure, and execution."
        ),
        how_it_works=(
            "When user input alters the SQL parser's syntax, the database executes instructions unintended by the developer. "
            "For instance, in an authentication query `SELECT * FROM users WHERE email = '` + email + `' AND pass = '` + pass + `'`, "
            "an input like `' OR '1'='1` transforms the condition to always evaluate to true, bypassing authentication."
        ),
        detection_methodology=(
            "1. Identify input fields that interact with backend databases (login forms, search filters, pagination).\n"
            "2. Check error handling: does sending standard punctuation (like a single quote `'`) trigger raw database errors "
            "(e.g. SQLite, Postgres, MySQL syntax errors) in response bodies?\n"
            "3. Verify whether queries use parameterized placeholders or raw string formatting."
        ),
        defensive_remediation=(
            "1. Always use Parameterized Queries (Prepared Statements) for all database operations.\n"
            "2. Use reputable ORMs (e.g. SQLAlchemy, Prisma, Hibernate) while avoiding raw SQL interpolation.\n"
            "3. Follow the principle of least privilege for database service accounts."
        ),
        code_example=(
            "# VULNERABLE (String concatenation):\n"
            "cursor.execute(f'SELECT * FROM products WHERE category = \"{user_category}\"')\n\n"
            "# SECURE (Parameterized query):\n"
            "cursor.execute('SELECT * FROM products WHERE category = %s', (user_category,))"
        ),
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://portswigger.net/web-security/sql-injection",
        ],
    ),

    "auth": VulnerabilityGuide(
        title="Authentication and Session Flaws",
        owasp_category="A07:2021-Identification and Authentication Failures",
        cwe_id="CWE-287",
        summary=(
            "Flaws in authentication mechanisms allow adversaries to compromise passwords, keys, or session tokens, "
            "or exploit implementation vulnerabilities to assume the identity of legitimate users."
        ),
        how_it_works=(
            "Common authentication flaws include:\n"
            "1. Lack of rate-limiting/lockout on login routes, enabling automated credential stuffing and brute-force attacks.\n"
            "2. Insecure session token generation (e.g. predictable PRNGs or tokens derived from user names).\n"
            "3. Session fixation: reusing the same session identifier before and after successful login.\n"
            "4. Insecure password reset flows (predictable reset tokens or token leaks in HTTP Referer)."
        ),
        detection_methodology=(
            "1. Inspect session tokens: are they cryptographically random with high entropy (>= 128 bits)?\n"
            "2. Inspect token lifecycle: does the session identifier change upon login and invalidate completely upon logout?\n"
            "3. Test password reset workflows for token predictability or omission of expiration."
        ),
        defensive_remediation=(
            "1. Adopt Multi-Factor Authentication (MFA) and enforce rate-limiting on authentication endpoints.\n"
            "2. Always regenerate session identifiers immediately after successful login.\n"
            "3. Use established authentication frameworks (e.g. OAuth 2.0 / OpenID Connect, well-tested libraries) "
            "rather than building custom crypto or token mechanisms."
        ),
        code_example=(
            "# VULNERABLE (Preserving session across authentication boundary):\n"
            "@app.route('/login', methods=['POST'])\n"
            "def login():\n"
            "    user = authenticate(request.form['user'], request.form['pass'])\n"
            "    session['user_id'] = user.id  # Session ID remains unchanged (Session Fixation)\n\n"
            "# SECURE (Regenerating session):\n"
            "@app.route('/login', methods=['POST'])\n"
            "def login():\n"
            "    user = authenticate(request.form['user'], request.form['pass'])\n"
            "    session.clear()          # Invalidate pre-auth session\n"
            "    session.regenerate()     # Issue new cryptographic session token\n"
            "    session['user_id'] = user.id"
        ),
        references=[
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
    ),

    "broken_access_control": VulnerabilityGuide(
        title="Broken Access Control",
        owasp_category="A01:2021-Broken Access Control",
        cwe_id="CWE-284",
        summary=(
            "Access control enforces policy such that users cannot act outside of their intended permissions. "
            "Failures typically lead to unauthorized information disclosure, modification or destruction of data, "
            "or performing business functions beyond user limits."
        ),
        how_it_works=(
            "Failures occur when authorization checks are missing or inconsistently implemented:\n"
            "- Horizontal Privilege Escalation: Accessing resources of peer users.\n"
            "- Vertical Privilege Escalation: Standard users accessing administrative capabilities (e.g. by navigating "
            "directly to `/admin/delete_user` because access control was only enforced in UI menus).\n"
            "- Contextual/State Bypassing: Skipping steps in multi-step workflows (e.g. checkout payment phase)."
        ),
        detection_methodology=(
            "1. Create matrix of application roles (e.g. Anonymous, Standard User, Manager, Administrator).\n"
            "2. Test direct requests to privileged endpoints using low-privilege tokens or cookies.\n"
            "3. Test modifying HTTP verbs (e.g. changing GET to POST, PUT, or DELETE) to see if authorization middleware is skipped."
        ),
        defensive_remediation=(
            "1. Deny by default: Unless a resource is explicitly public, mandate authentication and permission checks.\n"
            "2. Enforce access control at the server API layer, never solely relying on client-side UI hiding.\n"
            "3. Implement centralized Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC) middleware."
        ),
        code_example=(
            "# VULNERABLE (relying on UI client to hide admin routes):\n"
            "@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])\n"
            "def delete_user(user_id):\n"
            "    User.delete(user_id)  # No check if caller is an admin!\n\n"
            "# SECURE (centralized role enforcement):\n"
            "@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])\n"
            "@login_required\n"
            "@require_role('ADMIN')\n"
            "def delete_user(user_id):\n"
            "    User.delete(user_id)"
        ),
        references=[
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://portswigger.net/web-security/access-control",
        ],
    ),
}


class VulnerabilityKnowledgeBase:
    """Provides educational query capabilities for vulnerability concepts."""

    @staticmethod
    def get_all_topics() -> List[str]:
        return list(VULNERABILITY_CATALOG.keys())

    @staticmethod
    def get_guide(topic_key: str) -> Optional[VulnerabilityGuide]:
        return VULNERABILITY_CATALOG.get(topic_key.lower())

    @staticmethod
    def search(query: str) -> List[VulnerabilityGuide]:
        q = query.lower()
        results = []
        for guide in VULNERABILITY_CATALOG.values():
            if (
                q in guide.title.lower()
                or q in guide.summary.lower()
                or q in guide.owasp_category.lower()
                or q in guide.cwe_id.lower()
            ):
                results.append(guide)
        return results
