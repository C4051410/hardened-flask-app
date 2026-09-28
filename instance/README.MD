# Hardened Flask Web Application & OWASP Defense Architecture

A secure-by-default enterprise web application built with Python and Flask, engineered to systematically mitigate the OWASP Top 10 and CWE Top 25 web application security vulnerabilities. The application implements layered defense-in-depth controls across authentication, access control, input validation, cryptographic operations, and security event auditing.

---

## Security Architecture & Mitigations

### 1. Authentication & Session Integrity
* **Cryptographic Credential Hashing:** Uses Argon2id / bcrypt with adaptive work factors and per-user cryptographic salts to resist offline GPU cracking.
* **Session Hardening:** Configured with `HttpOnly`, `SameSite=Lax/Strict`, and `Secure` cookie flags to eliminate client-side token extraction and mitigate session fixation attacks.
* **Credential Hygiene:** Enforces NIST SP 800-63B guidelines (character complexity, entropy checks, and checks against common credential blacklists).

### 2. Authorization & Access Control (RBAC)
* **Principle of Least Privilege:** Custom decorator-based authorization middleware (`@roles_required`) enforcing strict vertical and horizontal access control boundaries.
* **Privilege Escalation Prevention:** Contextual permission checks prevent Insecure Direct Object References (IDOR/BOLA) across API endpoints and administrative routes.

### 3. Injection Prevention & ORM Abstraction
* **SQL Injection (SQLi) Elimination:** Uses SQLAlchemy ORM to enforce parameterized database queries, separating untrusted SQL inputs from query logic.
* **Cross-Site Scripting (XSS) Mitigation:** Context-aware Jinja2 auto-escaping combined with explicit HTML sanitization (`Bleach`) for user-supplied rich-text inputs.

### 4. Transport & Client-Side Protections
* **Cross-Site Request Forgery (CSRF):** Synchronizer Token Pattern implemented across all mutating state requests (`POST`, `PUT`, `DELETE`) via Flask-WTF.
* **HTTP Security Headers:** Integrated policy enforcement (`Flask-Talisman`):
  * `Content-Security-Policy (CSP)`: Strict policy restricting script execution sources and disallowing inline scripts.
  * `Strict-Transport-Security (HSTS)`: Enforces TLS termination and sub-domain encryption.
  * `X-Frame-Options`: Set to `DENY` to eliminate Clickjacking vectors.
  * `X-Content-Type-Options`: Set to `nosniff` to prevent MIME-type confusion attacks.

### 5. Secure Auditing, Error Handling & Configuration
* **Structured Security Auditing:** Dedicated audit logger capturing critical lifecycle events (failed authentications, permission violations, password updates) with timestamps and actor IDs while stripping passwords and tokens.
* **Information Leakage Containment:** Centralized error handlers for HTTP `4xx` and `5xx` statuses displaying generic user messages while masking internal application stack traces and database schemas.
* **Environment Separation:** Complete decoupling of configuration from source code using `.env` environment injection; debug mode strictly isolated from production environments.

---

## Tech Stack

* **Core Framework:** Python 3.10+, Flask
* **Database & ORM:** SQLite / PostgreSQL, SQLAlchemy
* **Form & Input Security:** Flask-WTF, WTForms, Bleach
* **Security & Auth:** Werkzeug Security, Flask-Login, Cryptography
* **Static Analysis & Testing:** Bandit, Flake8, PyTest

---

## Project Structure

```text
├── app/
│   ├── auth/              # Authentication routes, session workflows, MFA
│   ├── models/            # SQLAlchemy schemas & cryptographic hooks
│   ├── static/            # Static assets & client styles
│   ├── templates/         # Auto-escaped Jinja2 views
│   ├── utils/             # Sanitization, custom decorators, RBAC helpers
│   ├── __init__.py        # Application factory & security extension initialization
│   └── config.py          # Environment-driven security configurations
├── logs/                  # Rotated, sanitized audit logs
├── tests/                 # Unit, integration, and security assertion suites
├── .env.example           # Documented template for environment secrets
├── requirements.txt       # Pinned production dependencies
└── run.py                 # Application entrypoint