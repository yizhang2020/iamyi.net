---
title: Review Authentication, Session, and Access Control
keywords:
  - CSRF
  - session
  - IDOR
  - authorization
  - JWT
  - cookies
description: Review CSRF, sessions, passwords, authz/IDOR, JWT-at-code-level, and cookie flags.
---

## 4.5 - Review Authentication, Session, and Access Control

### Overview

These findings ask who is acting, what binds the request to that actor, and what they are allowed to touch. Review session lifecycle, CSRF defenses, password handling, object-level authorization, and cookie flags together. For OAuth/OIDC/SAML protocol depth, continue in [5.1 Review Identity and Federation](5-01-review-identity-and-federation.md); for JWT issuance and JWKS, see [5.2 Review Tokens and API Trust](5-02-review-tokens-and-api-trust.md#jwt).

The points below are the ideas this family chapter uses again and again.

1. Ask who is acting, what binds the request to that actor, and what they may touch.
2. Review session lifecycle, CSRF, passwords, object-level authorization, JWT-at-code-level, and cookies together.
3. Authentication is not authorization; object IDs need server-side ownership checks.
4. Protocol depth for OAuth/OIDC/SAML continues in Chapter 5.
5. Evidence names the identity decision, missing control, impact, and a proving test.

After reading this chapter, we should be able to review authn, session, and access together and separate code-level JWT flaws from protocol issuance review.

## Shared Review Model

Across every variant below, keep the same evidence habit: name the **source**, the **sink**, the **missing control**, the **impact**, and a **test** that would prove a fix.

## Variants in This Family

### Authentication and authorization {: #authz }

Insecure authentication lets attackers pose as another user through weak credential checks, session flaws, or forged tokens. Missing authorization lets authenticated users access other users' data or admin functions because the handler never verifies ownership or role. Authentication alone does not limit which records or APIs are reachable.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Reports, exports, refunds, role changes, config edits, cross-tenant queries |
| **Authn entry points** | Login, API keys, OAuth callbacks, service accounts, machine-to-machine tokens |
| **Missing authz** | Handlers load resources by attacker-supplied ID without ownership test |
| **Client-trusted roles** | `isAdmin` from JWT body, `X-Admin` header, or JSON field without server mapping |
| **Implicit public** | `permitAll`, `[AllowAnonymous]`, missing middleware on `/internal` paths |
| **Service bypass** | Message consumers and schedulers calling repositories without authorization |

**Appendix detail:** [Authentication and authorization code reference](appendix/code-level-reference/4-05-review-authentication-session-and-access.md#authz).

### IDOR {: #idor }

IDOR is horizontal privilege escalation. A user authorized for object A can read or modify object B by changing an identifier in the URL, body, or header. The application performs the database or file operation but never checks ownership, tenant, or role against the target resource.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Profile edit, invoice download, order detail, file download, message view |
| **Object selectors** | Path variables, query strings, JSON `id` fields, hidden form inputs |
| **ID-only lookup** | `findById(userSuppliedId)` with no ownership filter in repository layer |
| **Client-supplied owner** | Create/update DTOs accepting `userId`, `orgId`, or `accountId` from body |
| **Batch endpoints** | Arrays of IDs returned without per-item authorization |
| **File access** | `send_file(userInput)` or bucket keys built from unsanitized names |

**Appendix detail:** [IDOR code reference](appendix/code-level-reference/4-05-review-authentication-session-and-access.md#idor).

### Forced browsing {: #forced-browsing }

Forced browsing is a form of broken access control. Attackers request paths such as `/admin`, `/api/internal/export`, or backup file names directly. If the server only checks that someone is logged in, any authenticated user may access admin functionality. Missing role or permission checks on each sensitive entry point create this gap.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Admin consoles, actuator endpoints, debug tools, importer APIs, legacy servlets |
| **Login-only guard** | Filter redirects when `user == null` but allows any authenticated user into `/admin` |
| **Hidden routes** | Sensitive `@GetMapping` without `@PreAuthorize` while public routes are protected |
| **Static exposure** | `/actuator`, `/swagger`, `/debug`, or `.git` served in production |
| **Method gap** | GET protected on admin page while POST `/admin/delete` lacks the same check |
| **Parallel channels** | Mobile API v2, GraphQL resolvers, WebSocket handlers missing admin checks |

**Appendix detail:** [Forced browsing code reference](appendix/code-level-reference/4-05-review-authentication-session-and-access.md#forced-browsing).

### Broken session management {: #session }

Session management ties HTTP requests to an authenticated user. Weak implementations use predictable identifiers, expose tokens in URLs, skip rotation at login, or leave sessions valid after logout. Session fixation occurs when the application keeps the same session ID before and after login, allowing an attacker who planted that ID to inherit the victim's authenticated state.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login, logout, remember-me, password change, role elevation, multi-device sessions |
| **Session creation** | `getSession(true)` before auth, client-supplied session IDs, short or predictable tokens |
| **Cookie flags** | Missing `HttpOnly`, `Secure`, or permissive `SameSite=None` without justification |
| **Fixation risk** | Same session ID before and after successful login |
| **Logout gaps** | Client-only cookie clear without server-side invalidation |
| **Transport leaks** | Session IDs in URLs, logs, referrer headers, or analytics |

**Appendix detail:** [Broken session management code reference](appendix/code-level-reference/4-05-review-authentication-session-and-access.md#session).

### CSRF {: #csrf }

CSRF tricks a logged-in victim's browser into sending a request the application treats as legitimate. The attacker does not need to steal the session cookie if the browser attaches it automatically. Impact may include fund transfers, profile changes, privilege grants, or deletion of data.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Transfers, email change, password update, role assignment, account deletion, settings forms |
| **HTTP methods** | POST, PUT, PATCH, DELETE; unsafe GET that mutates state |
| **Session model** | Cookie-based sessions without synchronizer tokens or custom headers |
| **SPA/AJAX** | JSON APIs authenticated by cookies alone; missing `X-CSRF-Token` header |
| **Framework bypass** | `@csrf_exempt`, `csrf().disable()`, omitted `[ValidateAntiForgeryToken]` |
| **High-risk gaps** | MFA disable, payout flows, admin actions without reauthentication |

**Appendix detail:** [CSRF code reference](appendix/code-level-reference/4-05-review-authentication-session-and-access.md#csrf).

### Broken password lifecycle {: #password }

Broken password lifecycle management lets attackers set, change, or reset credentials without proving identity. Risks include plain-text storage, weak hashing, missing current-password checks, reusable reset tokens, and MFA bypass on high-impact operations. Initial passwords left unchanged and debug logging of credentials amplify exposure.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Registration, admin provisioning, password change, reset confirm, MFA disable |
| **Storage flaws** | Plain text, MD5/SHA1, reversible encryption, passwords in audit tables |
| **Change without auth** | `user_id` from form body updates another account's password |
| **Reset token flaws** | Predictable tokens, long TTL, missing single-use invalidation, tokens in URL logs |
| **Enumeration** | Different responses for valid vs invalid email on reset |
| **MFA bypass** | Disable MFA without step-up; debug logging of passwords or reset links |

**Appendix detail:** [Broken password lifecycle code reference](appendix/code-level-reference/4-05-review-authentication-session-and-access.md#password).

### JWT security (code-level) {: #jwt }

A JWT carries claims the application may treat as identity and permissions. If signature verification is skipped, uses a hardcoded secret, or accepts the `none` algorithm, attackers can forge tokens and impersonate users or elevate privileges. Key confusion attacks swap asymmetric verification for symmetric keys when libraries are misconfigured.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | API auth middleware, microservice trust, mobile backends, OAuth resource servers |
| **Parse without verify** | Permissive `algorithms=` including `none`, RS256→HS256 confusion, manual header parsing for key selection |
| **Key material** | Hardcoded `"secretkey"`, dev keys shipped to prod, missing JWKS rotation |
| **Algorithm issues** | `none` accepted, HS256/RS256 confusion, ignoring `alg` header |
| **Claim validation** | Missing `exp`, `iss`, `aud`, or excessive access token lifetime |
| **Storage and logout** | localStorage tokens, refresh tokens without revocation, debug endpoints disabling verify |

**Appendix detail:** [JWT security (code-level) code reference](appendix/code-level-reference/4-05-review-authentication-session-and-access.md#jwt).

### Insecure cookie configuration {: #cookies }

Browsers store cookies and send them automatically on matching requests. Session cookies carry authentication state. If JavaScript can read the cookie, a cross-site scripting flaw may steal the session. If the cookie travels over HTTP, network attackers may intercept it. If SameSite is missing or too permissive, cross-site request forgery becomes easier. Overly long or persistent session cookies extend the window for stolen-token abuse.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login success handlers, "remember me," OAuth callbacks, session refresh, logout |
| **Framework config** | `web.xml`, Spring `application.yml`, Django `SESSION_COOKIE_*`, Express session middleware |
| **Missing HttpOnly** | `set_cookie(..., httponly=False)`, `Cookie` without `setHttpOnly(true)` |
| **Missing Secure** | Cookies set without `Secure` in production or behind TLS-terminating proxies |
| **SameSite gaps** | Cross-site flows, embedded widgets, OAuth redirects without deliberate SameSite choice |
| **Overlong lifetime** | Far-future `Expires` or `Max-Age` bypassing idle timeout policy |
| **Logout gaps** | Client cookie cleared but server-side session record still valid |

**Appendix detail:** [Insecure cookie configuration code reference](appendix/code-level-reference/4-05-review-authentication-session-and-access.md#cookies).

## Worked Example (Authentication and authorization)

We walk **Authentication and authorization** in depth. Apply the same tracing steps to the other variants, adjusting sources and sinks from the tables above.

### Sample vulnerable code (Python)

```python
from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

app = FastAPI()

@app.get("/api/projects/{project_id}")
def get_project(project_id: str, db: Session = Depends(get_db)):
    if not current_user_id():
        raise HTTPException(status_code=401)
    # Authenticated but no tenant/owner filter — any user reads any project
    return db.query(Project).filter(Project.id == project_id).one()

@app.post("/admin/billing")
def update_billing(payload: dict):
    # No role check; any caller who reaches the route can change billing config
    billing_config.update(payload)
    return {"ok": True}
```

### Step-by-step review walkthrough

1. **Map authentication entry points.** Login, API keys, OAuth callbacks, service accounts, and machine-to-machine tokens.
2. **Verify credential validation.** Password hashes, MFA gates, account lockout, and consistent failure responses.
3. **List sensitive operations.** Exports, refunds, role changes, config edits, and cross-tenant queries.
4. **For each operation, find the authorization check.** Role, scope, resource owner, or policy engine call must appear before the action.
5. **Compare UI restrictions to server enforcement.** Hidden buttons are not security controls.
6. **Review default-deny vs default-allow.** New endpoints should require explicit permission annotations.
7. **Check service layers and background jobs.** They must inherit the same authorization as HTTP controllers.

## Risk Impact (Family)

**Horizontal data access.** Authenticated users read or modify records belonging to others when ownership checks are absent.

**Administrative compromise.** Missing role checks on admin routes let standard users change configuration, roles, or billing.

**Tenant isolation failure.** Cross-tenant queries without tenant predicates expose one customer's data to another.

**Persistent unauthorized changes.** Background jobs and message handlers without authz may apply attacker-supplied operations at scale.

**Regulatory and contractual breach.** Broken access control is a top OWASP category and a common finding in security assessments.

## Fix Principles

Primary safer patterns for the worked example follow. For other languages and variant-specific fixes, use the [family appendix](appendix/code-level-reference/4-05-review-authentication-session-and-access.md).

### Python

Filter queries by authenticated user. Use dependency injection for scope checks on every route.

```python
from flask import Flask, g, abort
from flask_login import login_required, current_user

@app.route("/api/document/<doc_id>")
@login_required
def get_document(doc_id):
    doc = db.documents.find_one({"_id": doc_id, "owner_id": current_user.id})
    if not doc:
        abort(404)
    return jsonify(doc)

@app.route("/admin/settings", methods=["POST"])
@login_required
def save_settings():
    if not current_user.has_role("admin"):
        abort(403)
    config.update(request.get_json())
    return jsonify(ok=True)
```

```python
# FastAPI pattern
@app.get("/api/document/{doc_id}")
def get_document(doc_id: str, user=Depends(require_scope("documents:read"))):
    doc = repo.get_for_owner(doc_id, user.id)
    if not doc:
        raise HTTPException(status_code=404)
    return doc
```

**Important:** Use `user.has_perm` in Django and query filters like `Model.objects.filter(owner=request.user)`.

## Verify During Review

Use the checklist below as a family-level pass over the variants above. Each item should map to evidence in the change under review.

- Every sensitive operation performs server-side authorization after authentication.
- Resource access validates ownership, tenant, or role—not only presence of a session.
- Admin and internal routes require explicit elevated permissions, not obscurity.
- New endpoints default to deny; public exceptions are documented and rare.
- Background workers and message handlers enforce the same rules as HTTP APIs.
- Code structure makes authentication steps distinct from authorization checks for maintainers.
- Object lookups include owner, tenant, or permission predicate tied to the authenticated principal.
- Create and update operations ignore client-supplied ownership fields or validate them against policy.
- File and export endpoints authorize each object, including batch and async jobs.
- Indirect reference tokens are bound to the user session and expire appropriately.
- Mobile, GraphQL, and internal APIs apply the same object-level checks as primary web routes.
- Enumeration risk is reduced with rate limits and consistent 404/403 responses where policy allows.
- Admin and internal paths require explicit elevated roles or scopes, not only authentication.
- Every HTTP method on sensitive resources has matching authorization checks.
- Global security configuration defaults to deny; exceptions are documented.
- Actuator, swagger, debug, and backup paths are disabled or restricted in production.
- Parallel API versions and WebSocket routes repeat the same authorization rules as primary HTTP handlers.
- UI hiding of links is supplemented by server enforcement on direct navigation.
- Session ID regenerates or invalidates on successful login to prevent session fixation.
- Session identifiers are long, random, and not accepted from URL parameters.
- Session cookies use `HttpOnly`, `Secure`, and appropriate `SameSite` in production.
- Idle and absolute timeouts match policy; privileged apps use shorter windows.
- Logout and account lock invalidate server-side session state, not only browser cookies.
- Role, tenant, or MFA changes trigger session rotation or reauthentication where required.
- Session IDs do not appear in logs, analytics, or external referrer URLs.
- Every state-changing endpoint validates CSRF tokens or equivalent framework protection.
- Session cookies use `Secure`, `HttpOnly`, and appropriate `SameSite` attributes.
- No sensitive mutations over GET; dangerous actions require POST or API verbs with protections.
- SPAs and AJAX include anti-forgery headers when cookies authenticate requests.
- High-risk operations add reauthentication, MFA, or CAPTCHA beyond generic CSRF tokens.
- CSRF protections are not globally disabled in security configuration without documented exceptions.
- Passwords are hashed with modern algorithms and unique salts; plain text never stored or logged.
- Password change requires current credential or fresh reauthentication tied to the active session.
- Reset tokens are random, hashed at rest, time-limited, single-use, and not derived from email alone.
- Reset and registration responses do not enumerate valid accounts to anonymous callers.
- MFA is required for enrollment removal, email change, and other high-risk account operations.
- Initial and temporary passwords force change on first login when policy requires it.
- Audit trails record lifecycle events without cleartext passwords or reset secrets.
- Every authentication path verifies JWT signature with the correct key and algorithm.
- `none` and unexpected algorithms are rejected; asymmetric and symmetric paths are not confused.
- `exp`, `iss`, and `aud` (and `nbf` when used) are validated with acceptable clock skew.
- Signing keys are not hardcoded in production; rotation and JWKS are supported where applicable.
- Authorization uses claims from verified tokens only, not duplicate client-controlled headers.
- Access token lifetime matches risk; refresh and logout invalidate continued use when required.
- Session and authentication cookies set `HttpOnly` and `Secure` in production.
- `SameSite` is chosen deliberately for CSRF and OAuth redirect flows; `None` requires `Secure`.
- Cookie lifetime matches session timeout policy; "remember me" uses separate, scoped cookies when enabled.
- Logout invalidates server-side sessions and clears client cookies.
- Framework defaults were verified, not assumed; deployment descriptors match application code.
- No sensitive session identifiers appear in URL query parameters as a substitute for cookies.

## Code Reference (Appendix)

Payloads, language-specific sinks, multi-language examples, and full fix catalogs for every variant live in **[4.5 code reference — Review Authentication, Session, and Access Control](appendix/code-level-reference/4-05-review-authentication-session-and-access.md)**.

## Reference

- Appendix — [4.5 code reference](appendix/code-level-reference/4-05-review-authentication-session-and-access.md)

- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [OWASP Top 10 — Broken Access Control](https://owasp.org/www-project-top-ten/)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [Django — Permissions](https://docs.djangoproject.com/en/stable/topics/auth/default/#permissions-and-authorization)
- [Flask-Login documentation](https://flask-login.readthedocs.io/en/latest/)
- [Spring Security — Method Security](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)
- [ASP.NET Core — Authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/introduction)
- [Casbin documentation](https://casbin.org/docs/overview)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [Django — Object-level permissions](https://django-guardian.readthedocs.io/en/stable/)
- [Spring Data — Query methods](https://docs.spring.io/spring-data/jpa/docs/current/reference/html/#jpa.query-methods)
- [Spring Security — PostAuthorize](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)
- [ASP.NET Core — Resource-based authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/resourcebased)
- [EF Core — Global query filters](https://learn.microsoft.com/en-us/ef/core/querying/filters)
- [CWE-425: Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)
- [Django — Permissions and authorization](https://docs.djangoproject.com/en/stable/topics/auth/default/#permissions-and-authorization)
- [Flask-Principal roles](https://flask-principal.readthedocs.io/en/latest/)
- [Spring Security — Authorize HTTP requests](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html)
- [ASP.NET Core — Policy-based authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/policies)
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP ASVS — Session Management](https://owasp.org/www-project-application-security-verification-standard/)
- [Django — Using sessions](https://docs.djangoproject.com/en/stable/topics/http/sessions/)
- [Flask — Sessions](https://flask.palletsprojects.com/en/stable/api/#sessions)
- [Java Servlet — changeSessionId](https://jakarta.ee/specifications/servlet/6.0/apidocs/jakarta.servlet/jakarta/servlet/http/httpsession)
- [ASP.NET Core — Session](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/app-state)
- [gorilla/sessions](https://pkg.go.dev/github.com/gorilla/sessions)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Django — CSRF protection](https://docs.djangoproject.com/en/stable/ref/csrf/)
- [Flask-WTF CSRFProtect](https://flask-wtf.readthedocs.io/en/stable/csrf.html)
- [Spring Security — CSRF](https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html)
- [ASP.NET Core — Prevent cross-site request forgery](https://learn.microsoft.com/en-us/aspnet/core/security/anti-request-forgery)
- [gorilla/csrf package](https://pkg.go.dev/github.com/gorilla/csrf)
- [MDN — SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [CWE-620: Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)
- [CWE-640: Weak Password Recovery Mechanism](https://cwe.mitre.org/data/definitions/640.html)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [passlib documentation](https://passlib.readthedocs.io/en/stable/)
- [Spring Security — Password Storage](https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html)
- [ASP.NET Core Identity](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity)
- [Go golang.org/x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [RFC 7519: JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PyJWT documentation](https://pyjwt.readthedocs.io/en/stable/)
- [Auth0 — JWT algorithm confusion](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [jjwt library](https://github.com/jwtk/jjwt)
- [ASP.NET Core — JWT Bearer authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/jwt-authn)
- [golang-jwt/jwt v5](https://pkg.go.dev/github.com/golang-jwt/jwt/v5)
- [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
- [RFC 6265: HTTP State Management Mechanism](https://www.rfc-editor.org/rfc/rfc6265)
- [Flask session cookie configuration](https://flask.palletsprojects.com/en/stable/config/#SESSION_COOKIE_HTTPONLY)
- [Django session settings](https://docs.djangoproject.com/en/stable/ref/settings/#sessions)
- [Jakarta Servlet Cookie API](https://jakarta.ee/specifications/servlet/6.0/apidocs/jakarta.servlet/jakarta/servlet/http/Cookie.html)
- [Spring Boot server.servlet.session.cookie](https://docs.spring.io/spring-boot/docs/current/reference/html/application-properties.html#application-properties.server.server.servlet.session.cookie)
- [ASP.NET Core cookie authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/cookie)
- [Go net/http Cookie](https://pkg.go.dev/net/http#Cookie)
