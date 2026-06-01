---
title: Review Broken Session Management
keywords:
  - security code review
  - session management
  - session fixation
  - session hijacking
  - cookie security
description: How to read code for broken session management—verify session rotation at login, cookie flags, timeouts, and server-side revocation.
---

## 4.15 - Review Broken Session Management

Broken session management lets attackers hijack or reuse another user's session. Review login and logout flows, cookie attributes, server-side session stores, and timeout policies. Pay special attention to session fixation: whether the session identifier changes after authentication and whether pre-login session IDs are accepted afterward.

## What This Vulnerability Is

Session management ties HTTP requests to an authenticated user. Weak implementations use predictable identifiers, expose tokens in URLs, skip rotation at login, or leave sessions valid after logout. Session fixation occurs when the application keeps the same session ID before and after login, allowing an attacker who planted that ID to inherit the victim's authenticated state.

The unsafe assumption is that knowing the session ID is equivalent to proof of identity forever. Impact includes account takeover and privilege abuse. Related weaknesses map to [CWE-384](https://cwe.mitre.org/data/definitions/384.html) (Session Fixation) and [CWE-613](https://cwe.mitre.org/data/definitions/613.html) (Insufficient Session Expiration).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login, logout, remember-me, password change, role elevation, multi-device sessions |
| **Session creation** | `getSession(true)` before auth, client-supplied session IDs, short or predictable tokens |
| **Cookie flags** | Missing `HttpOnly`, `Secure`, or permissive `SameSite=None` without justification |
| **Fixation risk** | Same session ID before and after successful login |
| **Logout gaps** | Client-only cookie clear without server-side invalidation |
| **Transport leaks** | Session IDs in URLs, logs, referrer headers, or analytics |

## Abuse Scenarios

Use these in authorized tests and code review. They show how weak session APIs let attackers fixate, hijack, or reuse sessions—not injection strings.

### Pattern 1: Session fixation (pre-login ID accepted after auth)

```text
1. Attacker obtains SESSIONID=abc123 (unauthenticated).
2. Victim logs in with that cookie; server keeps abc123.
3. Attacker reuses abc123 as the authenticated victim.
```

### Pattern 2: Predictable or short session identifiers

```text
SESSIONID=100042
session_id = str(uuid.uuid4())[:8]
```

### Pattern 3: Missing cookie security flags

```http
Set-Cookie: session=abc123; Path=/
# Missing HttpOnly, Secure, appropriate SameSite
```

### Pattern 4: Logout without server invalidation

```text
Client deletes cookie; server session store still maps old ID → user.
Captured ID remains valid until TTL expires.
```

### Pattern 5: Session ID in URL or referrer leak

```text
https://app.example/home?sessionid=abc123
Referer: https://app.example/home?sessionid=abc123 → third-party analytics
```

## Language-Specific Sinks and Dangerous APIs

Trace session creation, cookie issuance, rotation at login, and invalidation at logout.

### Python

```python
from starlette.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

# SessionMiddleware with permissive cookie flags — fixation if ID not rotated at login
session_store["user"] = username  # same session key before and after auth
response = RedirectResponse("/home")
response.set_cookie("sid", session_id, httponly=False, secure=False, samesite="none")
```

Django: `login()` without `cycle_key()`; Flask `session` without clear/regenerate on auth success.

### Java

```java
HttpSession session = request.getSession(true);  // before authentication
// login success — same session ID, no session.invalidate() + new session
response.addCookie(new Cookie("JSESSIONID", session.getId()));
```

Servlet: `request.changeSessionId()` not called; `Cookie` without `HttpOnly`/`Secure`. Spring Session config.

### C#

```csharp
HttpContext.Session.SetString("User", name);
Response.Cookies.Append("SessionId", id);  // missing HttpOnly, Secure, SameSite
```

ASP.NET Core: `AddSession` without secure cookie options; Identity without sign-in cookie rotation.

### JavaScript (Node.js)

```javascript
req.session.userId = id;  // express-session, no regenerate on login
res.cookie('connect.sid', sid, { httpOnly: false });
```

`express-session`, `cookie-session`, Passport without `req.session.regenerate()`.

### Go

```go
session.Values["user"] = username
session.Save(r, w)  // same store ID before and after login
http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Secure: false})
```

Gorilla sessions, `scs` session manager—check `Session.Regenerate` on auth success.

### PHP

```php
session_start();
$_SESSION['user'] = $user;  // session_id() unchanged at login
setcookie(session_name(), session_id(), 0, '/');  // no httponly/secure flags
```

## Sample Vulnerable Code in Python

```python
import secrets
from starlette.applications import Starlette
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.routing import Route

async def sso_callback(request: Request):
    form = await request.form()
    if not valid_saml_response(form):
        return RedirectResponse("/login?failed=1", status_code=303)
    # Reuses pre-login session; short ID; cookie missing HttpOnly/Secure
    if "sid" not in request.session:
        request.session["sid"] = secrets.token_hex(4)
    request.session["user"] = extract_username(form)
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.set_cookie(
        "sso_session",
        request.session["sid"],
        httponly=False,
        secure=False,
        samesite="none",
    )
    return resp

app = Starlette(routes=[Route("/sso/callback", sso_callback, methods=["POST"])])
app.add_middleware(SessionMiddleware, secret_key="dev-only", https_only=False)
```

## Step-by-Step Review Walkthrough

1. **Map session creation.** Note when `getSession(true)` runs, how IDs are generated, and whether login reuses an existing ID.
2. **Trace login success.** Confirm the server invalidates the old session or rotates the session key before setting auth attributes (Starlette `session.clear()` or Django `cycle_key()`).
3. **Review cookie flags.** Check `HttpOnly`, `Secure`, `SameSite`, path, and domain scope on session cookies.
4. **Check idle and absolute timeouts.** Review `setMaxInactiveInterval`, sliding expiration, and remember-me lifetimes.
5. **Follow logout and password change.** Server-side invalidation, token blacklist, and clearing all devices when required.
6. **Inspect session storage.** Server memory, Redis, or JWT sessions—confirm IDs do not appear in logs or referrer headers.
7. **Connect to related risks.** XSS stealing cookies, CSRF riding sessions, and missing rotation on role elevation.

## Risk Impact Analysis

**Account takeover.** Stolen or fixed session IDs let attackers act as the victim without knowing the password.

**Persistent access after logout.** Server sessions that survive client cookie deletion allow reuse of captured identifiers.

**Privilege inheritance.** Session fixation at login lets an attacker inherit a victim's authenticated state after credential entry.

**Cross-site cookie exposure.** Missing `SameSite` or `Secure` flags increase CSRF and network interception risk.

**Audit and compliance gaps.** Weak session lifecycle controls fail common security assessments and customer due diligence reviews.

## Vulnerable Examples in Other Languages

### Java

```java
@WebServlet("/sso/callback")
public class SsoCallbackServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        HttpSession session = req.getSession(); // reuses attacker-supplied JSESSIONID
        if (validateSamlResponse(req.getParameter("SAMLResponse"))) {
            session.setAttribute("user", extractNameId(req));
            Cookie c = new Cookie("JSESSIONID", session.getId());
            resp.addCookie(c);
            resp.sendRedirect("/dashboard");
        }
    }
}
```

### C#

```csharp
[HttpPost("sso/callback")]
public IActionResult SsoCallback(SamlResponseModel model)
{
    if (_saml.Validate(model.Response))
    {
        HttpContext.Session.SetString("User", model.NameId);
        Response.Cookies.Append("SessionId", HttpContext.Session.Id);
        return RedirectToAction("Index", "Dashboard");
    }
    return Unauthorized();
}
```

### Go

```go
func ssoCallback(w http.ResponseWriter, r *http.Request) {
    token := r.FormValue("session_token")
    if token == "" {
        token = fmt.Sprintf("%d", time.Now().UnixNano()/1e6)
    }
    if !validateSaml(r.FormValue("SAMLResponse")) {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    store[token] = extractSubject(r)
    http.SetCookie(w, &http.Cookie{Name: "sso_session", Value: token, Path: "/"})
    http.Redirect(w, r, "/dashboard", http.StatusFound)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Regenerate session after login. Use strong secret keys from the environment and secure cookie flags.

```python
from flask import Flask, session, redirect, request, make_response
import secrets

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

@app.route("/sso/callback", methods=["POST"])
def sso_callback():
    if not valid_saml_response(request.form):
        return "failed", 401
    session.clear()
    session["user"] = extract_username(request.form)
    session["sid"] = secrets.token_urlsafe(32)
    return redirect("/dashboard")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/login")
```

**Important:** Django's `login()` rotates the session key automatically. Enable `SESSION_COOKIE_SECURE` and `HTTPONLY` in production settings.

### Java

Rotate session ID on successful login. Configure secure cookie tracking.

```java
protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {
    if (!validateSamlResponse(req.getParameter("SAMLResponse"))) {
        resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        return;
    }
    HttpSession old = req.getSession(false);
    if (old != null) {
        old.invalidate();
    }
    HttpSession session = req.getSession(true);
    session.setAttribute("user", extractNameId(req));
    req.changeSessionId(); // Servlet 3.1+
    resp.sendRedirect("/dashboard");
}
```

```xml
<!-- web.xml -->
<session-config>
  <cookie-config>
    <http-only>true</http-only>
    <secure>true</secure>
  </cookie-config>
  <tracking-mode>COOKIE</tracking-mode>
</session-config>
```

**Important:** Use Spring Session for centralized store with explicit logout and concurrent session controls.

### C#

Use cookie authentication that issues a new auth ticket at sign-in.

```csharp
[HttpPost("sso/callback")]
public async Task<IActionResult> SsoCallback(SamlResponseModel model)
{
    if (!_saml.Validate(model.Response))
        return Unauthorized();

    HttpContext.Session.Clear();
    var claims = new[] { new Claim(ClaimTypes.Name, model.NameId) };
    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    await HttpContext.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(identity));

    return RedirectToAction("Index", "Dashboard");
}
```

```csharp
services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
});
```

**Important:** Call `HttpContext.Session.Clear()` before establishing authenticated state to avoid fixation.

### Go

Generate cryptographically random session IDs. Never accept client-supplied identifiers.

```go
import (
    "crypto/rand"
    "encoding/hex"
    "net/http"
    "time"
)

func newSessionID() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return hex.EncodeToString(b), nil
}

func ssoCallback(w http.ResponseWriter, r *http.Request) {
    if !validateSaml(r.FormValue("SAMLResponse")) {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    sid, _ := newSessionID()
    store.Set(sid, extractSubject(r), 30*time.Minute)
    http.SetCookie(w, &http.Cookie{
        Name:     "sso_session",
        Value:    sid,
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   1800,
    })
    http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func logout(w http.ResponseWriter, r *http.Request) {
    if c, err := r.Cookie("sso_session"); err == nil {
        store.Delete(c.Value)
    }
    http.SetCookie(w, &http.Cookie{Name: "sso_session", MaxAge: -1, Path: "/"})
}
```

**Important:** Use gorilla/sessions with securecookie for signed cookies. Expire entries in Redis or SQL with idle and absolute deadlines.

## Verify During Review

- Session ID regenerates or invalidates on successful login to prevent session fixation.
- Session identifiers are long, random, and not accepted from URL parameters.
- Session cookies use `HttpOnly`, `Secure`, and appropriate `SameSite` in production.
- Idle and absolute timeouts match policy; privileged apps use shorter windows.
- Logout and account lock invalidate server-side session state, not only browser cookies.
- Role, tenant, or MFA changes trigger session rotation or reauthentication where required.
- Session IDs do not appear in logs, analytics, or external referrer URLs.

## Reference

- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP ASVS — Session Management](https://owasp.org/www-project-application-security-verification-standard/)
- [Django — Using sessions](https://docs.djangoproject.com/en/stable/topics/http/sessions/)
- [Flask — Sessions](https://flask.palletsprojects.com/en/stable/api/#sessions)
- [Java Servlet — changeSessionId](https://jakarta.ee/specifications/servlet/6.0/apidocs/jakarta.servlet/jakarta/servlet/http/httpsession)
- [ASP.NET Core — Session](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/app-state)
- [gorilla/sessions](https://pkg.go.dev/github.com/gorilla/sessions)
