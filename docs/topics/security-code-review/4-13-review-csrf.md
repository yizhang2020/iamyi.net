---
title: Review CSRF
keywords:
  - security code review
  - csrf
  - cross-site request forgery
  - anti-forgery token
  - samesite cookie
description: How to read code for cross-site request forgery—trace state-changing handlers and verify anti-CSRF tokens, SameSite cookies, or framework protections.
---

## 4.13 - Review CSRF

Cross-site request forgery (CSRF) appears when the application trusts a browser that already holds session cookies and performs state-changing work without proving the user intended the action. Review POST, PUT, PATCH, and DELETE handlers, AJAX endpoints that mutate data, and admin workflows. Confirm each sensitive operation requires an unpredictable token, strict SameSite cookies, or another framework-supported anti-CSRF control.

## What This Vulnerability Is

CSRF tricks a logged-in victim's browser into sending a request the application treats as legitimate. The attacker does not need to steal the session cookie if the browser attaches it automatically. Impact may include fund transfers, profile changes, privilege grants, or deletion of data.

The unsafe assumption is that only same-origin pages can trigger important actions. Attackers host malicious pages or embed crafted forms and images that target your endpoints. This pattern maps to [CWE-352](https://cwe.mitre.org/data/definitions/352.html) (Cross-Site Request Forgery).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Transfers, email change, password update, role assignment, account deletion, settings forms |
| **HTTP methods** | POST, PUT, PATCH, DELETE; unsafe GET that mutates state |
| **Session model** | Cookie-based sessions without synchronizer tokens or custom headers |
| **SPA/AJAX** | JSON APIs authenticated by cookies alone; missing `X-CSRF-Token` header |
| **Framework bypass** | `@csrf_exempt`, `csrf().disable()`, omitted `[ValidateAntiForgeryToken]` |
| **High-risk gaps** | MFA disable, payout flows, admin actions without reauthentication |

## Attack Payloads

Use these in authorized tests when a state-changing endpoint trusts session cookies alone. Host the HTML on a domain the victim visits while logged in.

### Pattern 1: Hidden auto-submit form (classic CSRF)

```html
<form action="https://bank.example/transfer" method="POST" id="csrf">
  <input type="hidden" name="to" value="attacker-acct">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.getElementById('csrf').submit();</script>
```

### Pattern 2: GET mutation (unsafe side effect)

```html
<img src="https://app.example/admin/delete?userId=42" width="0" height="0">
```

### Pattern 3: `fetch` with cookies (cookie-authenticated API)

```javascript
fetch('https://app.example/api/settings/email', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'attacker@evil.example' })
});
```

### Pattern 4: Cross-origin form to JSON endpoint (content-type bypass attempts)

```html
<form action="https://app.example/api/role" method="POST" enctype="text/plain">
  <input name='{"role":"admin","x":"' value='"}'>
</form>
```

### Pattern 5: Multipart or file upload CSRF

```html
<form action="https://app.example/api/avatar" method="POST" enctype="multipart/form-data">
  <input type="file" name="file">
</form>
```

## Language-Specific Sinks and Dangerous APIs

Locate state-changing handlers and confirm anti-CSRF middleware or tokens are enforced—not disabled for convenience.

### Python

```python
from flask import request
@app.route("/transfer", methods=["POST"])
def transfer(): ...  # no flask-wtf CSRF, no token check
@app.route("/api/x", methods=["POST"])
@csrf_exempt
def api_x(): ...
```

Django: views without `csrf_protect`; `csrf_exempt` decorator. FastAPI: cookie session without `CSRFMiddleware`.

### Java

```java
@PostMapping("/transfer")
public void transfer(...) { }  // missing @CsrfToken or Spring Security CSRF

http.csrf().disable();
```

Spring Security: `CsrfFilter` disabled globally. JAX-RS: POST without synchronizer token.

### C#

```csharp
[HttpPost]
public IActionResult ChangeEmail(EmailModel m) { }  // no [ValidateAntiForgeryToken]

services.AddControllers().AddJsonOptions(...); // antiforgery not validated on API
```

ASP.NET: `[IgnoreAntiforgeryToken]`, missing `[ValidateAntiForgeryToken]` on MVC actions.

### JavaScript (Node.js)

```javascript
app.post('/settings', (req, res) => { /* cookie session, no csrf token */ });
router.post('/admin/role', requireLogin, updateRole);  // no csrf/cors check
```

Express: `cookie-parser` + session without `csurf` or double-submit cookie. SameSite-only reliance on APIs that accept simple POST bodies.

### Go

```go
http.HandleFunc("/transfer", transfer) // POST, session cookie, no CSRF token
mux.Handle("/api/email", csrfOff(handler))
```

Gorilla/mux or chi routes without CSRF middleware on cookie-authenticated POSTs.

### PHP

```php
// No CSRF token in form handler
if ($_SERVER['REQUEST_METHOD'] === 'POST') { update_account($_POST); }
```

Laravel: `@csrf` omitted; `VerifyCsrfToken` except list too broad.

## Sample Vulnerable Code in Python

```python
from flask import Flask, request, redirect, session

app = Flask(__name__)

@app.route("/settings/email", methods=["POST"])
def change_email():
    if "user_id" not in session:
        return redirect("/login")
    # No CSRF token check; attacker site can POST with victim's cookies
    new_email = request.form["email"]
    db.execute("UPDATE users SET email = ? WHERE id = ?",
               (new_email, session["user_id"]))
    return "updated"
```

## Step-by-Step Review Walkthrough

1. **List state-changing routes.** Inventory form posts, JSON APIs, GraphQL mutations, and batch jobs triggered from the UI.
2. **Check whether GET requests perform mutations.** CSRF often combines with unsafe GET side effects such as delete links.
3. **Trace session and cookie configuration.** Review `SameSite`, `Secure`, and whether APIs use cookie-based auth without extra proof.
4. **Locate anti-CSRF tokens.** Confirm generation, binding to session, server validation, and inclusion in forms or AJAX headers.
5. **Review SPA and mobile clients.** Cookie-authenticated APIs need custom headers or tokens beyond cookie presence.
6. **Inspect high-risk actions.** Password change, email update, MFA disable, and payment flows should add step-up authentication.
7. **Confirm framework CSRF middleware is enabled.** Search for global disables on sensitive controllers "for convenience."

## Risk Impact Analysis

**Unauthorized state changes.** Victims may unknowingly transfer funds, change contact details, or approve transactions while browsing an attacker-controlled page.

**Account takeover paths.** Email or phone change without CSRF protection lets attackers redirect recovery flows to accounts they control.

**Privilege escalation.** Role assignment or admin settings exposed to CSRF can elevate an attacker-chosen account without the admin's intent.

**Data loss.** Delete-account or bulk-delete endpoints without CSRF tokens may wipe records when a victim loads a crafted page.

**Compliance and audit gaps.** Financial and healthcare applications often require demonstrable CSRF controls for regulated workflows.

## Vulnerable Examples in Other Languages

### Java

```java
@PostMapping("/transfer")
public String transfer(@RequestParam String toAccount,
                       @RequestParam BigDecimal amount,
                       HttpSession session) {
    User user = (User) session.getAttribute("user");
    accountService.transfer(user, toAccount, amount);
    return "ok";
}
```

### C#

```csharp
[HttpPost]
[AllowAnonymous]
public IActionResult PromoteUser(int userId, string role)
{
    _userService.SetRole(userId, role);
    return Ok();
}
```

### HTML

```html
<!-- evil.example.com/transfer.html — victim's browser auto-POSTs with session cookies -->
<html>
  <body onload="document.forms[0].submit()">
    <form action="https://bank.example.com/transfer" method="POST">
      <input type="hidden" name="toAccount" value="attacker-acct"/>
      <input type="hidden" name="amount" value="1000"/>
    </form>
  </body>
</html>
```

### JavaScript

```javascript
// SPA calls state-changing API with cookies only — no synchronizer token
fetch('/api/admin/promote', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ userId: 42, role: 'admin' }),
});
```

### Go

```go
func deleteAccount(w http.ResponseWriter, r *http.Request) {
    cookie, _ := r.Cookie("session")
    userID := sessions.Get(cookie.Value)
    db.Exec("DELETE FROM users WHERE id = ?", userID)
    w.WriteHeader(http.StatusOK)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Enable CSRF protection on state-changing routes. Use SameSite cookies as defense in depth.

```python
from flask import Flask, render_template, request, session
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
csrf = CSRFProtect(app)

@app.route("/settings/email", methods=["POST"])
def change_email():
    if "user_id" not in session:
        return redirect("/login")
    new_email = request.form["email"]
    db.execute("UPDATE users SET email = ? WHERE id = ?",
               (new_email, session["user_id"]))
    return "updated"
```

```html
<!-- settings.html -->
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
  <input name="email" type="email"/>
  <button type="submit">Update</button>
</form>
```

**Important:** Django CSRF middleware and FastAPI starlette-csrf provide equivalent protection. Never mark sensitive POST handlers `@csrf_exempt` without documented exceptions.

### Java

Spring Security enables CSRF by default for session-backed apps.

```java
@PostMapping("/transfer")
public String transfer(@RequestParam String toAccount,
                       @RequestParam BigDecimal amount,
                       HttpSession session) {
    User user = (User) session.getAttribute("user");
    accountService.transfer(user, toAccount, amount);
    return "ok";
}
```

```java
// SecurityConfig — CSRF enabled (default); SPA header pattern:
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
```

```html
<form action="/transfer" method="post">
  <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
  <!-- fields -->
</form>
```

**Important:** Supplement tokens with `SameSite=Lax` or `Strict` on session cookies. Require reauthentication for MFA removal and payouts.

### C#

Use anti-forgery tokens on MVC and Razor POST actions.

```csharp
[HttpPost]
[ValidateAntiForgeryToken]
[Authorize(Roles = "Admin")]
public IActionResult PromoteUser(int userId, string role)
{
    _userService.SetRole(userId, role);
    return Ok();
}
```

```cshtml
<form asp-action="PromoteUser" method="post">
  @Html.AntiForgeryToken()
  <!-- fields -->
</form>
```

```csharp
// SPA: inject IAntiforgery and require X-CSRF-TOKEN header
services.AddAntiforgery(options => options.HeaderName = "X-CSRF-TOKEN");
```

**Important:** Separate role changes from anonymous or CSRF-exempt endpoints. Set `CookieOptions.SameSite = SameSiteMode.Strict` for auth cookies in production.

### Go

Use gorilla/csrf middleware or custom synchronizer tokens stored server-side.

```go
import (
    "github.com/gorilla/csrf"
    "github.com/gorilla/sessions"
)

func main() {
    r := mux.NewRouter()
    csrfKey := []byte(os.Getenv("CSRF_KEY"))
    r.HandleFunc("/account/delete", deleteAccount).Methods("POST")
    http.ListenAndServe(":8080",
        csrf.Protect(csrfKey, csrf.Secure(true))(r))
}
```

```html
<form action="/account/delete" method="POST">
  <input type="hidden" name="gorilla.csrf.Token" value="{{ .CSRFToken }}"/>
  <button type="submit">Delete account</button>
</form>
```

**Important:** Set `SameSite: http.SameSiteStrictMode` on session cookies. Prefer Bearer tokens with explicit client storage for pure APIs when cookies are not required.

## Verify During Review

- Every state-changing endpoint validates CSRF tokens or equivalent framework protection.
- Session cookies use `Secure`, `HttpOnly`, and appropriate `SameSite` attributes.
- No sensitive mutations over GET; dangerous actions require POST or API verbs with protections.
- SPAs and AJAX include anti-forgery headers when cookies authenticate requests.
- High-risk operations add reauthentication, MFA, or CAPTCHA beyond generic CSRF tokens.
- CSRF protections are not globally disabled in security configuration without documented exceptions.

## Reference

- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Django — CSRF protection](https://docs.djangoproject.com/en/stable/ref/csrf/)
- [Flask-WTF CSRFProtect](https://flask-wtf.readthedocs.io/en/stable/csrf.html)
- [Spring Security — CSRF](https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html)
- [ASP.NET Core — Prevent cross-site request forgery](https://learn.microsoft.com/en-us/aspnet/core/security/anti-request-forgery)
- [gorilla/csrf package](https://pkg.go.dev/github.com/gorilla/csrf)
- [MDN — SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
