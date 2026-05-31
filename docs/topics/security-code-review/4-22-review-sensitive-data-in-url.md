---
title: Review Sensitive Data in URL
keywords:
  - security code review
  - sensitive data exposure
  - GET parameters
  - credentials in URL
  - referrer leakage
description: How to read code for sensitive data in URL query strings where logs, history, and Referer headers can expose secrets.
---

## 4.22 - Review Sensitive Data in URL

Credentials and secrets in URL parameters leak through browser history, proxy logs, analytics, and Referer headers. Review login flows, password reset links, API keys in query strings, and OAuth redirects. Trace sensitive fields from forms and links to ensure they travel in request bodies or headers over HTTPS, not in GET URLs.

## What This Vulnerability Is

Sensitive data exposure via URLs occurs when passwords, tokens, session identifiers, or personal data appear in the query string or path where GET semantics apply. Browsers store URLs in history. Load balancers and CDNs often log full request lines. Third-party sites may receive secrets when users follow external links from a page that included them in the URL.

The unsafe assumption is that HTTPS alone protects the data. Transport encryption hides content on the wire but not from every system that records the URL after the request arrives. This maps to [CWE-598](https://cwe.mitre.org/data/definitions/598.html) (Use of GET Request Method With Sensitive Query Strings).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login, registration, password reset, magic links, API key auth, OAuth callbacks, shareable report URLs |
| **Input entry** | GET query params, bookmarkable links, email links with embedded tokens, front-end URL builders |
| **Sensitive fields** | Passwords, API keys, access tokens, session IDs, reset tokens, PII in query strings |
| **Logging sinks** | Access logs, APM, error trackers, analytics beacons that capture full request URIs |
| **Weak controls** | `@app.route(..., methods=["GET", "POST"])` on login, `[FromQuery] password`, redirect URLs echoing credentials |
| **Referrer leakage** | Pages with secrets in the URL linked from external sites without `Referrer-Policy` |

## Sample Vulnerable Code in Python

```python
from flask import Flask, request, redirect, render_template

app = Flask(__name__)

@app.route("/login", methods=["GET", "POST"])
def login():
    # Attacker-controlled credentials may arrive in the query string on GET
    user = request.args.get("user") or request.form.get("user")
    pwd = request.args.get("password") or request.form.get("password")
    if user and pwd:
        if do_login(user, pwd):
            # Redirect may leave credentials in server access logs
            return redirect(f"/home?user={user}")
    return render_template("login.html")
```

## Step-by-Step Review Walkthrough

1. **Find GET handlers that read secrets.** Search for routes that bind `password`, `token`, `api_key`, or `secret` from `request.args`, query parsers, or URL search params.
2. **Trace the Python login path.** In the sample, GET and POST share one handler. A crafted link can place credentials in the URL bar, browser history, and proxy logs.
3. **Inspect password reset and magic-link flows.** Long-lived tokens in query strings become shareable and loggable. Prefer POST exchange or opaque server-side lookup.
4. **Review front-end link builders.** Search JavaScript for `?token=`, `password=`, or template strings that append secrets to `href` or redirect targets.
5. **Check logging and analytics.** Access log formats, debug middleware, and exception messages must not record full URIs for auth endpoints.
6. **Examine Referer policy.** Pages that still touch sensitive flows need `Referrer-Policy: no-referrer` or strict-origin when outbound links exist.
7. **Confirm POST-only semantics.** Sensitive operations should reject GET with the same parameters and return 405 or redirect to a clean URL.

## Risk Impact Analysis

**Credential exposure in logs.** Load balancers, CDNs, and application access logs often store complete request lines. A single GET login attempt can persist passwords in log retention for months.

**Browser and shared-device leakage.** History, autofill, and synced browsers expose URL parameters to anyone with device access.

**Referer exfiltration to third parties.** When a user navigates from a page whose URL contains a token, the Referer header may send that token to external analytics or ad networks.

**Caching and bookmarking.** GET responses with secrets may be cached by browsers or intermediaries. Users who bookmark reset links may unknowingly store long-lived credentials.

## Vulnerable Examples in Other Languages

### Java

```java
@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String email = req.getParameter("email");
        String password = req.getParameter("password");
        if (email != null && password != null) {
            authenticate(email, password);
        }
        req.getRequestDispatcher("/login.jsp").forward(req, resp);
    }
}

@GetMapping("/reset/confirm")
public String confirmReset(@RequestParam String token, Model model) {
    model.addAttribute("token", token); // token visible in browser address bar
    return "reset-form";
}
```

### C#

```csharp
[HttpGet("auth")]
public IActionResult Auth([FromQuery] string username, [FromQuery] string password)
{
    var ok = _auth.Validate(username, password);
    return ok ? Ok() : Unauthorized();
}

[HttpGet("sso/callback")]
public IActionResult SsoCallback([FromQuery] string accessToken)
{
    // Token in query string — logged by proxies and sent in Referer
    SignInWithToken(accessToken);
    return Redirect($"/dashboard?token={accessToken}");
}
```

### Go

```go
func login(w http.ResponseWriter, r *http.Request) {
    user := r.URL.Query().Get("user")
    pass := r.URL.Query().Get("pass")
    if authenticate(user, pass) {
        http.Redirect(w, r, "/home", http.StatusFound)
    }
}

func apiProxy(w http.ResponseWriter, r *http.Request) {
    key := r.URL.Query().Get("api_key")
    resp, _ := http.Get("https://partner.example/api?key=" + key)
    io.Copy(w, resp.Body)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Accept credentials only on POST. Reject GET with password parameters. Put API keys in headers, not query strings.

```python
from flask import Flask, request, redirect, render_template
from flask.views import MethodView

app = Flask(__name__)

class LoginView(MethodView):
    def get(self):
        return render_template("login.html")

    def post(self):
        user = request.form["user"]
        pwd = request.form["password"]
        if do_login(user, pwd):
            return redirect("/home")  # clean URL, no echoed secrets
        return render_template("login.html", error="Invalid credentials"), 401

app.add_url_rule("/login", view_func=LoginView.as_view("login"), methods=["GET", "POST"])
```

```python
# API keys belong in headers, not query strings
from fastapi import Header, HTTPException

async def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")):
    if not valid_key(x_api_key):
        raise HTTPException(status_code=401)
```

**Important:** After login or reset, redirect to URLs that strip tokens from the visible address bar.

### Java

Use POST-only form login. Configure access logging to omit query strings on sensitive paths.

```java
@Override
protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {
    String email = req.getParameter("email");
    String password = req.getParameter("password");
    authenticate(email, password);
    resp.sendRedirect(req.getContextPath() + "/home");
}

@Override
protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {
    req.getRequestDispatcher("/login.jsp").forward(req, resp);
}
```

```java
// Spring Security: form login POST endpoint only
http.formLogin(form -> form.loginPage("/login").loginProcessingUrl("/login"));
```

### C#

Bind credentials from the form body. Disable GET on the same action.

```csharp
[HttpPost("auth")]
public IActionResult Auth([FromForm] string username, [FromForm] string password)
{
    var ok = _auth.Validate(username, password);
    return ok ? RedirectToAction("Home") : Unauthorized();
}
```

```csharp
// Response header on sensitive pages
Response.Headers["Referrer-Policy"] = "no-referrer";
```

### Go

Read credentials only after confirming POST. Return 405 for GET with password query params.

```go
func login(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    if err := r.ParseForm(); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    user := r.FormValue("user")
    pass := r.FormValue("pass")
    if authenticate(user, pass) {
        http.Redirect(w, r, "/home", http.StatusSeeOther)
    }
}
```

## Verify During Review

- Passwords, API keys, and long-lived tokens never appear in GET query strings or shareable URLs.
- Login and registration use POST with secrets in body or `Authorization` header over HTTPS.
- Access logs, APM, and error reporting do not store full URLs for authentication endpoints.
- Redirects after sensitive operations strip credentials from the visible URL bar.
- `Referrer-Policy` and cache headers are set where pages might still touch sensitive flows.
- OpenAPI or public docs do not advertise secret-bearing query parameters.

## Reference

- [CWE-598: Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
- [OWASP — Information exposure through query strings in URL](https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url)
- [MDN — Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)
- [Flask — HTTP methods](https://flask.palletsprojects.com/en/stable/quickstart/#http-methods)
- [FastAPI — Header parameters](https://fastapi.tiangolo.com/tutorial/header-params/)
- [Spring Security — Form Login](https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/form.html)
- [ASP.NET Core — Prevent cross-site request forgery](https://learn.microsoft.com/en-us/aspnet/core/security/anti-request-forgery)
- [Go net/http — Request handling](https://pkg.go.dev/net/http#Request)
