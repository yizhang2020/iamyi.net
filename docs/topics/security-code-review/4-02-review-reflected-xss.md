---
title: Review Reflected XSS
keywords:
  - security code review
  - reflected xss
  - cross-site scripting
  - output encoding
  - search pages
description: How to read code for reflected cross-site scripting—trace request input echoed in the immediate HTML response and verify context-appropriate encoding.
---

## 4.2 - Review Reflected XSS

Reflected cross-site scripting appears when attacker-controlled input from the current request is echoed into HTML without encoding. Start from query parameters, form fields, and headers, then follow each value into the response body in a single request cycle.

## What This Vulnerability Is

Reflected XSS is a client-side injection flaw. The application reads input from the current HTTP request and embeds it directly in the HTML response. If the value is not encoded for HTML, the browser may execute attacker-supplied script when a victim opens a crafted link.

Unlike stored XSS, the payload does not persist. The attacker typically delivers a malicious URL through phishing or ads. The victim's browser sends the parameter, and the server reflects it back unencoded. This maps to [CWE-79](https://cwe.mitre.org/data/definitions/79.html) (Improper Neutralization of Input During Web Page Generation).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Search pages, login errors, greeting banners, 404 handlers, redirect messages, OAuth error pages |
| **Input entry** | Query strings, POST form fields, path segments, Referer echoes, cookie values shown in UI |
| **Single-request echo** | Value enters and exits in one round trip; no database between input and output |
| **HTML sinks** | f-strings, `render_template_string`, JSP scriptlets, `@Html.Raw`, `Response.Write`, SPA `innerHTML` |
| **Weak controls** | Regex input filters only, `|safe` / `Markup()`, missing auto-escape, JavaScript string concat |
| **High impact views** | Authenticated pages that reflect search terms, admin error handlers, password-reset flows |

## Attack Payloads

Use these in authorized tests when request parameters are echoed in the immediate HTML response. Craft full URLs for phishing simulations; replace `PAYLOAD` with the value for the vulnerable parameter.

### Pattern 1: Query parameter script injection

```text
/login?error=<script>alert(document.domain)</script>
/reset?msg=<img src=x onerror=alert(1)>
/oauth/callback?state=<svg/onload=alert(1)>
```

### Pattern 2: Attribute context breakout

```text
?next="><script>alert(1)</script>
?return_url=javascript:alert(1)
?style=' onmouseover='alert(1)
```

### Pattern 3: Path or fragment reflection

```text
/404?uri=</title><script>alert(1)</script>
/help/<script>alert(1)</script>
```

### Pattern 4: Header or cookie echo

```text
Referer: https://evil.example/<script>alert(1)</script>
Cookie: locale=<img src=x onerror=alert(1)>
```

### Pattern 5: Filter bypass variants

```text
?error=<ScRiPt>alert(1)</ScRiPt>
?msg=<img src=x onerror=&#97;lert(1)>
?hint=<svg><script>alert&#40;1&#41;
```

### Pattern 6: DOM-based follow-on (when reflection lands in JS)

```text
?token=';alert(1)//
?nonce=</script><script>alert(1)</script>
?jsonp=alert(1)//  (JSONP-style sinks)
```

## Language-Specific Sinks and Dangerous APIs

Reflected XSS sinks appear wherever request data is written into HTML in the same handler. Trace each parameter to these APIs.

### Python (Flask / Jinja2)

```python
return f"<p class='error'>{request.args['error']}</p>"
return render_template_string(f"<div>{reset_msg}</div>")
return Markup(request.args.get("msg", ""))
```

### Java (JSP / servlets)

```jsp
Login failed: <%= request.getParameter("error") %>
<c:out value="${param.reason}" escapeXml="false"/>
out.println("Reset link sent to " + request.getParameter("email"));
```

### C# (ASP.NET / Razor)

```csharp
return Content($"<p>OAuth error: {Request.Query["error_description"]}</p>", "text/html");
@Html.Raw(Request.Query["msg"])
Response.Write(Request["failure_reason"]);
```

### JavaScript (Node / Express)

```javascript
res.send(`<p>Invalid token: ${req.query.token}</p>`);
document.title = location.hash.slice(1);
res.render("error", { detail: req.query.detail, autoEscape: false });
```

### HTML (error pages and static responses)

```html
<p>Password reset failed: <!-- reflected error param inserted without encoding --></p>
<meta http-equiv="refresh" content="0;url=REFLECTED_RETURN_URL">
```

### Go

```go
fmt.Fprintf(w, "<p>Login error: %s</p>", r.URL.Query().Get("error"))
template.HTML(reflectedMessage)  // disables escaping
```

## Sample Vulnerable Code in Python

```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/login")
def login_error():
    # Attacker-controlled error message from failed login redirect
    error = request.args.get("error", "")
    # Sink: reflected value embedded in HTML — no encoding
    return f"<h1>Sign in</h1><p class='alert'>{error}</p>"
```

## Step-by-Step Review Walkthrough

1. **Find echo endpoints.** Search for handlers that read request parameters and return HTML in the same action. Login failures, password-reset messages, and OAuth error pages are high yield.
2. **Trace the Python (or equivalent) read path.** In the sample, `request.args.get("error")` is attacker-controlled on every GET. Ask whether any validation runs before the response is built; input filtering is not a substitute for output encoding.
3. **Locate the HTML sink.** The f-string builds markup directly. Any `<script>` in `error` runs in the victim browser when they open a crafted link.
4. **Check error and validation branches.** Failed logins and 404 handlers often echo user input in messages. Review every branch, not only the happy path.
5. **Inspect non-HTML contexts.** Reflected values in `<script>` blocks, event handlers, `javascript:` URLs, and JSONP callbacks need context-specific encoding, not only HTML body encoding.
6. **Review URL decoding.** Double-encoded payloads may bypass naive denylist filters applied before reflection.
7. **Confirm link-deliverable impact.** Ask whether a crafted GET URL alone triggers execution. Reflected XSS often needs no POST or stored state.

## Risk Impact Analysis

**Session and account abuse.** Script on a trusted origin can read non-HttpOnly cookies, perform actions as the victim, or steal anti-CSRF tokens.

**Phishing at scale.** Attackers distribute malicious links that execute in the victim's session context, making fake login overlays more convincing.

**One-shot privilege paths.** Reflected XSS on admin search or support tools can compromise operators who click attacker-supplied links.

**Defense bypass.** Reflected payloads may chain with open redirects or CSRF gaps when script runs in an authenticated session.

## Vulnerable Examples in Other Languages

### Java

```java
@Override
protected void doGet(HttpServletRequest request, HttpServletResponse response)
        throws ServletException, IOException {
    String reason = request.getParameter("reason");
    request.setAttribute("failureReason", reason);
    request.getRequestDispatcher("/login.jsp").forward(request, response);
}
// login.jsp: <p class="error"><%= request.getAttribute("failureReason") %></p>
```

### C#

```csharp
public IActionResult ResetPassword(string token, string msg)
{
    ViewBag.StatusMessage = $"Reset failed: {msg}";
    return View();
}
// ResetPassword.cshtml: @Html.Raw(ViewBag.StatusMessage)
```

### JavaScript

```javascript
// Reflected OAuth error parameter written into the DOM
const err = new URLSearchParams(location.search).get("error_description") || "";
document.getElementById("oauth-error").innerHTML = `Authorization failed: ${err}`;
```

### HTML

```html
<!-- JSP echoes password-reset message without encoding -->
<p><%= request.getParameter("msg") %></p>

<!-- 404 handler reflects requested URI -->
<div class="not-found">Page not found: <%= request.getAttribute("uri") %></div>
```

### Go

```go
func loginError(w http.ResponseWriter, r *http.Request) {
    errMsg := r.URL.Query().Get("error")
    tmpl := `<html><body><h1>Login</h1><p class="alert">{{.Error}}</p></body></html>`
    t := template.Must(template.New("login").Parse(tmpl))
    t.Execute(w, map[string]string{"Error": errMsg}) // text/template, not html/template
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use templates with auto-escaping enabled. Never pass reflected input through `Markup()` or `|safe`.

```python
from flask import Flask, render_template, request
from markupsafe import escape

app = Flask(__name__)

@app.route("/login")
def login_error():
    error = request.args.get("error", "")
    return render_template("login.html", error=error)

# Manual encoding when building non-template fragments:
safe_error = escape(error)
```

**Important:** `render_template_string` with user-influenced template text is both reflected XSS and SSTI risk. Use static template files and pass data as variables.

```python
# Validate format when the parameter has a fixed shape (defense in depth):
import re
if not re.fullmatch(r"[a-zA-Z0-9\s.,!?-]{1,128}", error):
    error = ""
```

### Java

Encode at the HTML sink. Prefer JSTL or OWASP Encoder over regex-only input filters.

```jsp
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<p>Login failed: <c:out value="${failureReason}" /></p>
```

```java
import org.owasp.encoder.Encode;

String safe = Encode.forHtml(request.getParameter("error"));
model.addAttribute("safeError", safe);
```

**Important:** Thymeleaf `th:utext` and unescaped JSP scriptlets bypass default protections. Use `th:text` for reflected request data.

### C#

Razor encodes by default. Avoid `Html.Raw` on request-derived strings.

```cshtml
@* Safe default encoding *@
<p class="alert">@Model.ErrorMessage</p>
```

```csharp
using System.Net;

var encoded = WebUtility.HtmlEncode(msg);
ViewBag.SafeMessage = $"Reset failed: {encoded}";
```

For controlled HTML subsets in reflected content, use a maintained sanitizer with an explicit policy.

### Go

Use `html/template`, not `text/template`, for HTML responses.

```go
import "html/template"

var loginTmpl = template.Must(template.New("login").Parse(
    `<h1>Sign in</h1><p class="alert">{{.Error}}</p>`))

func loginError(w http.ResponseWriter, r *http.Request) {
    errMsg := r.URL.Query().Get("error")
    loginTmpl.Execute(w, struct{ Error string }{Error: errMsg})
}
```

**Important:** `html.EscapeString` helps only when you must build strings manually; templates apply context-aware rules automatically.

## Verify During Review

- Every reflected parameter is HTML-encoded at the template or response sink, including error and validation messages.
- Search, login failure, and 404 handlers do not echo raw request data.
- JavaScript contexts that embed reflected values use JSON serialization plus encoding, not string concatenation.
- Redirect and callback parameters are validated; open redirects are not chained with reflected script sinks.
- Encoding is applied per output context (HTML body, attribute, URL, JavaScript).
- CSP and HttpOnly cookies are defense in depth, not the primary XSS control.

## Reference

- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Jinja2 — Controlling autoescaping](https://jinja.palletsprojects.com/en/stable/api/#jinja2.Environment.autoescape)
- [MarkupSafe documentation](https://markupsafe.palletsprojects.com/en/stable/)
- [Python html.escape](https://docs.python.org/3/library/html.html#html.escape)
- [OWASP Java Encoder](https://owasp.org/www-project-java-encoder/)
- [Jakarta Tags — c:out](https://jakarta.ee/specifications/tags/3.0/apidocs/jakarta/tags/core/out)
- [ASP.NET Razor syntax — implicit encoding](https://learn.microsoft.com/en-us/aspnet/core/mvc/views/overview?view=aspnetcore-8.0)
- [WebUtility.HtmlEncode](https://learn.microsoft.com/en-us/dotnet/api/system.net.webutility.htmlencode)
- [Go html/template package](https://pkg.go.dev/html/template)
- [Go html.EscapeString](https://pkg.go.dev/html#EscapeString)
