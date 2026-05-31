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

## Sample Vulnerable Code in Python

```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/search")
def search():
    # Attacker-controlled query parameter from the current request
    term = request.args.get("q", "")
    # Sink: reflected value embedded in HTML — no encoding
    return f"<h1>Search</h1><p>You searched for: {term}</p>"
```

## Step-by-Step Review Walkthrough

1. **Find echo endpoints.** Search for handlers that read request parameters and return HTML in the same action. Search forms, error pages, and login failures are high yield.
2. **Trace the Python (or equivalent) read path.** In the sample, `request.args.get("q")` is attacker-controlled on every GET. Ask whether any validation runs before the response is built; input filtering is not a substitute for output encoding.
3. **Locate the HTML sink.** The f-string builds markup directly. Any `<script>` in `q` runs in the victim browser when they open a crafted link.
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
    String query = request.getParameter("q");
    request.setAttribute("searchTerm", query);
    request.getRequestDispatcher("/search.jsp").forward(request, response);
}
// search.jsp: <p>Results for <%= request.getAttribute("searchTerm") %></p>
```

### C#

```csharp
public IActionResult Search(string q)
{
    ViewBag.Message = $"You searched for: {q}";
    return View();
}
// Search.cshtml: @Html.Raw(ViewBag.Message)
```

### JavaScript

```javascript
// Reflected query parameter written into the DOM
const q = new URLSearchParams(location.search).get("q") || "";
document.getElementById("results").innerHTML = `Results for: ${q}`;
```

### HTML

```html
<!-- JSP echoes request parameter without encoding -->
<p>Results for <%= request.getParameter("q") %></p>

<!-- Error page reflects user-supplied message -->
<div class="alert"><%= request.getAttribute("errorMsg") %></div>
```

### Go

```go
func search(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query().Get("q")
    tmpl := `<html><body><p>Results for: {{.Query}}</p></body></html>`
    t := template.Must(template.New("s").Parse(tmpl))
    t.Execute(w, map[string]string{"Query": q}) // text/template, not html/template
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use templates with auto-escaping enabled. Never pass reflected input through `Markup()` or `|safe`.

```python
from flask import Flask, render_template, request
from markupsafe import escape

app = Flask(__name__)

@app.route("/search")
def search():
    term = request.args.get("q", "")
    return render_template("search.html", term=term)

# Manual encoding when building non-template fragments:
safe_line = escape(term)
```

**Important:** `render_template_string` with user-influenced template text is both reflected XSS and SSTI risk. Use static template files and pass data as variables.

```python
# Validate format when the parameter has a fixed shape (defense in depth):
import re
if not re.fullmatch(r"[a-zA-Z0-9\s-]{1,64}", term):
    term = ""
```

### Java

Encode at the HTML sink. Prefer JSTL or OWASP Encoder over regex-only input filters.

```jsp
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<p>Results for <c:out value="${searchTerm}" /></p>
```

```java
import org.owasp.encoder.Encode;

String safe = Encode.forHtml(request.getParameter("q"));
model.addAttribute("safeTerm", safe);
```

**Important:** Thymeleaf `th:utext` and unescaped JSP scriptlets bypass default protections. Use `th:text` for reflected request data.

### C#

Razor encodes by default. Avoid `Html.Raw` on request-derived strings.

```cshtml
@* Safe default encoding *@
<p>You searched for: @Model.SearchTerm</p>
```

```csharp
using System.Net;

var encoded = WebUtility.HtmlEncode(q);
ViewBag.SafeMessage = $"You searched for: {encoded}";
```

For controlled HTML subsets in reflected content, use a maintained sanitizer with an explicit policy.

### Go

Use `html/template`, not `text/template`, for HTML responses.

```go
import "html/template"

var searchTmpl = template.Must(template.New("search").Parse(
    `<h1>Search</h1><p>You searched for: {{.Term}}</p>`))

func search(w http.ResponseWriter, r *http.Request) {
    term := r.URL.Query().Get("q")
    searchTmpl.Execute(w, struct{ Term string }{Term: term})
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
