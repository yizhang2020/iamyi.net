---
title: Review XSS
keywords:
  - xss
  - cross-site scripting
  - output encoding
  - DOM XSS
description: Review stored, reflected, and DOM XSS as one HTML/script-context family.
---

## 4.1 - Review XSS

### Overview

Cross-site scripting is the same core failure in three delivery shapes: untrusted data reaches an HTML or JavaScript sink without context-appropriate encoding. The control is almost always **encode (or sanitize) at the sink for the output context**—not denylist filters on input alone.

The points below are the ideas this family chapter uses again and again.

1. Untrusted data reaches an HTML or JavaScript sink without context-appropriate encoding.
2. Encode or sanitize at the sink for the output context; denylist filters on input alone are not enough.
3. Stored, reflected, and DOM XSS share the same failure with different delivery shapes.
4. Name source, sink, missing control, impact, and a proving test for every finding.
5. Dense payloads and multi-language sinks live in the family appendix.

After reading this chapter, we should be able to review XSS as one family, distinguish delivery variants, and verify encoding at every relevant sink.

## Shared Review Model

Across every variant below, keep the same evidence habit: name the **source**, the **sink**, the **missing control**, the **impact**, and a **test** that would prove a fix.

## Variants in This Family

### Stored XSS {: #stored }

Stored XSS is a client-side injection flaw. The application accepts user input, stores it, and later embeds that value in an HTML response (current page or a later view). If the value is not encoded for HTML, the browser may run attacker-supplied script when another user loads the page.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Profiles, comments, support tickets, product reviews, admin notes, notification text, searchable stored fields |
| **Input entry** | POST forms, JSON API fields, multipart metadata, background jobs importing user content |
| **Persistence** | SQL/NoSQL columns, object storage, cache keys, session-backed “display name” |
| **HTML sinks** | Server templates, `render_template_string`, email HTML builders, SPA APIs feeding `innerHTML` |
| **Weak controls** | Regex denylist only, `|safe` / `@Html.Raw`, JSP scriptlets, missing auto-escape in templates |
| **High impact views** | Admin dashboards, moderator queues, exports—stored payloads often hit privileged users |

**Appendix detail:** [Stored XSS code reference](appendix/code-level-reference/4-01-review-xss.md#stored).

### Reflected XSS {: #reflected }

Reflected XSS is a client-side injection flaw. The application reads input from the current HTTP request and embeds it directly in the HTML response. If the value is not encoded for HTML, the browser may execute attacker-supplied script when a victim opens a crafted link.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Search pages, login errors, greeting banners, 404 handlers, redirect messages, OAuth error pages |
| **Input entry** | Query strings, POST form fields, path segments, Referer echoes, cookie values shown in UI |
| **Single-request echo** | Value enters and exits in one round trip; no database between input and output |
| **HTML sinks** | f-strings, `render_template_string`, JSP scriptlets, `@Html.Raw`, `Response.Write`, SPA `innerHTML` |
| **Weak controls** | Regex input filters only, `|safe` / `Markup()`, missing auto-escape, JavaScript string concat |
| **High impact views** | Authenticated pages that reflect search terms, admin error handlers, password-reset flows |

**Appendix detail:** [Reflected XSS code reference](appendix/code-level-reference/4-01-review-xss.md#reflected).

### DOM XSS {: #dom }

DOM XSS is a client-side injection flaw. The server may return a static or minimally dynamic page; the vulnerability lives entirely in front-end JavaScript (or inline script in HTML). Browser-controlled input reaches a dangerous sink without context-appropriate encoding. The attacker crafts a link or fragment; the victim's browser runs the payload when client code processes that input.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | OAuth/OIDC callback pages, client-side routers, “welcome” banners, error toasts, wiki/help viewers, postMessage widgets, client-side search highlighting |
| **Sources** | `location.hash`, `location.search`, `document.URL`, `document.referrer`, `window.name`, `localStorage` / `sessionStorage`, `postMessage` data, WebSocket messages parsed in JS |
| **DOM sinks** | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `document.writeln`, `Range.createContextualFragment` |
| **JS sinks** | `eval`, `Function`, `setTimeout("...", ms)`, `setInterval("...", ms)`, `location` / `location.href` assignment, `javascript:` URLs |
| **Framework sinks** | React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `[innerHTML]`, jQuery `.html()` / `.append()` |
| **Weak controls** | Regex strip of `<script>` only, client-side “sanitizer” without allowlist, trusting `postMessage` origin loosely |

**Appendix detail:** [DOM XSS code reference](appendix/code-level-reference/4-01-review-xss.md#dom).

## Worked Example (Stored XSS)

We walk **Stored XSS** in depth. Apply the same tracing steps to the other variants, adjusting sources and sinks from the tables above.

### Sample vulnerable code (Python)

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

### Step-by-step review walkthrough

1. **Find write + read pairs.** Search for `INSERT`/`UPDATE` on user-editable fields, then `SELECT` paths that feed HTML. Stored XSS requires both persistence and display.
2. **Trace the Python (or equivalent) write path.** In the sample, `request.form["body"]` flows straight into SQL. Ask whether any canonicalization runs before storage; storage-time stripping is not a substitute for render-time encoding unless the field is strictly non-HTML forever.
3. **Locate every read path for the same column.** Agent queues, email digests, search indexes, and JSON endpoints may reuse ticket `body` without the developer noticing.
4. **Inspect the sink in `list_tickets`.** The loop builds HTML with f-strings. Any stored `<script>` executes in the victim browser. Flag string-built HTML; prefer templates with auto-escape.
5. **Check filters vs encoding.** If you see `bleach.clean` or regex validation, read whether it is allowlist-based and whether output still uses encoding at the template boundary.
6. **Review secondary contexts.** Stored data in `href`, event handlers, `<script type="application/json">`, or Markdown renderers needs context-specific encoding, not only HTML body encoding.
7. **Confirm cross-user impact.** Ask who can view the stored field. Payloads in shared feeds or admin views are often higher severity than self-only profile preview.

## Risk Impact (Family)

**Session and account abuse.** Script in a trusted origin can read non-HttpOnly cookies, perform actions as the victim, or steal anti-CSRF tokens.

**Data and UI integrity.** Attackers can alter visible content, inject fake login forms, or exfiltrate page content to an external host.

**Privilege escalation paths.** Stored XSS in admin-only views is a common path to compromise operators who did not submit the payload.

**Compliance and trust.** Persistent script in customer-facing apps can trigger incident response, breach notification analysis, and reputational harm even when exploitation is limited to a subset of users.

## Fix Principles

Primary safer patterns for the worked example follow. For other languages and variant-specific fixes, use the [family appendix](appendix/code-level-reference/4-01-review-xss.md).

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

## Verify During Review

Use the checklist below as a family-level pass over the variants above. Each item should map to evidence in the change under review.

- Trace **write → storage → every HTML sink** for the same field.
- Confirm templates use framework auto-escape; no `|safe`, `th:utext`, `@Html.Raw`, or `innerHTML` on untrusted stored data.
- Encoding or vetted sanitization happens at **render time**, not only on input.
- Admin and export views treat stored fields like public views.
- CSP and HttpOnly cookies are defense in depth, not the primary XSS control.
- Every reflected parameter is HTML-encoded at the template or response sink, including error and validation messages.
- Search, login failure, and 404 handlers do not echo raw request data.
- JavaScript contexts that embed reflected values use JSON serialization plus encoding, not string concatenation.
- Redirect and callback parameters are validated; open redirects are not chained with reflected script sinks.
- Encoding is applied per output context (HTML body, attribute, URL, JavaScript).
- Every `location`, storage, and `postMessage` source traced to DOM/JS sinks in client code and inline scripts.
- No `innerHTML`, `document.write`, `eval`, or `dangerouslySetInnerHTML` / `v-html` on attacker-influenced data without vetted sanitization.
- OAuth and callback pages reviewed for hash and query handling on page load.
- CSP restricts inline script where feasible; DOM XSS review still required—CSP is defense in depth.
- Dynamic scanners supplemented with manual `#fragment` and client-route test cases.

## Code Reference (Appendix)

Payloads, language-specific sinks, multi-language examples, and full fix catalogs for every variant live in **[4.1 code reference — Review XSS](appendix/code-level-reference/4-01-review-xss.md)**.

## Reference

- Appendix — [4.1 code reference](appendix/code-level-reference/4-01-review-xss.md)

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
- [OWASP DOM Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)
- [MDN — Element.innerHTML](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML)
- [MDN — URLSearchParams](https://developer.mozilla.org/en-US/docs/Web/API/URLSearchParams)
- [DOMPurify](https://github.com/cure53/DOMPurify)
- [React — dangerouslySetInnerHTML](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html)
- [Vue — v-html](https://vuejs.org/api/built-in-directives.html#v-html)
