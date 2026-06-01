---
title: Review Framework Secure Defaults
keywords:
  - security code review
  - secure by default
  - framework configuration
  - django settings
  - spring security
description: How to read code for web framework secure defaults—confirm production config enables CSRF, escaping, cookies, and externalized secrets.
---

## 4.30 - Review Framework Secure Defaults

Frameworks ship security features, but many are configurable and easy to disable. Review environment-specific config files, dependency versions, and overrides to debug or convenience settings. Confirm production uses secure-by-default options for cookies, CSRF, escaping, errors, and secrets.

## What This Vulnerability Is

Secure by default means the standard configuration is safe without extra steps. Web frameworks often provide CSRF middleware, template auto-escaping, secure session cookies, and parameterized data access. Teams can undermine these benefits with `DEBUG=True`, disabled CSRF, raw template modes, or secrets in source control.

The unsafe assumption is that adopting a framework eliminates vulnerability classes. Dependency on frameworks still requires correct configuration per environment. Misconfiguration can reintroduce XSS, CSRF, session management flaws, injection, and sensitive data exposure without custom bug logic.

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Config surfaces** | `settings.py`, `application.yml`, `appsettings.json`, `config/environments/*.rb`, Express `app.js` |
| **Debug in prod** | `DEBUG=True`, `app.debug`, verbose stack traces, Werkzeug debugger exposed |
| **CSRF disabled** | `@csrf_exempt`, `csrf().disable()`, missing CSRF on cookie-auth forms |
| **Raw output** | `\|safe`, `th:utext`, `@Html.Raw` on user-controlled model fields |
| **Cookie flags** | Missing `Secure`, `HttpOnly`, `SameSite` on session identifiers |
| **Hardcoded secrets** | `SECRET_KEY`, JWT secrets, DB passwords committed in config files |

## Attack Payloads

These are abuse scenarios that exploit weak framework configuration—not single HTTP parameters. Use them when reviewing environment-specific config and deployment manifests.

### Pattern 1: Debug mode and verbose errors in production

```http
GET /nonexistent HTTP/1.1
→ 500 with Django debug page, Flask Werkzeug debugger, or full stack trace
```

Exposes settings, SQL, and local variables.

### Pattern 2: CSRF protection disabled (framework defaults abuse scenario)

```http
POST /transfer HTTP/1.1
Cookie: session=victim_session
Origin: https://attacker.example

amount=1000&to=attacker
```

Succeeds when `@csrf_exempt`, `csrf().disable()`, or missing CSRF middleware on cookie-authenticated forms.

### Pattern 3: Auto-escape disabled for templates

```html
POST /profile bio=<script>alert(1)</script>
→ Rendered unescaped via |safe, th:utext, @Html.Raw
```

### Pattern 4: Insecure session cookie defaults

```http
Set-Cookie: sessionid=abc; Path=/   # missing Secure, HttpOnly, SameSite
```

### Pattern 5: Permissive CORS and security headers

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

### Pattern 6: Default or committed secrets

```text
SECRET_KEY=django-insecure-change-me
JWT_SECRET=dev-secret-in-git
```

## Language-Specific Sinks and Dangerous APIs

Search configuration files and bootstrap code for overrides that weaken framework protections.

### Python (Django / Flask)

```python
DEBUG = True
ALLOWED_HOSTS = ["*"]
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
@app.route(..., methods=["GET","POST"])  # without CSRF on POST forms
```

Flask `SECRET_KEY` in repo; Jinja `|safe`; `TEMPLATES autoescape False`.

### Java (Spring Boot)

```yaml
spring.thymeleaf.cache: false
security.csrf.enabled: false
server.error.include-stacktrace: always
```

`@CrossOrigin(origins="*")`, `WebSecurityConfigurerAdapter` with `csrf().disable()`, JSP without escaping.

### C# (ASP.NET Core)

```csharp
services.AddControllers().AddJsonOptions(...);
// Missing AddAntiforgery, Hsts, UseHttpsRedirection in prod
options.Filters.Add(new IgnoreAntiforgeryTokenAttribute());
```

`@Html.Raw`, `DeveloperExceptionPage` in production pipeline.

### JavaScript (Express)

```javascript
app.disable("x-powered-by");  // often forgotten
app.use(cors({ origin: "*" }));
app.set("trust proxy", 1);  // mis-set breaks Secure cookies
```

Missing `helmet`, `csurf`, `cookie-session` without `httpOnly`/`secure`.

### Ruby on Rails

```ruby
config.force_ssl = false
config.consider_all_requests_local = true
config.action_controller.allow_forgery_protection = false
```

### Go (stdlib / Gin)

```go
gin.SetMode(gin.DebugMode)  // in production
// No secure cookie flags on session store
```

## Sample Vulnerable Code in Python

```ruby
# config/environments/production.rb — committed unsafe defaults
Rails.application.configure do
  config.force_ssl = false
  config.consider_all_requests_local = true
  config.action_controller.allow_forgery_protection = false
  config.session_store :cookie_store, key: "_app_session", secure: false, httponly: false
end
```

## Step-by-Step Review Walkthrough

1. **Open the primary config surface.** Compare production versus development files for debug flags, stack traces, and CORS `*`.
2. **Trace the Rails production config.** In the sample, debug-style errors, disabled CSRF, and insecure session cookies are unsafe in any deployed environment.
3. **Verify CSRF protection.** Browser session cookie applications need CSRF on state-changing routes.
4. **Check template auto-escape.** Search for explicit unsafe modes that bypass default encoding.
5. **Review cookie flags.** Confirm `Secure`, `HttpOnly`, and `SameSite` on session identifiers in production.
6. **Confirm secrets load from environment.** Keys must not live in committed config or images.
7. **Inspect dependency versions.** Framework and transitive libraries should be current and monitored for CVEs.

## Risk Impact Analysis

**Information disclosure.** Debug mode and verbose errors expose stack traces, settings, and internal paths to attackers.

**Session hijacking.** Cookies without `Secure` and `HttpOnly` are easier to steal over HTTP or via script.

**Cross-site request forgery.** Disabled CSRF lets attackers trigger state-changing actions in a victim's session.

**Credential compromise.** Hardcoded secrets in repos leak through history, forks, and CI logs.

## Vulnerable Examples in Other Languages

### Java

```properties
# application.properties committed to repo
spring.devtools.restart.enabled=true
server.error.include-stacktrace=always
jwt.secret=dev-secret-not-for-production
server.servlet.session.cookie.secure=false
```

```java
@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable());
        return http.build();
    }
}
```

### C#

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllersWithViews();
var app = builder.Build();

if (app.Environment.IsProduction())
{
    app.UseDeveloperExceptionPage();
}
app.UseHttpsRedirection();
// no UseAuthentication / UseAuthorization registered
app.MapControllers();
app.Run();
```

### JavaScript (Express)

```javascript
const express = require("express");
const session = require("express-session");

const app = express();
app.set("env", "development"); // verbose errors in production image
app.use(express.json());
app.use(session({
  secret: "hardcoded-session-secret",
  cookie: { secure: false, httpOnly: false },
}));
// no helmet, no csrf, no rate limiting
app.listen(3000);
```

### Go

```go
func main() {
    gin.SetMode(gin.DebugMode)
    r := gin.Default()
    r.Use(sessions.Sessions("session", cookie.NewStore([]byte("hardcoded-key"))))
    r.Run() // no TLS, no secure cookie settings on sessions
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Load secrets from environment. Disable debug in production. Enable secure cookie and CSRF settings.

```python
import os

DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "").split(",")

SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    # ...
]
```

```python
# Flask production config
class ProductionConfig:
    DEBUG = False
    SECRET_KEY = os.environ["FLASK_SECRET_KEY"]
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_ENABLED = True
```

**Important:** Jinja2 auto-escape is on by default in Flask for `.html` templates. Never mark user content `|safe` without a vetted sanitizer.

### Java (Spring Boot)

Enable Spring Security. Externalize secrets. Hide stack traces in production.

```yaml
# application-prod.yml
server:
  error:
    include-stacktrace: never
spring:
  devtools:
    restart:
      enabled: false
```

```java
@Bean
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.enable())
        .headers(headers -> headers
            .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'")))
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
    return http.build();
}
```

### C#

Use the exception handler in production. Register authentication and authorization.

```csharp
if (app.Environment.IsDevelopment())
    app.UseDeveloperExceptionPage();
else
    app.UseExceptionHandler("/Error");

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
```

```csharp
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
});
```

### Go

Run in release mode. Set secure session cookie options.

```go
import (
    "net/http"
    "os"

    "github.com/gin-contrib/sessions"
    "github.com/gin-contrib/sessions/cookie"
    "github.com/gin-gonic/gin"
)

func main() {
    gin.SetMode(gin.ReleaseMode)
    r := gin.New()
    r.Use(gin.Recovery())

    store := cookie.NewStore([]byte(os.Getenv("SESSION_KEY")))
    store.Options(sessions.Options{
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   3600,
    })
    r.Use(sessions.Sessions("session", store))
    r.RunTLS(":443", "cert.pem", "key.pem")
}
```

## Verify During Review

| Framework | Config surface | Confirm in production |
| --- | --- | --- |
| Django | `settings.py` | `DEBUG=False`, secure cookies, CSRF on, secrets from env |
| Flask | `config.py` / env | Autoescape, CSRF, secure sessions, no debugger |
| Express.js | `app.js` / `.env` | helmet, input validation, secure cookies, no stack to client |
| Ruby on Rails | `config/environments/*.rb` | `force_ssl`, strong params, CSRF default, secure headers |
| Spring Boot | `application.yml` | Spring Security, no stack in errors, secrets externalized |
| Laravel | `.env`, `config/*.php` | CSRF, ORM binding, encryption helpers, debug off |

- Framework secure defaults are enabled and not overridden in production configuration.
- Debug, verbose errors, and permissive CORS are confined to local development.
- Session and CSRF protections match the authentication model (cookie sessions need CSRF).
- Template and API output paths use framework escaping unless a documented exception exists.
- Dependencies are current and monitored; configuration drift is reviewed in each release.

## Reference

- [OWASP — Secure Configuration Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Configuration_Cheat_Sheet.html)
- [Django — Deployment checklist](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/)
- [Django — Settings reference](https://docs.djangoproject.com/en/stable/ref/settings/)
- [Flask — Configuration handling](https://flask.palletsprojects.com/en/stable/config/)
- [Spring Security — Getting started](https://docs.spring.io/spring-security/reference/getting-started.html)
- [ASP.NET Core — Security overview](https://learn.microsoft.com/en-us/aspnet/core/security/)
- [Gin — Mode and middleware](https://gin-gonic.com/en/docs/examples/custom-middleware/)
