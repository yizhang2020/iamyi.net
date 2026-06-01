---
title: Review Forced Browsing
keywords:
  - security code review
  - forced browsing
  - missing authorization
  - access control
  - security through obscurity
description: How to read code for forced browsing—verify restricted URLs and admin paths require elevated authorization, not only authentication.
---

## 4.19 - Review Forced Browsing

Forced browsing happens when users reach restricted pages or APIs by guessing URLs, not because the application granted permission. Security through obscurity—hiding `/admin` links from the menu—does not replace server-side checks. Review every authenticated route, static resource mapping, and alternate API version for consistent authorization.

## What This Vulnerability Is

Forced browsing is a form of broken access control. Attackers request paths such as `/admin`, `/api/internal/export`, or backup file names directly. If the server only checks that someone is logged in, any authenticated user may access admin functionality. Missing role or permission checks on each sensitive entry point create this gap.

The unsafe assumption is that users cannot discover unlinked URLs. Impact includes configuration changes, user management, and data exports reserved for administrators. This relates to [OWASP Broken Access Control](https://owasp.org/www-project-top-ten/) and [CWE-425](https://cwe.mitre.org/data/definitions/425.html) (Direct Request / Forced Browsing).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Admin consoles, actuator endpoints, debug tools, importer APIs, legacy servlets |
| **Login-only guard** | Filter redirects when `user == null` but allows any authenticated user into `/admin` |
| **Hidden routes** | Sensitive `@GetMapping` without `@PreAuthorize` while public routes are protected |
| **Static exposure** | `/actuator`, `/swagger`, `/debug`, or `.git` served in production |
| **Method gap** | GET protected on admin page while POST `/admin/delete` lacks the same check |
| **Parallel channels** | Mobile API v2, GraphQL resolvers, WebSocket handlers missing admin checks |

## Attack Payloads

Use these in authorized tests when you are authenticated as a non-admin user. Directly request paths that are omitted from the UI menu.

### Pattern 1: Admin console paths

```http
GET /admin HTTP/1.1
GET /admin/users HTTP/1.1
GET /administrator/dashboard HTTP/1.1
GET /manage/settings HTTP/1.1
```

### Pattern 2: Framework and ops endpoints

```http
GET /actuator/env HTTP/1.1
GET /actuator/heapdump HTTP/1.1
GET /swagger-ui.html HTTP/1.1
GET /debug/pprof/ HTTP/1.1
GET /.env HTTP/1.1
```

### Pattern 3: Internal and legacy API versions

```http
GET /api/internal/export HTTP/1.1
GET /api/v1/admin/reports HTTP/1.1
GET /api/v2/users?all=true HTTP/1.1
GET /legacy/servlet/AdminServlet HTTP/1.1
```

### Pattern 4: Alternate HTTP methods on same path

```http
GET /admin/delete?id=5 HTTP/1.1
POST /admin/delete HTTP/1.1
# GET blocked by role check; POST unprotected
```

### Pattern 5: Static and backup filenames

```text
/backup.sql
/config.json
/server-status
/phpinfo.php
```

## Language-Specific Sinks and Dangerous APIs

Map route registration and security filters. Login checks alone do not protect admin functionality.

### Python

```python
@app.route("/admin/users")
def admin_users():
    if "user" in session:  # no admin role
        return render_template("admin_users.html", users=db.all_users())
```

Flask blueprints without `@roles_required`. Django: views missing `@user_passes_test` or permission decorator.

### Java

```java
@GetMapping("/admin/settings")
public String settings() { return "ok"; }  // no @PreAuthorize("hasRole('ADMIN')")

http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/public/**").permitAll()
    .anyRequest().authenticated());  // not hasRole
```

Spring Security: `authenticated()` without `hasRole`; `@WebFilter` that only checks `session != null`.

### C#

```csharp
[Authorize]
public IActionResult AdminUsers() => View(_db.Users.ToList());

app.MapGet("/internal/health/detailed", () => secrets);
```

`[Authorize]` without role policy; minimal APIs mapped without `RequireAuthorization("AdminOnly")`.

### JavaScript (Node.js)

```javascript
app.get('/admin', requireLogin, adminPage);
app.use('/api/internal', internalRouter);  // auth but no role middleware
```

Express: `isAuthenticated` without `isAdmin`; Next.js API routes without RBAC.

### Go

```go
mux.Handle("/admin/", authOnly(adminHandler))  // missing role check
http.HandleFunc("/debug/pprof/", pprof.Index)
```

Chi/gin: JWT valid but no `RequireRole("admin")` on sensitive groups.

### nginx / reverse proxy (deployment)

```nginx
location /admin { }  # no IP allowlist or auth_request in prod
location ~ /\. { }    # dotfiles accidentally exposed
```

## Sample Vulnerable Code in Python

```python
from flask import Flask, session, redirect, render_template, jsonify

app = Flask(__name__)

@app.route("/admin/users")
def admin_users():
    # Only checks login, not admin role — any authenticated user lists all users
    if "user" in session:
        return render_template("admin_users.html", users=db.all_users())
    return redirect("/login")

@app.route("/internal/health/detailed")
def detailed_health():
    return jsonify({"db": DB_PASSWORD, "queue": QUEUE_URL})
```

## Step-by-Step Review Walkthrough

1. **Inventory sensitive paths.** Admin consoles, actuator endpoints, debug tools, importer APIs, and legacy servlets.
2. **Map global filters and middleware.** Confirm they enforce role checks, not only `user != null`.
3. **Compare route registration across frameworks.** MVC controllers, JAX-RS, FastAPI routers, and static file handlers.
4. **Review default security config.** Spring `permitAll` lists, ASP.NET authorization fallbacks, and nginx `location` blocks.
5. **Check alternate channels.** Mobile API v2, GraphQL resolvers, and WebSocket handlers for the same missing checks.
6. **Trace filter ordering.** Authorization must run before business logic and cannot be skipped by error paths.
7. **Validate admin paths require elevated roles on the server for every HTTP method.**

## Risk Impact Analysis

**Administrative compromise.** Standard users reach management functions by navigating directly to unlinked admin URLs.

**Secret and config exposure.** Internal health and debug endpoints may return credentials, connection strings, or environment details.

**Data exfiltration.** Export and reporting paths without role checks leak records beyond the caller's entitlement.

**Infrastructure abuse.** Exposed actuator or swagger endpoints reveal attack surface and may enable dangerous operations.

**Audit failure.** Forced browsing is a common finding when UI hiding substitutes for server-side authorization.

## Vulnerable Examples in Other Languages

### Java

```java
@WebFilter(urlPatterns = { "/admin/*" })
public class AdminFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        User user = (User) request.getSession().getAttribute("user");
        if (user == null) {
            ((HttpServletResponse) res).sendRedirect("/auth/login");
            return;
        }
        chain.doFilter(req, res);
    }
}
```

### C#

```csharp
[Authorize]
[HttpGet("/manage/config")]
public IActionResult GetConfig()
{
    return Ok(_config.GetAllSecrets());
}
```

### Go

```go
func routes(mux *http.ServeMux) {
    mux.HandleFunc("/dashboard", requireLogin(dashboard))
    mux.HandleFunc("/admin/reports", requireLogin(adminReports))
}

func requireLogin(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if getUser(r) == "" {
            http.Redirect(w, r, "/login", http.StatusFound)
            return
        }
        next(w, r)
    }
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Require explicit roles on every admin route. Disable debug paths outside development.

```python
from flask_login import login_required, current_user
from functools import wraps

def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated or not current_user.has_role(*roles):
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route("/admin/users")
@login_required
@roles_required("admin")
def admin_users():
    return render_template("admin_users.html", users=db.all_users())

# FastAPI: mount admin router with dependency
admin_router = APIRouter(prefix="/admin", dependencies=[Depends(require_role("admin"))])
```

**Important:** Use Django `permission_required("auth.view_user")` on class-based admin views. Gate internal routes with environment settings.

### Java

Configure URL patterns with role requirements and method security as defense in depth.

```java
@Bean
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated());
    return http.build();
}

@GetMapping("/admin/users")
@PreAuthorize("hasRole('ADMIN')")
public List<User> listUsers() {
    return userRepository.findAll();
}
```

**Important:** Disable unused actuator exposure in production profiles. Return 403 instead of redirect that leaks path existence.

### C#

Use policy-based authorization with admin-only policies on management endpoints.

```csharp
[Authorize(Policy = "AdminOnly")]
[HttpGet("/manage/config")]
public IActionResult GetConfig()
{
    return Ok(_config.GetPublicSummary());
}

// Startup:
services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireRole("Admin"));
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser().Build();
});
```

**Important:** Call `RequireAuthorization()` globally in minimal APIs. Add integration tests that standard users receive 403 on `/manage/*`.

### Go

Compose middleware chains with role checks after authentication.

```go
func requireRole(role string, next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        user := userFromContext(r.Context())
        if user == "" || !userHasRole(user, role) {
            http.Error(w, "forbidden", http.StatusForbidden)
            return
        }
        next(w, r)
    }
}

func routes(mux *http.ServeMux) {
    mux.HandleFunc("/admin/reports",
        requireLogin(requireRole("admin", adminReports)))
}
```

**Important:** Use casbin or OPA for central role-path policies. Serve admin API on internal port with mTLS when feasible.

## Verify During Review

- Admin and internal paths require explicit elevated roles or scopes, not only authentication.
- Every HTTP method on sensitive resources has matching authorization checks.
- Global security configuration defaults to deny; exceptions are documented.
- Actuator, swagger, debug, and backup paths are disabled or restricted in production.
- Parallel API versions and WebSocket routes repeat the same authorization rules as primary HTTP handlers.
- UI hiding of links is supplemented by server enforcement on direct navigation.

## Reference

- [CWE-425: Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)
- [OWASP Top 10 — Broken Access Control](https://owasp.org/www-project-top-ten/)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [Django — Permissions and authorization](https://docs.djangoproject.com/en/stable/topics/auth/default/#permissions-and-authorization)
- [Flask-Principal roles](https://flask-principal.readthedocs.io/en/latest/)
- [Spring Security — Authorize HTTP requests](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html)
- [ASP.NET Core — Policy-based authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/policies)
- [Casbin documentation](https://casbin.org/docs/overview)
