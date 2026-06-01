---
title: Review Authentication and Authorization
keywords:
  - security code review
  - authentication
  - authorization
  - access control
  - broken access control
description: How to read code for missing authorization—trace authentication entry points and verify every sensitive operation checks permissions server-side.
---

## 4.17 - Review Authentication and Authorization

Authentication confirms identity; authorization decides what that identity may do. Many severe flaws come from doing the first step well and skipping the second. Review login and token validation together with every sensitive read, write, and admin action. Trace whether the code checks permissions on the server, not only in the UI or route naming.

## What This Vulnerability Is

Insecure authentication lets attackers pose as another user through weak credential checks, session flaws, or forged tokens. Missing authorization lets authenticated users access other users' data or admin functions because the handler never verifies ownership or role. Authentication alone does not limit which records or APIs are reachable.

The unsafe assumption is that knowing a valid session or API key implies permission for every downstream operation. Impact ranges from horizontal data access to full administrative compromise. This maps to [OWASP Broken Access Control](https://owasp.org/www-project-top-ten/) and [CWE-285](https://cwe.mitre.org/data/definitions/285.html) (Improper Authorization).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Reports, exports, refunds, role changes, config edits, cross-tenant queries |
| **Authn entry points** | Login, API keys, OAuth callbacks, service accounts, machine-to-machine tokens |
| **Missing authz** | Handlers load resources by attacker-supplied ID without ownership test |
| **Client-trusted roles** | `isAdmin` from JWT body, `X-Admin` header, or JSON field without server mapping |
| **Implicit public** | `permitAll`, `[AllowAnonymous]`, missing middleware on `/internal` paths |
| **Service bypass** | Message consumers and schedulers calling repositories without authorization |

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
@app.route("/api/document/<doc_id>")
def get_document(doc_id):
    return db.documents.find_one({"_id": doc_id})  # no owner filter

if request.json.get("is_admin"):
    grant_admin()
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

## Sample Vulnerable Code in Python

```python
from flask import Flask, session, request, jsonify

app = Flask(__name__)

@app.route("/api/document/<doc_id>")
def get_document(doc_id):
    if "user" not in session:
        return "", 401
    # Authenticated but no ownership check — any user reads any document
    return jsonify(db.documents.find_one({"_id": doc_id}))

@app.route("/admin/settings", methods=["POST"])
def save_settings():
    # No role check; any caller who reaches the route can update config
    data = request.get_json()
    config.update(data)
    return jsonify(ok=True)
```

## Step-by-Step Review Walkthrough

1. **Map authentication entry points.** Login, API keys, OAuth callbacks, service accounts, and machine-to-machine tokens.
2. **Verify credential validation.** Password hashes, MFA gates, account lockout, and consistent failure responses.
3. **List sensitive operations.** Exports, refunds, role changes, config edits, and cross-tenant queries.
4. **For each operation, find the authorization check.** Role, scope, resource owner, or policy engine call must appear before the action.
5. **Compare UI restrictions to server enforcement.** Hidden buttons are not security controls.
6. **Review default-deny vs default-allow.** New endpoints should require explicit permission annotations.
7. **Check service layers and background jobs.** They must inherit the same authorization as HTTP controllers.

## Risk Impact Analysis

**Horizontal data access.** Authenticated users read or modify records belonging to others when ownership checks are absent.

**Administrative compromise.** Missing role checks on admin routes let standard users change configuration, roles, or billing.

**Tenant isolation failure.** Cross-tenant queries without tenant predicates expose one customer's data to another.

**Persistent unauthorized changes.** Background jobs and message handlers without authz may apply attacker-supplied operations at scale.

**Regulatory and contractual breach.** Broken access control is a top OWASP category and a common finding in security assessments.

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

## Verify During Review

- Every sensitive operation performs server-side authorization after authentication.
- Resource access validates ownership, tenant, or role—not only presence of a session.
- Admin and internal routes require explicit elevated permissions, not obscurity.
- New endpoints default to deny; public exceptions are documented and rare.
- Background workers and message handlers enforce the same rules as HTTP APIs.
- Code structure makes authentication steps distinct from authorization checks for maintainers.

## Reference

- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [OWASP Top 10 — Broken Access Control](https://owasp.org/www-project-top-ten/)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [Django — Permissions](https://docs.djangoproject.com/en/stable/topics/auth/default/#permissions-and-authorization)
- [Flask-Login documentation](https://flask-login.readthedocs.io/en/latest/)
- [Spring Security — Method Security](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)
- [ASP.NET Core — Authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/introduction)
- [Casbin documentation](https://casbin.org/docs/overview)
