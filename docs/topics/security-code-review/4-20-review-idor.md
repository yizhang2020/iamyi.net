---
title: Review IDOR
keywords:
  - security code review
  - idor
  - insecure direct object reference
  - horizontal privilege escalation
  - object level authorization
description: How to read code for insecure direct object references—verify object lookups bind to the authenticated principal's scope.
---

## 4.20 - Review IDOR

Insecure direct object references (IDOR) appear when the application uses predictable identifiers—numeric IDs, UUIDs in URLs, file names, or invoice numbers—without verifying the caller may access that object. Review edit, download, and API endpoints that take `id`, `userId`, `accountId`, or similar parameters. Confirm the server binds each query to the authenticated principal's scope.

## What This Vulnerability Is

IDOR is horizontal privilege escalation. A user authorized for object A can read or modify object B by changing an identifier in the URL, body, or header. The application performs the database or file operation but never checks ownership, tenant, or role against the target resource.

The unsafe assumption is that opaque or sequential IDs are secret. Attackers enumerate IDs or reuse leaked references from logs and emails. Impact includes exposure of personal data, unauthorized edits, and mass account compromise. This maps to [CWE-639](https://cwe.mitre.org/data/definitions/639.html) (Authorization Bypass Through User-Controlled Key) and [OWASP Broken Access Control](https://owasp.org/www-project-top-ten/).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Profile edit, invoice download, order detail, file download, message view |
| **Object selectors** | Path variables, query strings, JSON `id` fields, hidden form inputs |
| **ID-only lookup** | `findById(userSuppliedId)` with no ownership filter in repository layer |
| **Client-supplied owner** | Create/update DTOs accepting `userId`, `orgId`, or `accountId` from body |
| **Batch endpoints** | Arrays of IDs returned without per-item authorization |
| **File access** | `send_file(userInput)` or bucket keys built from unsanitized names |

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

## Sample Vulnerable Code in Python

```python
import os
from django.http import FileResponse, JsonResponse
from django.views.decorators.http import require_GET

@require_GET
def invoice_detail(request, invoice_id):
    if not request.user.is_authenticated:
        return JsonResponse({"error": "login required"}, status=401)
    # Authenticated but no owner filter — ID swap exposes other tenants' invoices
    inv = Invoice.objects.get(pk=invoice_id)
    return JsonResponse({"id": inv.id, "total": inv.total, "customer": inv.customer_email})

@require_GET
def attachment_download(request):
    key = request.GET.get("key")
    # User-supplied storage key without ACL check
    return FileResponse(open(os.path.join("/data/attachments", key), "rb"))
```

## Step-by-Step Review Walkthrough

1. **List parameters that select objects.** Path variables, query strings, JSON fields, and hidden form inputs.
2. **Trace the Django invoice handler.** In the sample, authenticated users can swap `invoice_id` without an owner predicate. Every object lookup needs principal scope.
3. **Locate authorization between lookup and response.** Compare resource `ownerId`, `tenantId`, or ACL to current user.
4. **Review bulk and export endpoints.** Arrays of IDs need per-item checks, not only batch existence.
5. **Check indirect references.** Download tokens, signed URLs, and GraphQL node IDs that decode to internal keys.
6. **Inspect create/update flows.** Attackers may set `owner_id` or `role` via mass assignment on create.
7. **Test UUID assumptions.** Even random IDs need authorization when leaked through shared links or logs.

## Risk Impact Analysis

**Personal data exposure.** Horizontal access to medical, financial, or account records violates privacy expectations and regulations.

**Unauthorized modification.** Attackers change addresses, payment methods, or orders belonging to other users.

**Mass enumeration.** Sequential IDs enable scripted harvesting of records across an entire dataset.

**File system access.** Path-based downloads without ACL checks may expose uploads from other tenants.

**Reputational and legal harm.** IDOR findings often trigger breach notification analysis and customer churn.

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

## Verify During Review

- Object lookups include owner, tenant, or permission predicate tied to the authenticated principal.
- Create and update operations ignore client-supplied ownership fields or validate them against policy.
- File and export endpoints authorize each object, including batch and async jobs.
- Indirect reference tokens are bound to the user session and expire appropriately.
- Mobile, GraphQL, and internal APIs apply the same object-level checks as primary web routes.
- Enumeration risk is reduced with rate limits and consistent 404/403 responses where policy allows.

## Reference

- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP Top 10 — Broken Access Control](https://owasp.org/www-project-top-ten/)
- [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
- [Django — Object-level permissions](https://django-guardian.readthedocs.io/en/stable/)
- [Spring Data — Query methods](https://docs.spring.io/spring-data/jpa/docs/current/reference/html/#jpa.query-methods)
- [Spring Security — PostAuthorize](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)
- [ASP.NET Core — Resource-based authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/resourcebased)
- [EF Core — Global query filters](https://learn.microsoft.com/en-us/ef/core/querying/filters)
