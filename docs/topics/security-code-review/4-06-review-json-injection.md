---
title: Review JSON Injection
keywords:
  - security code review
  - json injection
  - json parsing
  - prototype pollution
  - input validation
description: How to read code for JSON injection—trace attacker-controlled data into JSON construction or object merges and verify schema enforcement server-side.
---

## 4.6 - Review JSON Injection

JSON injection appears when attacker-controlled strings are concatenated into JSON documents or merged into parsed objects without schema validation. Start from APIs that build JSON manually, webhook payloads, and configuration blobs. Trace each user field through serialization and confirm structure is enforced server-side.

## What This Vulnerability Is

JSON injection is a server-side injection flaw. The application treats JSON as plain text or merges untrusted key-value pairs into objects that drive authorization, pricing, or workflow state. Attackers add fields, close strings early, or inject nested objects the developer did not intend.

The unsafe assumption is that clients send well-formed JSON with only expected keys. Attacker-controlled input can elevate privileges (`"role":"admin"`), alter amounts (`"price":0`), or break downstream parsers. This relates to [CWE-915](https://cwe.mitre.org/data/definitions/915.html) (Improperly Controlled Modification of Dynamically-Determined Variable Indexes).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Profile updates, checkout, order APIs, settings save, webhook relay, OAuth token handling |
| **Input entry** | JSON bodies, form fields embedded in JSON, query parameters serialized to JSON |
| **String-built JSON** | f-strings, concatenation of `{`, `}`, `"`, `:` from HTTP input without a serializer |
| **Mass assignment** | `dict.update`, spread operators, reflection that copies all client keys into models |
| **Weak controls** | Untyped `Map<String,Object>`, missing schema validation, trusting client price or role fields |
| **Downstream trust** | Microservices or batch jobs that accept JSON from a prior tier without re-validation |

## Sample Vulnerable Code in Python

```python
from flask import Flask, request, session

app = Flask(__name__)

@app.route("/api/settings", methods=["POST"])
def save_settings():
    # Attacker-controlled theme may contain unescaped quotes
    theme = request.form["theme"]
    # Sink: manual JSON string — breaks structure or injects fields
    payload = f'{{"theme":"{theme}","user_id":{session["user_id"]}}}'
    redis.set(f"settings:{session['user_id']}", payload)
    return payload
```

## Step-by-Step Review Walkthrough

1. **Find JSON-producing and JSON-consuming endpoints.** Search for manual JSON assembly and `request.get_json()` merge paths.
2. **Trace the Python (or equivalent) write path.** In the sample, `theme` is interpolated into a JSON string. Ask whether quotes in `theme` can break out of the string or add keys.
3. **Search for string-built JSON.** Flag f-strings and concatenation that build `{`, `}`, `"`, or `:` from HTTP input.
4. **Review merge operations.** `dict.update`, `__dict__.update`, and spread operators that copy client keys into server objects accept extra fields like `is_admin`.
5. **Check authorization and pricing logic.** Fields that drive access or amounts must be set server-side, not copied from client JSON.
6. **Inspect deserialization settings.** Unknown properties, polymorphic type fields, and default values that trust missing keys.
7. **Follow JSON embedded in other formats.** JWT claims, GraphQL variables, and SQL JSON columns need the same schema discipline.

## Risk Impact Analysis

**Privilege escalation.** Extra JSON keys such as `role`, `is_admin`, or `permissions` may overwrite server state when mass assignment is allowed.

**Financial fraud.** Client-supplied `price`, `discount`, or `quantity` fields can reduce charges or inflate credits when the server trusts them.

**Parser confusion.** Malformed hand-built JSON may break downstream consumers or trigger unexpected behavior in chained services.

**Integrity and audit gaps.** Injected fields in stored JSON may alter workflow state, bypass approval steps, or corrupt audit trails.

## Vulnerable Examples in Other Languages

### Java

```java
@PostMapping("/profile")
public ResponseEntity<String> updateProfile(@RequestBody String raw) {
    String json = "{\"user\":\"" + extractUsername(raw) + "\",\"prefs\":" + raw + "}";
    profileStore.save(json);
    return ResponseEntity.ok(json);
}

@PostMapping("/order")
public Order create(@RequestBody Map<String, Object> body) {
    Order order = new Order();
    order.setQuantity((Integer) body.get("quantity"));
    order.setPrice((Double) body.get("price")); // attacker sends "price": 0
    order.setCustomerId(currentUserId());
    return orderRepo.save(order);
}
```

### C#

```csharp
[HttpPost("checkout")]
public IActionResult Checkout([FromBody] JsonElement body)
{
    var json = $"{{\"sku\":\"{body.GetProperty("sku")}\",\"qty\":{body.GetProperty("qty")},\"discount\":{body.GetProperty("discount")}}}";
    _queue.Publish(json);
    return Ok(json);
}

[HttpPut("users/{id}")]
public IActionResult UpdateUser(int id, [FromBody] Dictionary<string, object> fields)
{
    var user = _db.Users.Find(id);
    foreach (var kv in fields)
        typeof(User).GetProperty(kv.Key)?.SetValue(user, kv.Value);
    _db.SaveChanges();
    return Ok(user);
}
```

### JavaScript

```javascript
app.post("/api/settings", (req, res) => {
  const color = req.body.color;
  const payload = `{"color":"${color}","uid":${req.session.userId}}`;
  db.run("UPDATE prefs SET data = ? WHERE uid = ?", payload, req.session.userId);
  res.type("json").send(payload);
});

app.patch("/api/users/me", (req, res) => {
  Object.assign(currentUser, req.body); // merges attacker keys (e.g. role, price)
  saveUser(currentUser);
  res.json(currentUser);
});
```

### Go

```go
func updatePrefs(w http.ResponseWriter, r *http.Request) {
    color := r.FormValue("color")
    payload := fmt.Sprintf(`{"color":"%s","uid":%d}`, color, userIDFromSession(r))
    db.Exec("UPDATE prefs SET data = $1 WHERE uid = $2", payload, userIDFromSession(r))
    w.Write([]byte(payload))
}

func applyPatch(w http.ResponseWriter, r *http.Request) {
    var patch map[string]interface{}
    json.NewDecoder(r.Body).Decode(&patch)
    user := loadUser(userIDFromSession(r))
    mergeMap(user, patch) // copies attacker keys into struct via reflection
    saveUser(user)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Build structures as dicts, then serialize with `json.dumps`. Never f-string JSON.

```python
import json

@app.route("/api/settings", methods=["POST"])
def save_settings():
    theme = request.form["theme"]
    payload = json.dumps({"theme": theme, "user_id": session["user_id"]})
    redis.set(f"settings:{session['user_id']}", payload)
    return payload
```

```python
from pydantic import BaseModel, ConfigDict, Field

class SettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    theme: str = Field(max_length=64)

@app.route("/api/user", methods=["PATCH"])
def patch_user():
    data = SettingsUpdate.model_validate(request.get_json())
    user = current_user()
    user.theme = data.theme  # explicit fields only
    db.session.commit()
    return jsonify({"theme": user.theme})
```

**Important:** Never `__dict__.update(request.json)` on persisted entities. Use separate read and write models.

### Java

Serialize with Jackson. Bind to typed DTOs with unknown fields rejected.

```java
import com.fasterxml.jackson.databind.ObjectMapper;

ObjectMapper mapper = new ObjectMapper();
String json = mapper.writeValueAsString(Map.of(
    "theme", theme,
    "userId", currentUserId()
));
```

```java
@JsonIgnoreProperties(ignoreUnknown = true)
public record OrderRequest(
    @NotNull @Min(1) Integer quantity
    // price is NOT accepted from client — computed server-side
) {}
```

**Important:** Avoid raw `Map<String,Object>` for security-sensitive endpoints. Use typed records with Bean Validation.

### C#

Serialize typed objects. Reject unknown members on sensitive models.

```csharp
var payload = JsonSerializer.Serialize(new CheckoutMessage
{
    Sku = dto.Sku,
    Qty = dto.Qty,
    Discount = ComputeDiscount(dto.Sku, UserId) // server-computed
});
```

```csharp
// Strict deserialization:
var options = new JsonSerializerOptions { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
var dto = JsonSerializer.Deserialize<UpdateProfileRequest>(body, options);
```

**Important:** Audit `[JsonExtensionData]` on sensitive models. Unexpected keys must not silently capture privileged fields.

### Go

Unmarshal into typed structs. Disallow unknown fields for strict parsing.

```go
func updatePrefs(w http.ResponseWriter, r *http.Request) {
    var req SettingsRequest
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()
    if err := dec.Decode(&req); err != nil {
        http.Error(w, "invalid json", http.StatusBadRequest)
        return
    }
    payload, _ := json.Marshal(map[string]interface{}{
        "color": req.Color,
        "uid":   userIDFromSession(r),
    })
    w.Write(payload)
}
```

**Important:** Avoid `map[string]interface{}` for auth or billing endpoints. Use separate input structs from persistence models.

## Verify During Review

- No hand-built JSON strings include HTTP parameters without proper escaping through a serializer.
- Request bodies bind to typed DTOs with unknown fields rejected or ignored by policy.
- Price, role, ownership, and status fields are set server-side, not copied from client JSON.
- Schema validation runs at the API boundary and in tests for extra-key and type-confusion cases.
- JSON stored in databases or queues is produced by libraries, not string templates.
- Downstream consumers re-validate or treat upstream JSON as untrusted when crossing trust boundaries.

## Reference

- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Variable Indexes](https://cwe.mitre.org/data/definitions/915.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [Python json module](https://docs.python.org/3/library/json.html)
- [Pydantic v2 — model configuration](https://docs.pydantic.dev/latest/api/config/)
- [jsonschema on PyPI](https://pypi.org/project/jsonschema/)
- [Jackson ObjectMapper](https://javadoc.io/doc/com.fasterxml.jackson.core/jackson-databind/latest/com/fasterxml/jackson/databind/ObjectMapper.html)
- [Jakarta Bean Validation](https://jakarta.ee/specifications/bean-validation/3.0/)
- [System.Text.Json — unmapped members](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/missing-members)
- [Go encoding/json — Decoder.DisallowUnknownFields](https://pkg.go.dev/encoding/json#Decoder.DisallowUnknownFields)
- [JSON Schema specification](https://json-schema.org/)
