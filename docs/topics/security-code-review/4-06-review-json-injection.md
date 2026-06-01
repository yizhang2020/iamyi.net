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

## Attack Payloads

Use these in authorized tests when user input is concatenated into JSON or merged into parsed objects. Confirm whether the backend uses a strict schema before relying on a single payload.

### Pattern 1: String termination and field injection

```json
","tenant_id":"999","x":"
","is_billing_admin":true,"note":"
```

Built manually: `{"note":"PAYLOAD","invoice_id":42}` where `PAYLOAD` closes the string and adds keys.

### Pattern 2: Prototype pollution (JavaScript merge sinks)

```json
{"__proto__":{"canApproveInvoices":true}}
{"constructor":{"prototype":{"tenant":"evil"}}}
{"__proto__":{"skipFraudCheck":true}}
```

### Pattern 3: Mass-assignment privilege escalation

```json
{"invoice_id":1001,"status":"paid","approved_by":"attacker"}
{"line_total":0,"tax_rate":0,"currency":"USD"}
{"owner_org_id":1,"target_org_id":999}
```

### Pattern 4: Array and type confusion

```json
{"line_items":[1,2,"'); DROP TABLE invoices;--"]}
{"amount":"99.99","amount":0.01}
{"auto_renew":"false"}
```

### Pattern 5: Nested object injection

```json
{"metadata":{"source":"webhook"},"billing":{"write_off":true}}
{"payload":{"__proto__":{"admin":true}}}
```

### Pattern 6: JSON inside JSON (double encoding)

```text
%7B%22status%22%3A%22paid%22%7D
{\"status\":\"paid\"}
```

## Language-Specific Sinks and Dangerous APIs

Search for manual JSON construction and untyped object merges. Any path that trusts client keys without schema validation is a review priority.

### Python

```python
payload = f'{{"note":"{note}","invoice_id":{inv_id}}}'
data = json.loads(raw)  # then data.update(request.json)
Invoice(**request.get_json())  # accepts all keys if model allows
webhook = {**defaults, **request.json}
```

### Java

```java
String json = "{\"name\":\"" + name + "\"}";
ObjectMapper mapper = new ObjectMapper();
Map<String, Object> body = mapper.readValue(input, Map.class);
BeanUtils.copyProperties(clientDto, serverEntity);
```

### C#

```csharp
var json = $"{{\"role\":\"{role}\"}}";
var obj = JsonConvert.DeserializeObject<Dictionary<string, object>>(body);
// Mass assignment:
_mapper.Map(clientModel, entity);
```

### JavaScript (Node.js)

```javascript
const body = `{ "name": "${req.body.name}" }`;
Object.assign(target, req.body);
lodash.merge(config, JSON.parse(userJson));
target.__proto__ = parsed.__proto__;
```

### Go

```go
payload := fmt.Sprintf(`{"name":"%s"}`, name)
json.Unmarshal(body, &map[string]interface{}{})
decoder.DisallowUnknownFields() // missing = accepts extra keys
```

### SQL (JSON columns)

```sql
UPDATE users SET profile = profile || user_json_fragment;
JSON_SET(profile, CONCAT('$.', user_key), user_value);
```

## Sample Vulnerable Code in Python

```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/api/webhooks/invoice", methods=["POST"])
def relay_invoice_webhook():
    # Attacker-controlled note may contain unescaped quotes
    note = request.form["note"]
    invoice_id = request.form["invoice_id"]
    # Sink: manual JSON string — breaks structure or injects fields
    payload = f'{{"note":"{note}","invoice_id":{invoice_id}}}'
    queue.publish("invoice-events", payload)
    return payload
```

## Step-by-Step Review Walkthrough

1. **Find JSON-producing and JSON-consuming endpoints.** Search for manual JSON assembly and `request.get_json()` merge paths.
2. **Trace the Python (or equivalent) write path.** In the sample, `note` is interpolated into a JSON string. Ask whether quotes in `note` can break out of the string or add keys.
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
@PostMapping("/webhooks/invoice")
public ResponseEntity<String> relayInvoice(@RequestBody String raw) {
    String json = "{\"vendor\":\"" + extractVendor(raw) + "\",\"payload\":" + raw + "}";
    eventBus.publish("invoice-events", json);
    return ResponseEntity.ok(json);
}

@PostMapping("/invoices/{id}/adjust")
public Invoice adjust(@PathVariable long id, @RequestBody Map<String, Object> body) {
    Invoice invoice = invoiceRepo.findById(id);
    invoice.setStatus((String) body.get("status")); // attacker sends "status": "paid"
    invoice.setWriteOff((Double) body.get("write_off"));
    return invoiceRepo.save(invoice);
}
```

### C#

```csharp
[HttpPost("webhooks/billing")]
public IActionResult RelayBillingEvent([FromBody] JsonElement body)
{
    var json = $"{{\"event\":\"{body.GetProperty("event")}\",\"amount\":{body.GetProperty("amount")},\"memo\":\"{body.GetProperty("memo")}\"}}";
    _queue.Publish(json);
    return Ok(json);
}

[HttpPatch("subscriptions/{id}")]
public IActionResult PatchSubscription(int id, [FromBody] Dictionary<string, object> fields)
{
    var sub = _db.Subscriptions.Find(id);
    foreach (var kv in fields)
        typeof(Subscription).GetProperty(kv.Key)?.SetValue(sub, kv.Value);
    _db.SaveChanges();
    return Ok(sub);
}
```

### JavaScript

```javascript
app.post("/api/webhooks/invoice", (req, res) => {
  const memo = req.body.memo;
  const payload = `{"memo":"${memo}","invoice_id":${req.body.invoice_id}}`;
  broker.publish("invoice-events", payload);
  res.type("json").send(payload);
});

app.patch("/api/invoices/:id", (req, res) => {
  Object.assign(currentInvoice, req.body); // merges attacker keys (e.g. status, write_off)
  saveInvoice(currentInvoice);
  res.json(currentInvoice);
});
```

### Go

```go
func relayWebhook(w http.ResponseWriter, r *http.Request) {
    memo := r.FormValue("memo")
    invoiceID := r.FormValue("invoice_id")
    payload := fmt.Sprintf(`{"memo":"%s","invoice_id":%s}`, memo, invoiceID)
    queue.Publish("invoice-events", payload)
    w.Write([]byte(payload))
}

func patchInvoice(w http.ResponseWriter, r *http.Request) {
    var patch map[string]interface{}
    json.NewDecoder(r.Body).Decode(&patch)
    inv := loadInvoice(invoiceIDFromPath(r))
    mergeMap(inv, patch) // copies attacker keys into struct via reflection
    saveInvoice(inv)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Build structures as dicts, then serialize with `json.dumps`. Never f-string JSON.

```python
import json

@app.route("/api/webhooks/invoice", methods=["POST"])
def relay_invoice_webhook():
    note = request.form["note"]
    invoice_id = int(request.form["invoice_id"])
    payload = json.dumps({"note": note, "invoice_id": invoice_id})
    queue.publish("invoice-events", payload)
    return payload
```

```python
from pydantic import BaseModel, ConfigDict, Field

class InvoiceAdjust(BaseModel):
    model_config = ConfigDict(extra="forbid")
    memo: str = Field(max_length=256)

@app.route("/invoices/<int:inv_id>/memo", methods=["PATCH"])
def patch_invoice_memo(inv_id):
    data = InvoiceAdjust.model_validate(request.get_json())
    invoice = load_invoice(inv_id)
    invoice.memo = data.memo  # explicit fields only
    db.session.commit()
    return jsonify({"memo": invoice.memo})
```

**Important:** Never `__dict__.update(request.json)` on persisted entities. Use separate read and write models.

### Java

Serialize with Jackson. Bind to typed DTOs with unknown fields rejected.

```java
import com.fasterxml.jackson.databind.ObjectMapper;

ObjectMapper mapper = new ObjectMapper();
String json = mapper.writeValueAsString(Map.of(
    "note", note,
    "invoiceId", invoiceId
));
```

```java
@JsonIgnoreProperties(ignoreUnknown = true)
public record InvoiceAdjustRequest(
    @NotBlank @Size(max = 256) String memo
    // status and write_off are NOT accepted from client — computed server-side
) {}
```

**Important:** Avoid raw `Map<String,Object>` for security-sensitive endpoints. Use typed records with Bean Validation.

### C#

Serialize typed objects. Reject unknown members on sensitive models.

```csharp
var payload = JsonSerializer.Serialize(new BillingWebhookMessage
{
    Event = dto.Event,
    Amount = dto.Amount,
    Tax = ComputeTax(dto.Sku, UserId) // server-computed
});
```

```csharp
// Strict deserialization:
var options = new JsonSerializerOptions { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
var dto = JsonSerializer.Deserialize<InvoiceMemoRequest>(body, options);
```

**Important:** Audit `[JsonExtensionData]` on sensitive models. Unexpected keys must not silently capture privileged fields.

### Go

Unmarshal into typed structs. Disallow unknown fields for strict parsing.

```go
func relayWebhook(w http.ResponseWriter, r *http.Request) {
    var req InvoiceWebhookRequest
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()
    if err := dec.Decode(&req); err != nil {
        http.Error(w, "invalid json", http.StatusBadRequest)
        return
    }
    payload, _ := json.Marshal(map[string]interface{}{
        "memo":       req.Memo,
        "invoice_id": req.InvoiceID,
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
