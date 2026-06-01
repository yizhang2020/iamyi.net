---
title: Review Client-Side Validation
keywords:
  - security code review
  - client-side validation
  - server-side validation
  - business logic
  - input validation
description: How to read code for reliance on client-side validation—trace each validated field to the server handler and confirm equivalent server-side checks run before persistence.
---

## 4.11 - Review Client-Side Validation

Client-side validation gaps appear when HTML attributes, JavaScript checks, or front-end frameworks enforce rules that the server never repeats. Start from forms, SPA APIs, mobile clients, and admin tools. Trace each validated field from browser to controller.

## What This Vulnerability Is

Missing server-side validation is a business logic and input-trust flaw. Browsers can enforce `pattern`, `required`, `maxlength`, and JavaScript checks for user experience. Attackers bypass these controls with modified requests, custom HTTP clients, or browser devtools.

The unsafe assumption is that well-behaved clients are the only callers. Without server-side enforcement, attackers submit negative quantities, past expiration dates, unauthorized role values, or oversized payloads. This relates to [CWE-602](https://cwe.mitre.org/data/definitions/602.html) (Client-Side Enforcement of Server-Side Security) and [CWE-20](https://cwe.mitre.org/data/definitions/20.html) (Improper Input Validation).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Checkout, registration, transfers, profile update, admin forms, SPA JSON APIs |
| **Client-only guards** | HTML5 `pattern`, `min`, `max`, `required`; React/Vue validators with no server mirror |
| **Hidden/trusted fields** | `role`, `price`, `userId`, `discount` in POST bodies accepted without server recomputation |
| **API parity gaps** | Mobile and third-party callers hit endpoints with weaker validation than the web UI |
| **Missing server libs** | Handlers with no Bean Validation, Pydantic, FluentValidation, or Go validator tags |
| **Partial persistence** | Invalid input rejected in UI but partially saved when API calls skip validation |

## Attack Payloads

Use these in authorized tests to bypass client-only checks. Send requests directly to the server API with tools such as curl, Burp, or Postman—never rely on the browser form alone.

### Pattern 1: Omit or tamper with hidden/trusted fields

```json
{"card_number":"4111111111111111","amount":0.01,"tier":"enterprise","account_id":999}
{"gift_code":"INTERNAL","balance":99999,"is_verified":true}
```

### Pattern 2: Type and range violations

```json
{"months":-12}
{"gift_amount":99999999999}
{"pin":"abc"}
{"recipient_email":"not-an-email"}
```

### Pattern 3: Bypass HTML5 constraints

```http
POST /gift-cards/redeem HTTP/1.1
Content-Type: application/json

{"amount":0,"pin":""}
```

Remove `required`, `pattern`, `min`, and `max` attributes have no effect on raw HTTP.

### Pattern 4: Oversized and malformed input

```text
recipient_name=AAAA...(100000 chars)...AAAA
message=<binary without client size check>
{"note":"<script>alert(1)</script>"}
```

### Pattern 5: Replay and step-skipping

```http
POST /api/subscription/activate
{"subscription_id":555,"status":"active","payment_captured":true}
```

Skip wizard steps the UI enforces in JavaScript only.

### Pattern 6: Alternate API versions and content types

```http
POST /api/v2/gift-cards/redeem
Content-Type: application/x-www-form-urlencoded

amount=1000&tier=enterprise&email=attacker@example.com
```

Mobile or legacy endpoints may lack validators present in the SPA.

## Language-Specific Sinks and Dangerous APIs

Client-side validation improves UX but is not a security control. Review both the browser-side APIs below and confirm each field has a matching server-side check.

### HTML (form attributes)

```html
<input type="number" min="1" max="10" required>
<input pattern="[A-Za-z]+" name="username">
<form novalidate>  <!-- browser checks disabled — server must still validate -->
<select required name="role">...</select>
```

### JavaScript (browser validation)

```javascript
if (!form.checkValidity()) return;
if (quantity < 1 || quantity > 10) showError();
const schema = z.object({ email: z.string().email() });
schema.parse(formData);  // client-only — not enforced server-side
```

### JavaScript (React / Vue)

```javascript
// React — client rules only
const errors = validate(values);
if (errors.quantity) return;

// Vue — Vuelidate / vee-validate without API mirror
rules: { amount: { minValue: minValue(0) } }
```

### Python (missing server validation)

```python
@app.route("/gift-cards/redeem", methods=["POST"])
def redeem_gift_card():
    data = request.get_json()  # no pydantic/marshmallow
    balance = data["amount"] + data.get("bonus", 0)
```

### Java (Bean Validation gap)

```java
// DTO without @Valid on controller parameter
public Order create(@RequestBody OrderRequest req) { ... }

// Client sends @NotNull fields as null via raw JSON
@NotBlank String email;  // never enforced if @Valid missing
```

### C# (DataAnnotations gap)

```csharp
public IActionResult Save([FromBody] ProfileModel model)
{
    // Missing ModelState.IsValid check
    _repo.Save(model);
}
```

### Go (missing validator tags)

```go
type Checkout struct {
    Quantity int `json:"quantity"`  // no validate:"gte=1"
}
json.NewDecoder(r.Body).Decode(&req)  // no validator.Struct(req)
```

### SQL (trust from prior tier)

```sql
-- Batch job trusts JSON column written by API with client-only validation
INSERT INTO orders SELECT * FROM json_populate_record(NULL::orders, client_json);
```

## Sample Vulnerable Code in Python

```python
from flask import Flask, request, session, jsonify

app = Flask(__name__)

@app.route("/gift-cards/redeem", methods=["POST"])
def redeem_gift_card():
    data = request.get_json()
    # React form validates amount and PIN client-side only — server trusts JSON
    credit = data["amount"] + data.get("bonus", 0)
    redemption = GiftRedemption(
        user_id=session["user_id"],
        credit=credit,
        pin=data.get("pin"),
    )
    db.session.add(redemption)
    db.session.commit()
    return jsonify({"credit": credit})
```

## Step-by-Step Review Walkthrough

1. **Inventory client validation.** List forms and API fields with HTML5 constraints, JavaScript checks, or mobile validators.
2. **Open the matching server handler.** In the sample, `redeem_gift_card` reads JSON and computes credit without range checks. Ask whether amount, bonus, or PIN are validated server-side; they are not.
3. **Compare client and server rules.** Required fields, numeric ranges, regex patterns, and max lengths must match—or the server must be stricter.
4. **Review hidden and disabled fields.** Attackers can POST `role`, `price`, or `userId` even when the UI hides them.
5. **Check SPA-only APIs.** Absence of browser forms does not remove the need for server validation.
6. **Trace validation libraries.** Confirm Pydantic, Marshmallow, Bean Validation, or Go validator tags run before database calls.
7. **Confirm negative tests.** Send invalid payloads directly to APIs without going through the front end.

## Risk Impact Analysis

**Financial fraud.** Client-trusted quantities, prices, and coupons allow negative totals, free orders, or unauthorized discounts.

**Authorization bypass.** Hidden role or permission fields accepted from the body may elevate privileges when the server does not recompute them.

**Data corruption.** Out-of-range or malformed values may violate database constraints or produce inconsistent business state.

**Injection and downstream flaws.** Unvalidated input that reaches SQL, shell, or template sinks inherits those vulnerability classes.

## Vulnerable Examples in Other Languages

### Java

```java
@PostMapping("/gift-cards/redeem")
public ResponseEntity<?> redeem(@RequestBody RedeemRequest req) {
    // Front-end enforces amount > 0 and PIN format; server skips validation
    giftCardService.redeem(req.getPin(), req.getAmount(), req.getBonus());
    return ResponseEntity.ok().build();
}

@PostMapping("/subscriptions/upgrade")
public String upgrade(@RequestParam String tier, @RequestParam int months) {
    subscriptionService.upgrade(currentUser(), tier, months); // no server-side tier policy
    return "redirect:/account";
}
```

### C#

```csharp
[HttpPost("gift-cards/redeem")]
public IActionResult RedeemGiftCard(RedeemDto dto)
{
    // Blazor form validates PIN format; API endpoint accepts raw dto
    _service.Redeem(UserId, dto);
    return Ok();
}

public class RedeemDto
{
    public string Pin { get; set; }
    public decimal Amount { get; set; } // no [Range], [Required], or length limits
}
```

### JavaScript

```javascript
function validateRedeem() {
  const amount = Number(document.querySelector('[name="amount"]').value);
  if (amount < 5 || amount > 500) return false;
  return true; // bypass with curl; server must re-validate
}

document.getElementById("redeem").addEventListener("submit", (e) => {
  if (!validateRedeem()) e.preventDefault();
  // hidden bonus/tier fields sent without server-side recomputation
});
```

### HTML

```html
<form action="/gift-cards/redeem" method="post">
  <input type="number" name="amount" min="5" max="500" required>
  <input type="hidden" name="bonus" value="0">
  <input type="hidden" name="tier" value="standard">
  <!-- min/max/required are browser hints only; not enforced on server -->
</form>
```

## Fix: Safer Patterns and Libraries to Use

### Python

Validate at the API boundary with Pydantic. Recompute trusted fields server-side.

```python
from pydantic import BaseModel, Field, EmailStr, ConfigDict

class GiftCardRedeemRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    amount: float = Field(ge=5, le=500)
    pin: str = Field(min_length=8, max_length=16)

@app.route("/gift-cards/redeem", methods=["POST"])
def redeem_gift_card():
    req = GiftCardRedeemRequest.model_validate(request.get_json())
    credit = gift_cards.redeem(req.pin, req.amount)  # server-computed, not from client bonus field
    redemption = GiftRedemption(user_id=session["user_id"], credit=credit)
    db.session.add(redemption)
    db.session.commit()
    return jsonify({"credit": credit})
```

**Important:** Client-side validation is UX only. Every security-relevant rule must exist on the server.

```python
# Marshmallow alternative:
from marshmallow import Schema, fields, validate

class RedeemSchema(Schema):
    amount = fields.Decimal(required=True, validate=validate.Range(min=5, max=500))
    pin = fields.Str(required=True, validate=validate.Length(min=8, max=16))
```

### Java

Apply Jakarta Bean Validation on request DTOs. Reject invalid input before the service layer.

```java
public record GiftCardRedeemRequest(
    @NotBlank @Pattern(regexp = "^[A-Z0-9]{8,16}$") String pin,
    @NotNull @DecimalMin("5.00") @DecimalMax("500.00") BigDecimal amount
) {}

@PostMapping("/gift-cards/redeem")
public ResponseEntity<?> redeem(@Valid @RequestBody GiftCardRedeemRequest req) {
    giftCardService.redeem(req.pin(), req.amount());
    return ResponseEntity.ok().build();
}
```

**Important:** Use `@Valid` on every mutating controller parameter. Recompute price, role, and owner from server context.

### C#

Use DataAnnotations or FluentValidation. Check ModelState on every mutating action.

```csharp
public class RedeemDto
{
    [Required, RegularExpression("^[A-Z0-9]{8,16}$")]
    public string Pin { get; set; } = "";

    [Required, Range(5, 500)]
    public decimal Amount { get; set; }
}

[HttpPost("gift-cards/redeem")]
public IActionResult RedeemGiftCard([FromBody] RedeemDto dto)
{
    if (!ModelState.IsValid)
        return BadRequest(ModelState);
    _service.Redeem(UserId, dto);
    return Ok();
}
```

**Important:** Never trust disabled UI fields. Authorization-sensitive properties come from server claims, not the request body.

### Go

Validate struct tags after JSON decode. Reject unknown fields.

```go
import "github.com/go-playground/validator/v10"

type RedeemGiftCardRequest struct {
    Amount float64 `json:"amount" validate:"required,gte=5,lte=500"`
    Pin    string  `json:"pin" validate:"required,min=8,max=16"`
}

func redeemGiftCard(w http.ResponseWriter, r *http.Request) {
    var req RedeemGiftCardRequest
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()
    if err := dec.Decode(&req); err != nil {
        http.Error(w, "invalid json", http.StatusBadRequest)
        return
    }
    if err := validate.Struct(req); err != nil {
        http.Error(w, "validation failed", http.StatusBadRequest)
        return
    }
    credit := giftcards.Redeem(req.Pin, req.Amount)
    db.Exec("INSERT INTO redemptions (user_id, credit) VALUES ($1,$2)", userID(r), credit)
}
```

**Important:** Shared validation middleware beats ad hoc checks scattered across handlers.

## Verify During Review

- Every user-editable field has equivalent server-side validation before business logic runs.
- HTML5, JavaScript, and mobile validations are treated as UX only, not security controls.
- Trusted values (price, role, user ID, discount eligibility) are computed server-side, not read from the client.
- Invalid input returns consistent 400 responses with safe error messages; handlers do not partially persist bad data.
- API endpoints used by SPAs and mobile apps enforce the same rules as server-rendered forms.
- Security tests bypass the front end and send out-of-range, missing, and malformed fields to each endpoint.

## Reference

- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Pydantic v2 — field constraints](https://docs.pydantic.dev/latest/concepts/fields/)
- [Marshmallow documentation](https://marshmallow.readthedocs.io/en/latest/)
- [Jakarta Bean Validation](https://jakarta.ee/specifications/bean-validation/3.0/)
- [Hibernate Validator](https://hibernate.org/validator/documentation/)
- [ASP.NET Core model validation](https://learn.microsoft.com/en-us/aspnet/core/mvc/models/validation)
- [FluentValidation](https://docs.fluentvalidation.net/)
- [go-playground/validator](https://pkg.go.dev/github.com/go-playground/validator/v10)
