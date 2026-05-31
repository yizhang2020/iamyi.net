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

## Sample Vulnerable Code in Python

```python
from flask import Flask, request, session, jsonify

app = Flask(__name__)

@app.route("/checkout", methods=["POST"])
def checkout():
    data = request.get_json()
    # Vue form validates quantity and coupon client-side only — server trusts JSON
    total = data["quantity"] * data["unit_price"]
    order = Order(
        user_id=session["user_id"],
        total=total,
        coupon=data.get("coupon"),
    )
    db.session.add(order)
    db.session.commit()
    return jsonify({"total": total})
```

## Step-by-Step Review Walkthrough

1. **Inventory client validation.** List forms and API fields with HTML5 constraints, JavaScript checks, or mobile validators.
2. **Open the matching server handler.** In the sample, `checkout` reads JSON and computes total without range checks. Ask whether quantity, price, or coupon are validated server-side; they are not.
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
@PostMapping("/transfer")
public ResponseEntity<?> transfer(@RequestBody TransferRequest req) {
    // Front-end enforces amount > 0 and recipient format; server skips validation
    accountService.transfer(req.getFromId(), req.getToAccount(), req.getAmount());
    return ResponseEntity.ok().build();
}

@PostMapping("/register")
public String register(@RequestParam String email, @RequestParam String password) {
    userService.create(email, password); // no server-side email/password policy
    return "redirect:/login";
}
```

### C#

```csharp
[HttpPost("update-profile")]
public IActionResult UpdateProfile(ProfileDto dto)
{
    // Blazor form validates phone format; API endpoint accepts raw dto
    _service.UpdateProfile(UserId, dto);
    return Ok();
}

public class ProfileDto
{
    public string Phone { get; set; }
    public string DisplayName { get; set; } // no [Required], [Phone], or length limits
}
```

### JavaScript

```javascript
function validateCheckout() {
  const qty = Number(document.querySelector('[name="quantity"]').value);
  if (qty < 1 || qty > 10) return false;
  return true; // bypass with curl; server must re-validate
}

document.getElementById("checkout").addEventListener("submit", (e) => {
  if (!validateCheckout()) e.preventDefault();
  // hidden price/role fields sent without server-side recomputation
});
```

### HTML

```html
<form action="/checkout" method="post">
  <input type="number" name="quantity" min="1" max="10" required>
  <input type="hidden" name="price" value="9.99">
  <input type="hidden" name="role" value="user">
  <!-- min/max/required are browser hints only; not enforced on server -->
</form>
```

## Fix: Safer Patterns and Libraries to Use

### Python

Validate at the API boundary with Pydantic. Recompute trusted fields server-side.

```python
from pydantic import BaseModel, Field, EmailStr, ConfigDict

class CheckoutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    quantity: int = Field(ge=1, le=10)
    sku: str = Field(max_length=64)

@app.route("/checkout", methods=["POST"])
def checkout():
    req = CheckoutRequest.model_validate(request.get_json())
    unit_price = catalog.price_for(req.sku)  # server-computed, not from client
    total = req.quantity * unit_price
    order = Order(user_id=session["user_id"], total=total, sku=req.sku)
    db.session.add(order)
    db.session.commit()
    return jsonify({"total": total})
```

**Important:** Client-side validation is UX only. Every security-relevant rule must exist on the server.

```python
# Marshmallow alternative:
from marshmallow import Schema, fields, validate

class CheckoutSchema(Schema):
    quantity = fields.Int(required=True, validate=validate.Range(min=1, max=10))
    sku = fields.Str(required=True, validate=validate.Length(max=64))
```

### Java

Apply Jakarta Bean Validation on request DTOs. Reject invalid input before the service layer.

```java
public record TransferRequest(
    @NotNull @Positive Long fromId,
    @NotBlank @Pattern(regexp = "^[A-Z0-9]{8,34}$") String toAccount,
    @NotNull @DecimalMin("0.01") BigDecimal amount
) {}

@PostMapping("/transfer")
public ResponseEntity<?> transfer(@Valid @RequestBody TransferRequest req) {
    accountService.transfer(req.fromId(), req.toAccount(), req.amount());
    return ResponseEntity.ok().build();
}
```

**Important:** Use `@Valid` on every mutating controller parameter. Recompute price, role, and owner from server context.

### C#

Use DataAnnotations or FluentValidation. Check ModelState on every mutating action.

```csharp
public class ProfileDto
{
    [Required, Phone]
    public string Phone { get; set; } = "";

    [Required, StringLength(64, MinimumLength = 1)]
    public string DisplayName { get; set; } = "";
}

[HttpPost("update-profile")]
public IActionResult UpdateProfile([FromBody] ProfileDto dto)
{
    if (!ModelState.IsValid)
        return BadRequest(ModelState);
    _service.UpdateProfile(UserId, dto);
    return Ok();
}
```

**Important:** Never trust disabled UI fields. Authorization-sensitive properties come from server claims, not the request body.

### Go

Validate struct tags after JSON decode. Reject unknown fields.

```go
import "github.com/go-playground/validator/v10"

type CreateOrderRequest struct {
    Quantity int    `json:"quantity" validate:"required,min=1,max=10"`
    Sku      string `json:"sku" validate:"required,max=64"`
}

var validate = validator.New()

func createOrder(w http.ResponseWriter, r *http.Request) {
    var req CreateOrderRequest
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
    price := catalog.Price(req.Sku)
    db.Exec("INSERT INTO orders (qty, price) VALUES ($1,$2)", req.Quantity, price)
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
