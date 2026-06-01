---
title: Review Username Enumeration
keywords:
  - security code review
  - username enumeration
  - account enumeration
  - information disclosure
  - authentication
description: How to read code for username enumeration where different responses reveal whether an account exists.
---

## 4.23 - Review Username Enumeration

Username enumeration leaks whether an account exists through different error messages, response times, or status codes. Review login, registration, password reset, and invite flows. Compare responses for valid and invalid identifiers and confirm the application reveals no more than policy allows.

## What This Vulnerability Is

Username enumeration is an information disclosure issue in authentication and account recovery. The application behaves differently when a username or email is registered versus when it is not. Attackers compile lists of valid accounts for credential stuffing, phishing, or targeted attacks.

The unsafe assumption is that friendly error text helps only legitimate users. Distinct messages such as "User does not exist" versus "Reset link sent" teach attackers which identifiers are valid. Timing differences, HTTP status codes, and whether an email is actually sent can also leak existence. This maps to [CWE-204](https://cwe.mitre.org/data/definitions/204.html) (Observable Response Discrepancy).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login, password reset, registration, invite acceptance, MFA enrollment, OAuth account linking |
| **Input entry** | Email or username fields on public-facing auth endpoints |
| **Branching logic** | `if user is None`, `if token != null`, different HTTP status or JSON error codes |
| **Side channels** | Response time when DB lookup is skipped, email send only when account exists |
| **Weak controls** | 404 for unknown email, explicit "already registered", distinct login failure messages |
| **API leaks** | JSON fields like `exists: true`, different error codes per case |

## Attack Payloads

Use these in authorized tests on login, registration, and password reset. Compare body, status code, headers, and timing for known-valid versus unknown identifiers.

### Pattern 1: Distinct error messages (login abuse scenario)

```http
POST /login
{"user":"known@victim.com","password":"wrong"}
→ {"error":"Invalid password"}

POST /login
{"user":"unknown@attacker.com","password":"wrong"}
→ {"error":"User does not exist"}
```

### Pattern 2: HTTP status discrepancy

```http
POST /reset {"email":"registered@victim.com"} → 200 OK
POST /reset {"email":"notregistered@x.com"}    → 404 Not Found
```

### Pattern 3: Registration and invite flows

```http
POST /register {"email":"taken@victim.com"}
→ {"error":"Email already registered"}

POST /register {"email":"new@attacker.com"}
→ {"ok":true}
```

### Pattern 4: JSON existence flags

```json
{"exists": true, "message": "Check your email"}
{"exists": false, "message": "No account found"}
```

### Pattern 5: Timing side channel

Repeated requests for unknown emails may return faster when the server skips mail queue or DB work. Measure response time distributions across many samples.

### Pattern 6: Password reset email behavior

Observe whether an outbound email is sent only when the account exists, or whether UI text differs ("We sent a link" vs "Unknown user").

## Language-Specific Sinks and Dangerous APIs

Search for branches that return different content when a user record is missing versus present.

### Python

```python
if not user:
    return jsonify({"error": "No account with that email"}), 404
return jsonify({"error": "Invalid password"})  # reveals valid user
```

Django `authenticate` followed by distinct messages; Flask `flash()` with different strings.

### Java

```java
if (user == null) {
    resp.sendError(404, "User not found");
} else {
    resp.sendError(401, "Bad password");
}
return Map.of("registered", user != null);
```

Spring Security custom `AuthenticationFailureHandler` with per-case messages.

### C#

```csharp
if (user == null)
    return NotFound("Email not registered");
return Unauthorized("Wrong password");
```

ASP.NET Identity error descriptions exposed to the client.

### JavaScript

```javascript
if (!user) return res.status(404).json({ error: "Unknown email" });
return res.status(401).json({ error: "Wrong password" });
```

### Go

```go
if user == nil {
    http.Error(w, "no such user", http.StatusNotFound)
    return
}
```

### HTML and template leaks

```html
<!-- Reset form only rendered when user exists -->
{% if user_found %}<p>Email sent</p>{% else %}<p>Unknown account</p>{% endif %}
```

## Sample Vulnerable Code in Python

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.post("/reset")
def reset():
    email = request.form["email"]
    user = User.query.filter_by(email=email).first()
    if not user:
        # Different message and status reveal that the email is not registered
        return jsonify({"error": "No account with that email"}), 404
    send_reset(user)
    return jsonify({"ok": True})
```

## Step-by-Step Review Walkthrough

1. **Map login failure paths.** Compare message text, status codes, and lockout behavior for unknown username versus wrong password.
2. **Trace the Python reset handler.** In the sample, a 404 with a specific error tells attackers the email is absent. Uniform messaging is required on public endpoints.
3. **Review registration and invite flows.** Search for "email already registered" versus generic success responses.
4. **Check MFA enrollment and device binding.** Hints when a user record is missing can leak account existence.
5. **Measure side channels.** Email or SMS sent only when the account exists still leaks through timing if the code path differs.
6. **Review API JSON shapes.** Different field sets or error codes between found and not-found cases enable enumeration.
7. **Confirm audit logs stay server-side.** Enumeration-friendly details must not appear in client-visible channels.

## Risk Impact Analysis

**Targeted credential stuffing.** Valid account lists reduce attacker effort. They focus password sprays on emails known to exist.

**Phishing and social engineering.** Attackers craft messages to confirmed users, improving click rates and perceived legitimacy.

**Privacy harm.** Revealing whether someone registered may disclose membership in a sensitive service.

**Compliance exposure.** Uniform responses are often required for authentication and privacy controls in regulated environments.

## Vulnerable Examples in Other Languages

### Java

```java
@PostMapping("/reset")
public String reset(@RequestParam String username, Model model) {
    Optional<User> user = userRepository.findByUsername(username);
    if (user.isEmpty()) {
        model.addAttribute("message", "User does not exist");
        return "reset";
    }
    mailService.sendReset(user.get());
    model.addAttribute("message", "The password reset link has been sent to you.");
    return "reset";
}

@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
    if (userRepository.existsByEmail(req.getEmail())) {
        return ResponseEntity.status(409).body(Map.of("error", "Email already registered"));
    }
    userRepository.save(new User(req.getEmail(), req.getPassword()));
    return ResponseEntity.ok(Map.of("message", "Account created"));
}
```

### C#

```csharp
[HttpPost("forgot-password")]
public async Task<IActionResult> ForgotPassword([FromForm] string email)
{
    var user = await _users.FindByEmailAsync(email);
    if (user == null)
        return BadRequest("Unknown email address.");
    await _email.SendResetAsync(user);
    return Ok("Check your email.");
}

[HttpPost("login")]
public IActionResult Login([FromBody] LoginDto dto)
{
    var user = _users.FindByName(dto.Username);
    if (user == null)
        return Unauthorized(new { error = "user_not_found" });
    if (!_hasher.Verify(dto.Password, user.PasswordHash))
        return Unauthorized(new { error = "bad_password" });
    return Ok(SignIn(user));
}
```

### Go

```go
func forgot(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    u, err := store.UserByEmail(email)
    if err == sql.ErrNoRows {
        http.Error(w, "user not found", http.StatusNotFound)
        return
    }
    mailer.SendReset(u)
    w.Write([]byte("email sent"))
}

func register(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    if store.EmailExists(email) {
        http.Error(w, "email already registered", http.StatusConflict)
        return
    }
    store.CreateUser(email, r.FormValue("password"))
    w.WriteHeader(http.StatusCreated)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Return the same message and status regardless of lookup result. Send email only server-side when the user exists.

```python
from flask import Flask, request, render_template

app = Flask(__name__)
GENERIC_RESET_MSG = "If an account exists for that email, we sent reset instructions."

@app.post("/reset")
def reset():
    email = request.form["email"]
    user = User.query.filter_by(email=email).first()
    if user:
        send_reset(user)
    # Always the same response — no branch on user is None
    return render_template("reset_sent.html", message=GENERIC_RESET_MSG), 200
```

```python
import time
import bcrypt

DUMMY_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt())

def verify_login(username, password):
    user = User.query.filter_by(username=username).first()
    if user:
        return bcrypt.checkpw(password.encode(), user.password_hash.encode())
    # Align timing when user is missing
    bcrypt.checkpw(password.encode(), DUMMY_HASH)
    return False
```

**Important:** Rate-limit reset and login endpoints per IP and identifier to slow enumeration even with uniform responses.

### Java

Use consistent messaging. Perform similar work when the user is absent to reduce timing gaps.

```java
private static final String RESET_MESSAGE =
    "If an account exists, we sent password reset instructions.";

public void handleReset(HttpServletRequest req, HttpServletResponse resp) {
    String username = req.getParameter("username");
    Optional<User> user = userRepository.findByUsername(username);
    user.ifPresent(u -> {
        String token = tokenService.createResetToken(u);
        mailService.sendReset(u.getEmail(), token);
    });
    req.setAttribute("message", RESET_MESSAGE);
    doForward(req, resp);
}
```

### C#

Return identical response body and status for found and not-found email on reset.

```csharp
private const string ResetMessage =
    "If an account exists for that email, we sent reset instructions.";

[HttpPost("forgot-password")]
public IActionResult ForgotPassword([FromForm] string email)
{
    var user = await _users.FindByEmailAsync(email);
    if (user != null)
        await _email.SendResetAsync(user);
    return Ok(ResetMessage);
}
```

### Go

Use one success response for forgot-password regardless of `ErrNoRows`.

```go
const resetMsg = "If an account exists for that email, we sent reset instructions."

func forgot(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    u, err := store.UserByEmail(email)
    if err == nil {
        mailer.SendReset(u)
    }
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(resetMsg))
}
```

## Verify During Review

- Login, reset, and registration responses do not differ in wording, status, or structure based on account existence.
- Email and SMS are triggered only server-side; clients cannot infer delivery from response alone.
- Timing and workload are similar enough that trivial timing attacks are not trivially enabled.
- Rate limits and monitoring protect public authentication endpoints.
- Intentional enumeration (admin consoles) is role-gated and documented.
- API documentation matches uniform external behavior.

## Reference

- [CWE-204: Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html)
- [OWASP — Testing for Account Enumeration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Django — Password reset views](https://docs.djangoproject.com/en/stable/topics/auth/default/#django.contrib.auth.views.PasswordResetView)
- [ASP.NET Core Identity — UserManager](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.identity.usermanager-1)
- [Spring Security — Authentication failure handling](https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html)
- [bcrypt — Python documentation](https://pypi.org/project/bcrypt/)
