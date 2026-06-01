---
title: Review Broken Password Lifecycle
keywords:
  - security code review
  - password lifecycle
  - password reset
  - mfa
  - credential management
description: How to read code for broken password lifecycle flaws—review setup, change, reset, and MFA flows for proper authentication and token handling.
---

## 4.18 - Review Broken Password Lifecycle

The password lifecycle spans account creation, login, change, reset, and MFA enrollment. Weaknesses in any stage can compromise accounts without exploiting injection flaws. Review each flow for proper authentication before changes, secure token handling on reset, strong hashing at setup, and MFA enforcement on sensitive actions.

## What This Vulnerability Is

Broken password lifecycle management lets attackers set, change, or reset credentials without proving identity. Risks include plain-text storage, weak hashing, missing current-password checks, reusable reset tokens, and MFA bypass on high-impact operations. Initial passwords left unchanged and debug logging of credentials amplify exposure.

The unsafe assumption is that knowing an email address or user ID is enough proof to alter credentials. Impact includes account takeover and persistent access after password changes. This aligns with [CWE-620](https://cwe.mitre.org/data/definitions/620.html) (Unverified Password Change) and [CWE-640](https://cwe.mitre.org/data/definitions/640.html) (Weak Password Recovery Mechanism).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Registration, admin provisioning, password change, reset confirm, MFA disable |
| **Storage flaws** | Plain text, MD5/SHA1, reversible encryption, passwords in audit tables |
| **Change without auth** | `user_id` from form body updates another account's password |
| **Reset token flaws** | Predictable tokens, long TTL, missing single-use invalidation, tokens in URL logs |
| **Enumeration** | Different responses for valid vs invalid email on reset |
| **MFA bypass** | Disable MFA without step-up; debug logging of passwords or reset links |

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

## Sample Vulnerable Code in Python

```python
import hashlib
from flask import Flask, request, session

app = Flask(__name__)

@app.route("/reset", methods=["POST"])
def reset_password():
    email = request.form["email"]
    user = db.users.find_one({"email": email})
    if not user:
        return "unknown email", 404  # enumerates valid accounts
    token = hashlib.md5(email.encode()).hexdigest()  # predictable
    send_mail(email, f"https://app/reset?token={token}")
    return "sent", 200

@app.route("/mfa/disable", methods=["POST"])
def disable_mfa():
    session["mfa_enabled"] = False  # no reauthentication
    return "ok"
```

## Step-by-Step Review Walkthrough

1. **Initial setup.** Trace registration and admin provisioning; confirm passwords are hashed with salt and never logged.
2. **Password change.** Require current password or reauthentication; bind changes to the authenticated session user, not a request parameter ID.
3. **Password reset.** Review token generation, entropy, storage, expiration, single-use invalidation, and delivery channel.
4. **Identity verification.** Reset must not rely solely on guessable security questions or user enumeration differences.
5. **MFA.** Locate enrollment, verification, backup codes, and whether MFA is required for change, reset, or disable flows.
6. **Policy enforcement.** Length, complexity, breach password lists, and reuse of recent passwords.
7. **Monitoring.** Audit logs for reset and MFA events without logging secrets or tokens in cleartext.

## Risk Impact Analysis

**Account takeover.** Weak reset tokens or unauthenticated password change let attackers lock out legitimate users.

**Credential exposure.** Plain-text or weakly hashed passwords fall quickly to offline cracking after database leaks.

**MFA circumvention.** Disable flows without step-up authentication remove the strongest account protection.

**User enumeration.** Reset responses that differ for valid emails aid targeted phishing and credential stuffing.

**Compliance impact.** Password handling failures appear in PCI, SOC 2, and identity management assessments.

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

## Verify During Review

- Passwords are hashed with modern algorithms and unique salts; plain text never stored or logged.
- Password change requires current credential or fresh reauthentication tied to the active session.
- Reset tokens are random, hashed at rest, time-limited, single-use, and not derived from email alone.
- Reset and registration responses do not enumerate valid accounts to anonymous callers.
- MFA is required for enrollment removal, email change, and other high-risk account operations.
- Initial and temporary passwords force change on first login when policy requires it.
- Audit trails record lifecycle events without cleartext passwords or reset secrets.

## Reference

- [CWE-620: Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)
- [CWE-640: Weak Password Recovery Mechanism](https://cwe.mitre.org/data/definitions/640.html)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [passlib documentation](https://passlib.readthedocs.io/en/stable/)
- [Spring Security — Password Storage](https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html)
- [ASP.NET Core Identity](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity)
- [Go golang.org/x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt)
