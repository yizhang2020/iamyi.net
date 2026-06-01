---
title: Review API Keys and Request Signing
keywords:
  - security code review
  - API keys
  - HMAC
  - request signing
  - key rotation
  - API authorization
description: How to review API key and HMAC request-signing implementations—scope, storage, rotation, replay resistance, and constant-time verification.
---

## 10.7 - Review API Keys and Request Signing

API keys and HMAC request signing authenticate programmatic callers when OAuth or mTLS is not used. Review how keys are issued, scoped, stored, transmitted, rotated, and verified. Treat the signing secret like a password: protect it at rest, never log it, and bind each key to least-privilege scope and lifetime.

## What This Vulnerability Is

Weak API key design exposes long-lived secrets in URLs, source code, or logs. HMAC verification fails when services skip signature checks, use predictable secrets, compare digests incorrectly, or omit timestamp and nonce checks that prevent replay.

The unsafe assumption is that possession of a static key implies ongoing authorization for every operation. Attackers who extract keys from repositories, browser history, or log aggregators can call APIs until rotation. This maps to [CWE-798](https://cwe.mitre.org/data/definitions/798.html) (Use of Hard-coded Credentials), [CWE-321](https://cwe.mitre.org/data/definitions/321.html) (Use of Hard-coded Cryptographic Key), and [OWASP API Security Top 10](https://owasp.org/API-Security/) broken authentication categories.

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Public REST/GraphQL APIs, webhooks, partner integrations, mobile app backends, CLI tools |
| **Key issuance** | Admin consoles, self-service signup, long-lived “master” keys, keys embedded in mobile binaries |
| **Transport** | `?api_key=` query params, keys in `Referer` via HTTP pages, missing TLS on key-bearing requests |
| **Verification** | Single shared secret for all tenants, optional auth middleware, timing-unsafe string compare |
| **HMAC schemes** | Custom headers without canonical string, missing clock skew, no nonce store, MD5/SHA1 HMAC for new designs |
| **Scope and lifecycle** | One key for read and admin, no per-environment separation, no revocation or rotation path |

## Abuse Scenarios

Use these when reviewing programmatic API authentication and webhook verification.

### Scenario 1: API key in URL leaked via logs and Referer

Clients send `?api_key=sk_live_...`. Access logs, CDN logs, browser history, and `Referer` headers when users follow links expose the key. Attacker replays key until rotation—often never.

### Scenario 2: Shared global secret across tenants

All partners use the same HMAC secret or API key. One partner breach yields access to every tenant's data on the API.

### Scenario 3: Webhook without HMAC verification

The webhook endpoint accepts POST bodies when a static header matches a guessable value, or skips verification entirely. Attacker injects fraudulent payment or user-provisioning events.

### Scenario 4: HMAC replay (no timestamp/nonce)

Valid signed requests can be replayed within the acceptance window because timestamp skew is unbounded or nonce is not tracked. Attacker captures one legitimate webhook and replays it.

### Scenario 5: Timing-unsafe signature compare

Server compares hex digest with `==` or `String.equals`. Remote timing analysis may leak correct MAC bytes byte-by-byte under favorable conditions.

### Scenario 6: Hardcoded key in mobile or frontend bundle

API key or signing secret is embedded in a mobile app IPA/APK or JavaScript bundle. Extraction tools recover it in minutes.

## Language-Specific Libraries and Dangerous Patterns

### Python

```python
# Dangerous
api_key = request.args.get("api_key")
if api_key == "sk_live_abc123": ...
sig == expected  # not constant-time
hashlib.sha256(body + secret.encode()).hexdigest()  # not HMAC

# Safer
import hmac, hashlib
hmac.compare_digest(
    hmac.new(secret, signing_string, hashlib.sha256).hexdigest(),
    provided_sig,
)
record = db.find_key_by_hash(hashlib.sha256(raw_key.encode()).hexdigest())
```

Also review: Flask `before_request` key checks without scope, Stripe/Twilio SDK signature helpers used incorrectly.

See [Python hmac.compare_digest](https://docs.python.org/3/library/hmac.html#hmac.compare_digest).

### Java

```java
// Dangerous
@RequestParam String apiKey
if ("hardcoded-prod-key".equals(apiKey)) ...
sig.equals(expectedHex);

// Safer
MessageDigest.isEqual(expectedMac, providedMac);
Mac mac = Mac.getInstance("HmacSHA256");
mac.init(new SecretKeySpec(secret, "HmacSHA256"));
```

Also review: Spring Security `ApiKeyAuthenticationFilter`, AWS Signature Version 4 validation libraries.

See [Java Mac class](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Mac.html).

### C#

```csharp
// Dangerous
if (sig == expected)
SHA256.HashData(body.Concat(secret).ToArray());

// Safer
CryptographicOperations.FixedTimeEquals(expected, provided);
HMACSHA256.HashData(secret, signingString);
```

Also review: ASP.NET Core API key packages, Azure Functions webhook validation attributes.

See [CryptographicOperations.FixedTimeEquals](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cryptographicoperations.fixedtimeequals).

### JavaScript

```javascript
// Dangerous
if (req.header('x-api-key') !== VALID_KEY)
if (sig === expected)

// Safer
import crypto from 'crypto';
crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(provided));
crypto.createHmac('sha256', secret).update(signingString).digest('hex');
```

Also review: `@aws-sdk/signature-v4`, `stripe.webhooks.constructEvent`, `passport-http-bearer`.

### Go

```go
// Dangerous
key := r.URL.Query().Get("api_key")
if sig == expected

// Safer
hmac.Equal(expected, provided)
subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) // same-length only
```

See [Go crypto/hmac](https://pkg.go.dev/crypto/hmac) and [RFC 2104 HMAC](https://www.rfc-editor.org/rfc/rfc2104).

## Sample Vulnerable Code in Python

```python
import hashlib
import hmac
from flask import Flask, request

app = Flask(__name__)
API_SECRET = "static-partner-secret"  # hardcoded; shared by all partners

@app.route("/v1/orders")
def list_orders():
    api_key = request.args.get("api_key")  # key in URL — leaks via logs and Referer
    if api_key != "sk_live_abc123":
        return {"error": "unauthorized"}, 401
    return {"orders": db.all_orders()}  # no scope — full data for any valid key

@app.route("/v1/webhook", methods=["POST"])
def webhook():
    sig = request.headers.get("X-Signature", "")
    body = request.get_data()
    expected = hashlib.sha256(body + API_SECRET.encode()).hexdigest()
    if sig == expected:  # not HMAC; wrong compare pattern for some libs
        apply_webhook(body)
    return "", 204
```

## Step-by-Step Review Walkthrough

1. **Locate authentication entry points.** Search for `api_key`, `X-Api-Key`, `Authorization: Bearer sk_`, HMAC headers, and webhook signature middleware.
2. **Trace key storage and loading.** Keys must not live in source control. Confirm secrets come from vault, KMS, or environment injection with rotation support.
3. **Review transport rules.** Reject query-string keys for browser-accessible endpoints. Require TLS 1.2+ per [10.5](10-05-review-tls-ssl-protocol.md).
4. **Inspect verification logic.** HMAC must use a standard algorithm such as HMAC-SHA256 per [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104). Use constant-time comparison (`hmac.compare_digest` or equivalent).
5. **Check scope and authorization.** Map each key or signing identity to allowed methods, routes, tenants, and IP ranges. Authorization must not stop at “key is valid.”
6. **Evaluate replay controls.** Signed requests should include timestamp and nonce (or short-lived signatures) with enforced skew windows and nonce deduplication where replays matter.
7. **Confirm rotation and revocation.** Look for multi-key acceptance during rollover, admin revoke APIs, audit logs on key use, and separate keys per environment.

## Risk Impact Analysis

**Full API compromise from one leaked key.** Long-lived, unscoped keys grant broad access until manually rotated—often discovered only after abuse.

**Credential exposure via URLs and logs.** Query-string keys appear in access logs, analytics, and browser history, violating least exposure.

**Forged webhooks and partner calls.** Missing or weak HMAC verification lets attackers inject events or exfiltrate data by calling “internal” endpoints.

**Cross-tenant access.** Shared secrets or missing tenant binding in signature payloads enable horizontal privilege escalation between customers.

**Compliance and contractual breach.** Partner agreements and frameworks such as [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) expect managed cryptographic key lifecycles.

## Vulnerable Examples in Other Languages

### Java

```java
@GetMapping("/v1/report")
public Report export(@RequestParam String apiKey) {
    if ("hardcoded-prod-key".equals(apiKey)) {
        return reportService.fullExport(); // no HMAC, no scope, key in query string
    }
    throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
}
```

### C#

```csharp
[HttpPost("hook")]
public IActionResult Hook([FromBody] byte[] body, [FromHeader(Name = "X-Signature")] string sig)
{
    var expected = Convert.ToBase64String(
        SHA256.HashData(body.Concat(Encoding.UTF8.GetBytes("webhook-secret")).ToArray()));
    if (sig == expected) // timing-unsafe compare; not HMAC
        _processor.Apply(body);
    return Ok();
}
```

### JavaScript

```javascript
// Express: API key checked only in header; stored in repo
const VALID_KEY = process.env.API_KEY || "dev-key-12345";

app.get("/v1/users", (req, res) => {
  if (req.header("x-api-key") !== VALID_KEY) return res.sendStatus(401);
  res.json(db.allUsers()); // no per-key scope
});
```

### Go

```go
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        key := r.URL.Query().Get("api_key")
        if key == os.Getenv("GLOBAL_API_KEY") {
            next.ServeHTTP(w, r)
            return
        }
        http.Error(w, "unauthorized", http.StatusUnauthorized)
    })
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Store hashed keys at rest. Accept keys only in headers. Use HMAC-SHA256 over a canonical request string with timestamp; compare digests in constant time.

```python
import hashlib
import hmac
import secrets
import time
from flask import Flask, request, abort

app = Flask(__name__)
MAX_SKEW_SECONDS = 300

def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()

def verify_request(api_key: str) -> dict | None:
    record = db.find_key_by_hash(hash_api_key(api_key))
    if record is None or record.revoked:
        return None
    return record

def verify_hmac(secret: bytes, signing_string: bytes, provided: str) -> bool:
    expected = hmac.new(secret, signing_string, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, provided)

@app.route("/v1/orders")
def list_orders():
    api_key = request.headers.get("X-Api-Key")
    if not api_key:
        abort(401)
    record = verify_request(api_key)
    if record is None or "orders:read" not in record.scopes:
        abort(403)
    return {"orders": db.orders_for_tenant(record.tenant_id)}

@app.route("/v1/webhook", methods=["POST"])
def webhook():
    ts = request.headers.get("X-Timestamp")
    sig = request.headers.get("X-Signature")
    if not ts or not sig or abs(time.time() - int(ts)) > MAX_SKEW_SECONDS:
        abort(401)
    body = request.get_data()
    signing_string = f"{ts}\n".encode() + body
    secret = db.webhook_secret(request.headers.get("X-Partner-Id"))
    if not verify_hmac(secret, signing_string, sig):
        abort(401)
    apply_webhook(body)
    return "", 204

# Issue: raw_key shown once; store hash_api_key(raw_key) only
raw_key = "sk_live_" + secrets.token_urlsafe(32)
```

**Important:** Never log raw keys or HMAC secrets. Rotate by accepting two key hashes during a overlap window, then revoke the old hash.

See [Python hmac — compare_digest](https://docs.python.org/3/library/hmac.html#hmac.compare_digest) and [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104).

### Java

Use a secrets manager for HMAC keys. Prefer framework filters that enforce scope after lookup.

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

public boolean verifyHmacSha256(byte[] secret, byte[] message, byte[] provided) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(secret, "HmacSHA256"));
    byte[] expected = mac.doFinal(message);
    return MessageDigest.isEqual(expected, provided);
}
```

Validate API keys against hashed records in a database; reject keys in query parameters at the edge.

**Important:** Use `MessageDigest.isEqual` or `Mac` output comparison—not `String.equals` on hex digests without constant-time guarantees.

See [Java Mac class](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Mac.html) and [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/).

### C#

Store API key hashes with ASP.NET Core authentication handlers or custom middleware. Use HMACSHA256 for webhooks.

```csharp
using System.Security.Cryptography;

static bool VerifyHmacSha256(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> data, ReadOnlySpan<byte> provided)
{
    Span<byte> expected = stackalloc byte[32];
    HMACSHA256.HashData(secret, data, expected);
    return CryptographicOperations.FixedTimeEquals(expected, provided);
}
```

Configure separate keys per partner and environment in secret configuration—not `appsettings.json` committed to git.

**Important:** Use `CryptographicOperations.FixedTimeEquals` for MAC comparison.

See [CryptographicOperations.FixedTimeEquals](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cryptographicoperations.fixedtimeequals) and [Azure WebJobs SDK — HMAC validation pattern](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-http-webhook).

### Go

Compare HMAC with `hmac.Equal`. Pass keys via headers and hash at rest with a slow password hash if humans never re-enter the raw key.

```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "crypto/subtle"
    "net/http"
)

func validateAPIKey(r *http.Request) (*KeyRecord, bool) {
    key := r.Header.Get("X-Api-Key")
    if key == "" {
        return nil, false
    }
    rec, ok := store.LookupByHash(sha256.Sum256([]byte(key)))
    return rec, ok && !rec.Revoked && rec.HasScope("orders:read")
}

func verifyHMAC(secret, msg, sig []byte) bool {
    mac := hmac.New(sha256.New, secret)
    mac.Write(msg)
    expected := mac.Sum(nil)
    return hmac.Equal(expected, sig)
}
```

**Important:** Restrict keys by source IP or mTLS where partners are fixed—defense in depth, not a substitute for scoped keys.

See [Go crypto/hmac](https://pkg.go.dev/crypto/hmac) and [Go subtle — ConstantTimeCompare](https://pkg.go.dev/crypto/subtle#ConstantTimeCompare).

## Verify During Review

- API keys are **never** in query strings, URLs shared to browsers, or committed source.
- Secrets load from a **managed store**; raw keys are shown once at issuance and stored hashed.
- Each key has explicit **scope**, tenant binding, and **revocation** path.
- HMAC uses **HMAC-SHA256** (or stronger approved MAC) with **constant-time** verification.
- Signed requests include **timestamp** (and nonce where needed) with enforced skew and replay controls.
- **Rotation** supports overlapping valid keys; audit logs record key id, not secret material.
- Successful authentication still passes through **authorization** checks for the requested resource.

## Reference

- [RFC 2104: HMAC — Keyed-Hashing for Message Authentication](https://www.rfc-editor.org/rfc/rfc2104)
- [RFC 7518: JSON Web Algorithms (JWA) — HMAC SHA algorithms](https://www.rfc-editor.org/rfc/rfc7518)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST SP 800-57 Part 1 Rev. 5: Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [Python hmac module](https://docs.python.org/3/library/hmac.html)
- [Java javax.crypto.Mac](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Mac.html)
- [Microsoft CryptographicOperations.FixedTimeEquals](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cryptographicoperations.fixedtimeequals)
- [Go crypto/hmac](https://pkg.go.dev/crypto/hmac)
