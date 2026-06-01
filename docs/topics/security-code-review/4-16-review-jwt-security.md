---
title: Review JWT Security
keywords:
  - security code review
  - jwt
  - json web token
  - signature verification
  - algorithm confusion
description: How to read code for JWT security flaws—verify signature, algorithm, issuer, audience, and expiration before claims drive authorization.
---

## 4.16 - Review JWT Security

JSON Web Token (JWT) issues often appear in API gateways, microservices, and mobile backends. Review where tokens are parsed, which algorithms are accepted, and how signing keys are loaded. Confirm every trust decision verifies signature, issuer, audience, and expiration before claims drive authorization.

## What This Vulnerability Is

A JWT carries claims the application may treat as identity and permissions. If signature verification is skipped, uses a hardcoded secret, or accepts the `none` algorithm, attackers can forge tokens and impersonate users or elevate privileges. Key confusion attacks swap asymmetric verification for symmetric keys when libraries are misconfigured.

The unsafe assumption is that base64-encoded payloads are trustworthy because they look opaque. Impact includes authentication bypass and broken access control. This area relates to [CWE-347](https://cwe.mitre.org/data/definitions/347.html) (Improper Verification of Cryptographic Signature) and [CWE-287](https://cwe.mitre.org/data/definitions/287.html) (Improper Authentication).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | API auth middleware, microservice trust, mobile backends, OAuth resource servers |
| **Parse without verify** | `jwt.decode` with `verify_signature=False`, manual base64 JSON parsing for auth |
| **Key material** | Hardcoded `"secretkey"`, dev keys shipped to prod, missing JWKS rotation |
| **Algorithm issues** | `none` accepted, HS256/RS256 confusion, ignoring `alg` header |
| **Claim validation** | Missing `exp`, `iss`, `aud`, or excessive access token lifetime |
| **Storage and logout** | localStorage tokens, refresh tokens without revocation, debug endpoints disabling verify |

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

### Pattern 5: Claim tampering with verification disabled

```python
jwt.decode(token, options={"verify_signature": False})
# Change "role":"user" → "role":"admin" in payload, resubmit
```

## Language-Specific Sinks and Dangerous APIs

Find every path that decodes JWTs for authentication or authorization decisions.

### Python

```python
import jwt
jwt.decode(token, options={"verify_signature": False})
jwt.decode(token, "changeme", algorithms=["HS256", "none"])
```

PyJWT, `python-jose`, manual `base64` + `json.loads` on middle segment.

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

## Sample Vulnerable Code in Python

```python
import jwt

SECRET = "changeme"

def current_user(auth_header):
    token = auth_header.split(" ", 1)[1]
    # Signature verification disabled — attacker forges any payload
    return jwt.decode(token, options={"verify_signature": False})

def issue_token(user):
    return jwt.encode({"sub": user.id, "admin": True}, SECRET, algorithm="HS256")
```

## Step-by-Step Review Walkthrough

1. **Find JWT parse and validate calls.** Search filters, middleware, and service-to-service clients for token handling.
2. **Trace signing key resolution.** Static strings, JWKS endpoints, rotation, and per-tenant keys each need review.
3. **Check allowed algorithms.** Reject `none`; enforce expected `alg` (for example RS256 vs HS256).
4. **Validate standard claims.** Confirm `exp`, `nbf`, `iss`, `aud`, and clock skew handling.
5. **Review authorization claims.** Roles, scopes, `sub`, and custom flags must come from verified tokens only.
6. **Inspect token storage.** localStorage vs HttpOnly cookies, refresh token handling, and logout invalidation.
7. **Confirm production builds.** Debug endpoints and test harnesses must not disable verification in deployed code.

## Risk Impact Analysis

**Authentication bypass.** Forged tokens let attackers impersonate any user or service account without valid credentials.

**Privilege escalation.** Unverified `admin` or `role` claims in the payload grant elevated access when handlers trust decoded JSON.

**Persistent unauthorized access.** Long-lived access tokens without rotation or revocation extend compromise windows.

**Cross-service trust breakdown.** Weak JWT validation in one microservice may cascade into broader internal network access.

**Compliance and audit failure.** Regulated environments require demonstrable token validation aligned with identity provider standards.

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
function currentUser() {
  const token = localStorage.getItem('access_token');
  const payload = JSON.parse(atob(token.split('.')[1]));
  return { id: payload.sub, isAdmin: payload.admin === true };
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

## Verify During Review

- Every authentication path verifies JWT signature with the correct key and algorithm.
- `none` and unexpected algorithms are rejected; asymmetric and symmetric paths are not confused.
- `exp`, `iss`, and `aud` (and `nbf` when used) are validated with acceptable clock skew.
- Signing keys are not hardcoded in production; rotation and JWKS are supported where applicable.
- Authorization uses claims from verified tokens only, not duplicate client-controlled headers.
- Access token lifetime matches risk; refresh and logout invalidate continued use when required.

## Reference

- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [RFC 7519: JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PyJWT documentation](https://pyjwt.readthedocs.io/en/stable/)
- [Auth0 — JWT algorithm confusion](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [jjwt library](https://github.com/jwtk/jjwt)
- [ASP.NET Core — JWT Bearer authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/jwt-authn)
- [golang-jwt/jwt v5](https://pkg.go.dev/github.com/golang-jwt/jwt/v5)
