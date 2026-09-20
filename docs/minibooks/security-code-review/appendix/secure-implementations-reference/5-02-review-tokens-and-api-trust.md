---
title: "5.2 Reference — Review Tokens and API Trust"
description: >
  Libraries, multi-language examples, and fixes for Review Tokens and API Trust.
---

# 5.2 Reference — Review Tokens and API Trust

This appendix supports the guiding chapter **[5.2 - Review Tokens and API Trust](../../5-02-review-tokens-and-api-trust.md)**. Each section below preserves the dense material from a former topic chapter.

**Back to chapter:** [5.2 - Review Tokens and API Trust](../../5-02-review-tokens-and-api-trust.md)

## JWT implementation {: #jwt }

From former `10-03-review-jwt-implementation.md`. **Guiding chapter section:** [5.2 - Review Tokens and API Trust § JWT implementation](../../5-02-review-tokens-and-api-trust.md#jwt).

## 5.3 - Review JWT Implementation

JWT implementation review covers how your service **issues** and **validates** tokens, not only whether parsing skips signature checks. Start at the authorization server: signing keys, algorithms, claim design, and refresh handling. Then trace every resource server that consumes those tokens. For parse-time flaws and algorithm confusion, also read [4.5 § JWT security (code-level)](4-05-review-authentication-session-and-access.md#jwt).

## What This Topic Is

This chapter is about **implementation review**, not generic vulnerability hunting. A secure JWT stack requires correct cryptography, key lifecycle, claim policy, and refresh rotation—not merely calling `jwt.decode` with a secret string.

The unsafe assumption is that HS256 with a long-lived shared secret scales across many services, or that access tokens can live for days without refresh controls. Weak issuance undermines every downstream validator.

This maps to [CWE-347](https://cwe.mitre.org/data/definitions/347.html) and [CWE-613](https://cwe.mitre.org/data/definitions/613.html) (Insufficient Session Expiration) when refresh rotation and revocation are missing.

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Custom auth server, API gateway token mint, microservice mesh, mobile backend |
| **Signing model** | HS256 shared secret copied to every service; private keys in repo; no `kid` in header |
| **JWKS endpoint** | Missing `/.well-known/jwks.json`, stale keys served after rotation, HTTP not HTTPS |
| **Access token policy** | Lifetime over 15 minutes without justification; sensitive claims in access token |
| **Refresh tokens** | Reusable refresh tokens, no rotation, no reuse detection, refresh stored in localStorage |
| **Validation gaps** | Resource servers fetch JWKS once at startup; no `iss`/`aud` enforcement per API |
| **Revocation** | Logout clears client cookie only; no server-side refresh denylist or token version claim |

## Abuse Scenarios

Use these when reviewing custom authorization servers and resource APIs that mint or consume JWTs.

### Scenario 1: HS256 secret exfiltration → universal forgery

One shared symmetric secret is copied into twenty microservices and a mobile app. An attacker extracts it from any artifact and mints tokens with arbitrary `sub`, `scope`, and `admin` claims.

### Scenario 2: Refresh token replay (no rotation)

Refresh tokens are valid until expiry and reusable without bound. XSS steals the refresh token; attacker obtains new access tokens for months without re-authentication.

### Scenario 3: Refresh reuse undetected

The server issues a new refresh token on refresh but does not invalidate the previous one. Stolen old refresh tokens continue to work alongside new ones.

### Scenario 4: JWKS never refreshed

Resource servers cache JWKS at startup. After key compromise, auth server rotates keys but stale validators accept old `kid` or fail open to HS256 fallback with a dev secret.

### Scenario 5: Missing audience on resource server

API accepts any token signed by the org issuer regardless of `aud`. Token minted for public web client is replayed to internal admin API.

### Scenario 6: Long-lived access token with embedded roles

Access token lifetime is 30 days with `roles: ["admin"]` inside. Admin lockout or role change has no effect until token expiry.

## Language-Specific Libraries and Dangerous Patterns

### Python

```python
# Dangerous issuance
jwt.encode({"sub": uid, "admin": True, "exp": now + timedelta(days=7)}, SECRET, algorithm="HS256")
jwt.decode(token, SECRET, algorithms=["HS256", "none"])  # resource server

# Safer: PyJWT RS256 + JWKS endpoint for resource servers
import jwt as pyjwt
from jwt import PyJWKClient

jwks_client = PyJWKClient("https://auth.example.com/.well-known/jwks.json")
signing_key = jwks_client.get_signing_key_from_jwt(raw_token)
pyjwt.decode(
    raw_token, signing_key.key, algorithms=["RS256"],
    audience="api.example.com", issuer="https://auth.example.com",
)
```

Also review: `python-jose` `jwt.decode` defaults, `flask-jwt-extended` configuration.

### Java

```java
// Dangerous: jjwt HS256 secret in source; 30-day exp
Jwts.builder().setExpiration(thirtyDays).signWith(SignatureAlgorithm.HS256, SECRET);

// Safer: jjwt RS256 + NimbusJwtDecoder with JWK Set URI
Jwts.parserBuilder().setSigningKeyResolver(jwkResolver).requireIssuer("https://auth.example.com").build();
NimbusJwtDecoder.withJwkSetUri("https://auth.example.com/.well-known/jwks.json").build();
```

Also review: [jjwt](https://github.com/jwtk/jjwt), Spring Authorization Server, Keycloak adapter configs.

### C#

```csharp
// Dangerous
new JwtSecurityToken(..., expires: DateTime.UtcNow.AddDays(30), signingCredentials: hmacCreds);

// Safer: AddJwtBearer with Authority + Audience; RSA signing at auth server
services.AddAuthentication().AddJwtBearer(o => {
    o.Authority = "https://auth.example.com";
    o.Audience = "api.example.com";
    o.TokenValidationParameters.ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 };
});
```

Also review: `IdentityModel`, Azure AD token validation, `Microsoft.AspNetCore.Authentication.JwtBearer`.

### JavaScript

```javascript
// Dangerous
jwt.sign({ sub: user.id, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '30d' });
jwt.verify(token, secret);  // no aud/iss

// Safer: jose library with JWKS
import * as jose from 'jose';
const JWKS = jose.createRemoteJWKSet(new URL('https://auth.example.com/.well-known/jwks.json'));
const { payload } = await jose.jwtVerify(token, JWKS, { issuer: 'https://auth.example.com', audience: 'api.example.com' });
```

### Go

```go
// Dangerous
jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(os.Getenv("JWT_SECRET")))

// Safer: golang-jwt + lestrrat-go/jwx JWKS
token, err := jwt.Parse(raw, jwt.WithKeySet(jwkSet), jwt.WithAudience("api.example.com"), jwt.WithIssuer("https://auth.example.com"))
```

See [PyJWT](https://pyjwt.readthedocs.io/), [jjwt](https://github.com/jwtk/jjwt), [RFC 8725 JWT BCP](https://www.rfc-editor.org/rfc/rfc8725), and [lestrrat-go/jwx](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2).

## Sample Vulnerable Code in Python

```python
import jwt
from datetime import datetime, timedelta

SECRET = "shared-across-twenty-microservices"

def issue_tokens(user_id: str, scopes: list[str]) -> dict:
    now = datetime.utcnow()
    access = jwt.encode(
        {
            "sub": user_id,
            "scope": " ".join(scopes),
            "admin": True,  # privilege claim without audience binding
            "exp": now + timedelta(days=7),
        },
        SECRET,
        algorithm="HS256",
    )
    refresh = jwt.encode(
        {"sub": user_id, "typ": "refresh", "exp": now + timedelta(days=90)},
        SECRET,
        algorithm="HS256",
    )
    return {"access_token": access, "refresh_token": refresh}

def refresh_access_token(refresh_token: str) -> str:
    claims = jwt.decode(refresh_token, SECRET, algorithms=["HS256"])
    # Same refresh token works forever; no rotation or reuse detection
    return issue_tokens(claims["sub"], ["api"])["access_token"]
```

## Step-by-Step Review Walkthrough

1. **Map issuer and consumers.** Identify which component signs tokens and every service that validates them. HS256 requires secret distribution; RS256/ES256 should use public keys via JWKS.
2. **Review signing key storage.** Private keys belong in HSM, KMS, or sealed secrets—not git. Confirm `kid` is present and rotates with the key material.
3. **Inspect access token claims.** Keep lifetimes short. Put authorization data in scope or custom claims bound to `aud`. Avoid embedding long-lived privileges without refresh checks.
4. **Trace JWKS publication.** Authorization servers expose current and rollover public keys. Consumers cache JWKS with TTL and refresh on unknown `kid`.
5. **Review refresh flow.** Each refresh should mint a new refresh token, invalidate the previous one, and detect reuse (revoke token family on replay).
6. **Check resource server validation.** Each API validates `iss`, `aud`, signature, and `exp` with the correct key—not a copy-pasted dev secret.
7. **Confirm logout and compromise response.** Document how operators revoke sessions: refresh denylist, `jti` blocklist, or session version claim bumped on password change.

## Risk Impact Analysis

**Wide-scale forgery.** A leaked HS256 secret or stolen private key lets attackers mint valid tokens for any subject and scope.

**Stale key trust.** Services that never refresh JWKS continue trusting compromised keys after rotation delays exposure but do not stop active abuse if rotation is skipped.

**Refresh token replay.** Non-rotating refresh tokens act like long-lived passwords; XSS or device theft yields persistent access.

**Privilege sprawl.** Overlong access tokens with embedded roles delay revocation until expiry even after admin lockout.

**Cross-service audience confusion.** Tokens minted for one API accepted by another when `aud` is not enforced per resource server.

## Vulnerable Examples in Other Languages

### Java

```java
@Service
public class TokenService {
    private static final String SECRET = "prod-secret-in-source";

    public String mintAccessToken(User user) {
        return Jwts.builder()
            .setSubject(user.getId())
            .claim("roles", user.getRoles())
            .setExpiration(Date.from(Instant.now().plus(30, ChronoUnit.DAYS)))
            .signWith(SignatureAlgorithm.HS256, SECRET)
            .compact();
    }

    public String refresh(String refreshToken) {
        Claims claims = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(refreshToken).getBody();
        return mintAccessToken(userRepo.findById(claims.getSubject()));
        // refresh token not rotated; reuse undetected
    }
}
```

### C#

```csharp
public string IssueAccessToken(string userId)
{
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: "auth.example.com",
        claims: new[] { new Claim("sub", userId), new Claim("role", "admin") },
        expires: DateTime.UtcNow.AddDays(1),
        signingCredentials: creds);
    return new JwtSecurityTokenHandler().WriteToken(token);
    // No audience; RS256 not used; JWKS not published
}
```

### JavaScript

```javascript
import jwt from "jsonwebtoken";

const PRIVATE_KEY = process.env.JWT_SECRET; // symmetric secret for all services

export function issuePair(user) {
  const access = jwt.sign({ sub: user.id, scope: "api" }, PRIVATE_KEY, { expiresIn: "24h" });
  const refresh = jwt.sign({ sub: user.id, typ: "refresh" }, PRIVATE_KEY, { expiresIn: "180d" });
  return { access, refresh };
}

export function rotateRefresh(oldRefresh) {
  const payload = jwt.verify(oldRefresh, PRIVATE_KEY);
  return issuePair({ id: payload.sub }); // new refresh issued; old still valid
}
```

### Go

```go
func mint(sub string) (string, error) {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "sub": sub,
        "exp": time.Now().Add(72 * time.Hour).Unix(),
    })
    return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
    // Authorization server has no JWKS endpoint; RS256 not supported
    http.Error(w, "not found", http.StatusNotFound)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Sign with RS256 using PyJWT and expose JWKS. Rotate refresh tokens and detect reuse.

```python
import jwt as pyjwt
import secrets
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PRIVATE_KEY = load_private_key_from_kms()
PUBLIC_KEY = PRIVATE_KEY.public_key()
KID = "2026-05-key-1"

def issue_tokens(user_id: str, scopes: list[str], refresh_family: str | None = None) -> dict:
    now = int(time.time())
    access = pyjwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": user_id,
            "aud": "api.example.com",
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + 900,
        },
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KID},
    )
    family = refresh_family or secrets.token_urlsafe(16)
    refresh_jti = secrets.token_urlsafe(16)
    refresh = pyjwt.encode(
        {
            "iss": "https://auth.example.com",
            "sub": user_id,
            "aud": "auth.example.com",
            "jti": refresh_jti,
            "family": family,
            "iat": now,
            "exp": now + 604800,
        },
        PRIVATE_KEY,
        algorithm="RS256",
        headers={"kid": KID},
    )
    store_refresh(refresh_jti, family, user_id)
    return {"access_token": access, "refresh_token": refresh}

def refresh_tokens(presented_refresh: str) -> dict:
    claims = validate_refresh(presented_refresh)  # RS256 + iss/aud/exp/jti via PyJWT
    if is_refresh_reused(claims["jti"], claims["family"]):
        revoke_family(claims["family"])
        raise AuthError("refresh reuse detected")
    invalidate_refresh(claims["jti"])
    return issue_tokens(claims["sub"], ["api"], refresh_family=claims["family"])
```

**Important:** Resource servers validate with your JWKS URL and required `aud`. Pair with [4.5 Review Authentication, Session, and Access Control § JWT security (code-level)](4-05-review-authentication-session-and-access.md#jwt) checks for algorithm allowlists and `none` rejection.

### Java

Use Nimbus with RSA keys and publish JWKS from the authorization server.

```java
RSAKey rsaKey = new RSAKey.Builder(publicKey, privateKey)
    .keyID("2026-05-key-1")
    .algorithm(JWSAlgorithm.RS256)
    .build();
JWKSet jwkSet = new JWKSet(rsaKey.toPublicJWK());

SignedJWT access = new SignedJWT(
    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
    new JWTClaimsSet.Builder()
        .issuer("https://auth.example.com")
        .subject(userId)
        .audience("api.example.com")
        .expirationTime(Date.from(Instant.now().plusSeconds(900)))
        .claim("scope", scopes)
        .build());
access.sign(new RSASSASigner(rsaKey));
```

```java
@Bean
JwtDecoder jwtDecoder() {
    NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(
        "https://auth.example.com/.well-known/jwks.json").build();
    decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer("https://auth.example.com"));
    return decoder;
}
```

**Important:** Enable refresh token rotation in Spring Authorization Server or your custom store with reuse detection. Bump a `token_version` user claim on password reset.

### C#

Use RSA credentials and `AddJwtBearer` with authority metadata for resource APIs.

```csharp
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "https://auth.example.com";
        options.Audience = "api.example.com";
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
        };
    });
```

```csharp
var rsa = RSA.Create(2048);
var signingCredentials = new SigningCredentials(
    new RsaSecurityKey(rsa) { KeyId = "2026-05-key-1" },
    SecurityAlgorithms.RsaSha256);

services.AddSingleton<IJwksProvider>(new JwksProvider(rsa.ExportParameters(false), "2026-05-key-1"));
```

**Important:** Publish JWKS from the auth service. Store refresh tokens hashed server-side and replace them on each refresh request.

### Go

Use `lestrrat-go/jwx` or `golang-jwt/jwt` with RSA and a JWKS HTTP handler.

```go
import "github.com/lestrrat-go/jwx/v2/jwk"

key, _ := rsa.GenerateKey(rand.Reader, 2048)
jwkKey, _ := jwk.FromRaw(key)
jwkKey.Set(jwk.KeyIDKey, "2026-05-key-1")
jwkKey.Set(jwk.AlgorithmKey, jwk.RS256)

func jwksHandler(w http.ResponseWriter, r *http.Request) {
    set := jwk.NewSet()
    set.AddKey(jwkKey.PublicKey())
    json.NewEncoder(w).Encode(set)
}

func validateAccess(raw string) (jwt.MapClaims, error) {
    set, _ := jwk.Fetch(context.Background(), "https://auth.example.com/.well-known/jwks.json")
    token, err := jwt.Parse(raw, jwt.WithKeySet(set, jws.WithRequireKid(true)),
        jwt.WithIssuer("https://auth.example.com"), jwt.WithAudience("api.example.com"))
    // ...
}
```

**Important:** Cache JWKS with HTTP cache headers and refetch when `kid` is unknown. Treat refresh reuse as a full session compromise signal.

## Verify During Review

- Authorization server signs with **asymmetric keys (RS256/ES256)** and publishes **JWKS** with `kid`.
- Access tokens are **short-lived**; refresh tokens **rotate** and trigger **reuse detection**.
- Every resource server validates **signature, iss, aud, exp** against current JWKS—not a shared HS256 secret.
- Private keys live in **KMS/HSM**; rotation plan updates JWKS without invalidating all sessions instantly unless required.
- Logout and account recovery **invalidate refresh families** or bump session version claims.
- Cross-check [4.5 § JWT security (code-level)](4-05-review-authentication-session-and-access.md#jwt) for consumer-side parse and algorithm flaws.

## Reference

- [RFC 7519: JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 7517: JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 8725: JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [OAuth 2.0 Authorization Framework — Refresh Token](https://www.rfc-editor.org/rfc/rfc6749#section-1.5)
- [OAuth 2.0 Token Exchange and Rotation Practices (RFC 9700 BCP)](https://datatracker.ietf.org/doc/html/rfc9700)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [PyJWT documentation](https://pyjwt.readthedocs.io/)
- [PyJWT PyJWKClient](https://pyjwt.readthedocs.io/en/stable/usage.html#retrieve-rsa-signing-key-from-jwks-endpoint)
- [Spring Authorization Server](https://docs.spring.io/spring-authorization-server/reference/index.html)
- [Microsoft identity — Token validation](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
- [lestrrat-go/jwx](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2)

## API keys and request signing {: #api-keys }

From former `10-07-review-api-keys-and-request-signing.md`. **Guiding chapter section:** [5.2 - Review Tokens and API Trust § API keys and request signing](../../5-02-review-tokens-and-api-trust.md#api-keys).

## 5.7 - Review API Keys and Request Signing

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
if api_key == "wh_partner_9f2c_export": ...
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
    if api_key != "wh_partner_9f2c_export":
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
3. **Review transport rules.** Reject query-string keys for browser-accessible endpoints. Require TLS 1.2+ per [5.3 § TLS](../../5-03-review-transport-and-service-identity.md#tls).
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

