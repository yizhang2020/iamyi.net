---
title: Review Tokens and API Trust
keywords:
  - jwt
  - jwks
  - api keys
  - request signing
  - hmac
description: Review JWT issuance/validation and API key / request-signing designs together.
---

## 5.2 - Review Tokens and API Trust

### Overview

Tokens and API credentials prove who may call what. Review how they are **minted**, **validated**, **rotated**, and **bound to transport**—not only whether `jwt.decode` or a header check exists. For parse-time JWT flaws (algorithm confusion, skipped signature), also use Chapter 4.5.

The points below are the ideas this family chapter uses again and again.

1. Tokens and API credentials prove who may call what.
2. Review how credentials are minted, validated, rotated, and bound to transport.
3. JWT issuance/JWKS and API keys/request signing share that trust problem.
4. Parse-time JWT flaws stay in Chapter 4.5; issuance and rotation live here.
5. Evidence names the credential decision, missing control, impact, and a proving test.

After reading this chapter, we should be able to review JWT issuance/validation and API signing designs with shared token-trust habits.

## Shared Review Model

Across every variant below, keep the same evidence habit: name the **protocol step or credential**, the **trust decision**, the **missing control**, the **impact**, and a **test** that would prove a fix.

## Variants in This Family

### JWT implementation {: #jwt }

This chapter is about **implementation review**, not generic vulnerability hunting. A secure JWT stack requires correct cryptography, key lifecycle, claim policy, and refresh rotation—not merely calling `jwt.decode` with a secret string.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Custom auth server, API gateway token mint, microservice mesh, mobile backend |
| **Signing model** | HS256 shared secret copied to every service; private keys in repo; no `kid` in header |
| **JWKS endpoint** | Missing `/.well-known/jwks.json`, stale keys served after rotation, HTTP not HTTPS |
| **Access token policy** | Lifetime over 15 minutes without justification; sensitive claims in access token |
| **Refresh tokens** | Reusable refresh tokens, no rotation, no reuse detection, refresh stored in localStorage |
| **Validation gaps** | Resource servers fetch JWKS once at startup; no `iss`/`aud` enforcement per API |
| **Revocation** | Logout clears client cookie only; no server-side refresh denylist or token version claim |

**Appendix detail:** [JWT implementation reference](appendix/secure-implementations-reference/5-02-review-tokens-and-api-trust.md#jwt).

### API keys and request signing {: #api-keys }

Weak API key design exposes long-lived secrets in URLs, source code, or logs. HMAC verification fails when services skip signature checks, use predictable secrets, compare digests incorrectly, or omit timestamp and nonce checks that prevent replay.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Public REST/GraphQL APIs, webhooks, partner integrations, mobile app backends, CLI tools |
| **Key issuance** | Admin consoles, self-service signup, long-lived “master” keys, keys embedded in mobile binaries |
| **Transport** | `?api_key=` query params, keys in `Referer` via HTTP pages, missing TLS on key-bearing requests |
| **Verification** | Single shared secret for all tenants, optional auth middleware, timing-unsafe string compare |
| **HMAC schemes** | Custom headers without canonical string, missing clock skew, no nonce store, MD5/SHA1 HMAC for new designs |
| **Scope and lifecycle** | One key for read and admin, no per-environment separation, no revocation or rotation path |

**Appendix detail:** [API keys and request signing reference](appendix/secure-implementations-reference/5-02-review-tokens-and-api-trust.md#api-keys).

## Worked Example (JWT implementation)

We walk **JWT implementation** in depth. Apply the same tracing steps to the other variants, adjusting protocol steps and sinks from the tables above.

### Sample vulnerable code (Python)

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

### Step-by-step review walkthrough

1. **Map issuer and consumers.** Identify which component signs tokens and every service that validates them. HS256 requires secret distribution; RS256/ES256 should use public keys via JWKS.
2. **Review signing key storage.** Private keys belong in HSM, KMS, or sealed secrets—not git. Confirm `kid` is present and rotates with the key material.
3. **Inspect access token claims.** Keep lifetimes short. Put authorization data in scope or custom claims bound to `aud`. Avoid embedding long-lived privileges without refresh checks.
4. **Trace JWKS publication.** Authorization servers expose current and rollover public keys. Consumers cache JWKS with TTL and refresh on unknown `kid`.
5. **Review refresh flow.** Each refresh should mint a new refresh token, invalidate the previous one, and detect reuse (revoke token family on replay).
6. **Check resource server validation.** Each API validates `iss`, `aud`, signature, and `exp` with the correct key—not a copy-pasted dev secret.
7. **Confirm logout and compromise response.** Document how operators revoke sessions: refresh denylist, `jti` blocklist, or session version claim bumped on password change.

## Risk Impact (Family)

**Wide-scale forgery.** A leaked HS256 secret or stolen private key lets attackers mint valid tokens for any subject and scope.

**Stale key trust.** Services that never refresh JWKS continue trusting compromised keys after rotation delays exposure but do not stop active abuse if rotation is skipped.

**Refresh token replay.** Non-rotating refresh tokens act like long-lived passwords; XSS or device theft yields persistent access.

**Privilege sprawl.** Overlong access tokens with embedded roles delay revocation until expiry even after admin lockout.

**Cross-service audience confusion.** Tokens minted for one API accepted by another when `aud` is not enforced per resource server.

## Fix Principles

Primary safer patterns for the worked example follow. For other languages and variant-specific fixes, use the [family appendix](appendix/secure-implementations-reference/5-02-review-tokens-and-api-trust.md).

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

Use the checklist below as a family-level pass over the variants above. Each item should map to evidence in the change under review.

- Authorization server signs with **asymmetric keys (RS256/ES256)** and publishes **JWKS** with `kid`.
- Access tokens are **short-lived**; refresh tokens **rotate** and trigger **reuse detection**.
- Every resource server validates **signature, iss, aud, exp** against current JWKS—not a shared HS256 secret.
- Private keys live in **KMS/HSM**; rotation plan updates JWKS without invalidating all sessions instantly unless required.
- Logout and account recovery **invalidate refresh families** or bump session version claims.
- Cross-check [4.5 § JWT security (code-level)](4-05-review-authentication-session-and-access.md#jwt) for consumer-side parse and algorithm flaws.
- API keys are **never** in query strings, URLs shared to browsers, or committed source.
- Secrets load from a **managed store**; raw keys are shown once at issuance and stored hashed.
- Each key has explicit **scope**, tenant binding, and **revocation** path.
- HMAC uses **HMAC-SHA256** (or stronger approved MAC) with **constant-time** verification.
- Signed requests include **timestamp** (and nonce where needed) with enforced skew and replay controls.
- **Rotation** supports overlapping valid keys; audit logs record key id, not secret material.
- Successful authentication still passes through **authorization** checks for the requested resource.

## Implementation Reference (Appendix)

Library sinks, multi-language examples, and full fix catalogs for every variant live in **[5.2 reference — Review Tokens and API Trust](appendix/secure-implementations-reference/5-02-review-tokens-and-api-trust.md)**.

## Reference

- Appendix — [5.2 reference](appendix/secure-implementations-reference/5-02-review-tokens-and-api-trust.md)

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
