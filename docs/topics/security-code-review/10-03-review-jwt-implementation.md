---
title: Review JWT Implementation
keywords:
  - security code review
  - jwt implementation
  - rs256
  - jwks
  - refresh token rotation
description: How to review secure JWT issuance and validation—RS256 signing, JWKS publication, key rotation, and refresh token rotation beyond basic parse flaws.
---

## 10.3 - Review JWT Implementation

JWT implementation review covers how your service **issues** and **validates** tokens, not only whether parsing skips signature checks. Start at the authorization server: signing keys, algorithms, claim design, and refresh handling. Then trace every resource server that consumes those tokens. For parse-time flaws and algorithm confusion, also read [4.16 Review JWT Security](4-16-review-jwt-security.md).

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

**Important:** Resource servers validate with your JWKS URL and required `aud`. Pair with [4.16](4-16-review-jwt-security.md) checks for algorithm allowlists and `none` rejection.

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
- Cross-check [4.16 Review JWT Security](4-16-review-jwt-security.md) for consumer-side parse and algorithm flaws.

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
