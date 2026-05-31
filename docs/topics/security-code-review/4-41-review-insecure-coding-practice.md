---
title: Review Insecure Coding Practice
keywords:
  - security code review
  - insecure coding
  - TLS verification
  - JWT verification
  - cookie flags
  - security misconfiguration
description: A code review guide for recurring insecure coding practices—TLS certificate verification, JWT signature and key handling, HTTP cookie flags, and related configuration mistakes.
---

## 4.41 - Review Insecure Coding Practice

“Insecure coding practice” is not one CWE. It is a cluster of implementation habits that look small in a diff but collapse transport trust, session trust, or API identity in production. This chapter focuses on three high-frequency patterns: HTTPS clients that skip certificate verification, JWT handling that skips signature and key checks, and session cookies missing HttpOnly, Secure, and SameSite. It also lists related practices you should scan in the same review pass, with pointers to dedicated mini-chapters where they exist.

## What This Vulnerability Is

These flaws come from convenience shortcuts, copy-pasted samples, or framework defaults left unchanged. The application still “uses HTTPS” or “uses JWT,” but the code does not actually validate the peer, token, or cookie the way the design assumes.

The unsafe assumption is that the network is honest, the token payload is authoritative because it is base64-encoded, or that HTTPS alone protects sessions without explicit cookie flags. Attackers exploit MITM on outbound calls, forged JWTs, and stolen session cookies. Reviewers should treat each pattern as a missing security control, not as style issues.

## Vulnerability Characteristics (Where to Identify Them)

| Pattern | Where to look | Red flags |
| --- | --- | --- |
| **TLS / HTTPS verification disabled** | `requests.get(..., verify=False)`, custom `TrustManager` that accepts all certs, `NODE_TLS_REJECT_UNAUTHORIZED=0`, gRPC/HTTP clients with insecure channel creds | Comments like “fix cert later,” test code shipped to prod |
| **JWT signature / key mishandling** | `verify_signature=False`, hardcoded `secretkey`, accepting `alg: none`, parsing payload without `jwt.decode` validation, JWKS without issuer/audience checks | Auth middleware that only base64-decodes the middle segment |
| **Insecure HTTP cookie flags** | `set_cookie` without `httponly`/`secure`/`samesite`, legacy servlet cookies, framework session defaults | Session ID in URL, year-long `Max-Age`, logout that only clears client cookie |
| **Hardcoded secrets** (related) | API keys, DB passwords, signing keys in source | See [4.32 Review Hardcoded Secrets](4-32-review-hardcoded-secrets.md) |
| **Weak or custom crypto** (related) | MD5 passwords, home-grown AES, mixed hash/encrypt | See [4.12](4-12-review-cryptographic-implementation.md), [4.36](4-36-review-non-standard-crypto-practices.md), [4.38](4-38-review-encryption-decryption-mistakes.md) |
| **Dangerous dynamic execution** (related) | `eval`, `exec`, script engines on user input | See [4.35 Review Dangerous Functions](4-35-review-dangerous-functions.md) |
| **Sensitive data in logs or URLs** (related) | Tokens/passwords in logs, credentials in GET | See [4.22](4-22-review-sensitive-data-in-url.md), [4.25](4-25-review-sensitive-logging.md) |
| **Secrets in comments** (related) | Password hints in HTML/JS comments | See [4.31 Review Sensitive Code Comments](4-31-review-sensitive-code-comments.md) |
| **Insecure deserialization** (related) | `pickle.loads` on untrusted bytes | See [4.37 Review Insecure Deserialization](4-37-review-insecure-deserialization.md) |
| **Framework defaults left weak** (related) | DEBUG=True, permissive CORS, CSRF off | See [4.30 Review Framework Secure Defaults](4-30-review-framework-secure-defaults.md) |

**Suggested additions for the same review pass:** debug endpoints left enabled in production, permissive CORS with credentials, missing CSRF on state-changing cookie auth ([4.13](4-13-review-csrf.md)), trust-all proxy headers without validation, and disabling security headers (CSP, HSTS) at the edge.

## Sample Vulnerable Code in Python

```python
import jwt
import requests
from flask import Flask, make_response, redirect, request

app = Flask(__name__)
JWT_SECRET = "changeme"  # hardcoded; rotation not supported

@app.route("/login", methods=["POST"])
def login():
    session_id = issue_session(request.form["username"])
    resp = make_response(redirect("/dashboard"))
    # Insecure cookie: no HttpOnly, Secure, or SameSite
    resp.set_cookie("session", session_id, httponly=False, secure=False)
    return resp

@app.route("/api/me")
def api_me():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    # Forged tokens accepted — signature not verified
    user = jwt.decode(token, options={"verify_signature": False})
    return {"user": user}

@app.route("/sync")
def sync_partner():
    url = request.args["url"]  # attacker-controlled partner URL
    # TLS certificate verification disabled — MITM possible
    return requests.get(url, verify=False, timeout=10).text
```

## Step-by-Step Review Walkthrough

1. **Search for TLS verification bypass.** Grep `verify=False`, `CERT_NONE`, `check_hostname = False`, and custom trust managers. Ask which environments use the code; test-only paths must not ship in production builds.
2. **Trace outbound HTTPS from user-influenced URLs.** In the sample, `sync_partner` fetches arbitrary URLs without validation—this overlaps SSRF ([4.14](4-14-review-ssrf.md)). Even for fixed partners, disabling verification invites MITM credential theft.
3. **Locate JWT parse and authorize paths.** In `api_me`, claims drive behavior without signature verification. Find every `jwt.decode`, library wrappers, and API gateways that forward `X-User-Id` without validation.
4. **Review signing key resolution.** Static `JWT_SECRET`, shared dev keys, missing JWKS fetch, and no `iss`/`aud`/`exp` checks are common. Confirm allowed algorithms are explicit (reject `none`).
5. **Audit cookie setters on login and refresh.** Match `login()` against policy: HttpOnly (anti-XSS theft), Secure (HTTPS only), SameSite (CSRF posture). See [4.33](4-33-review-insecure-cookie-configuration.md) for depth.
6. **Walk related insecure practices.** In one service, hardcoded secrets often appear beside disabled TLS verify—fix both in the same change set.
7. **Verify production configuration.** Environment flags, Helm values, and reverse-proxy cookie settings must align with application code; code may set flags while the edge strips Secure.

## Risk Impact Analysis

**Man-in-the-middle on outbound HTTPS.** Disabling certificate verification lets attackers intercept API keys, OAuth tokens, and PII on service-to-service calls even when the URL uses `https://`.

**Authentication and authorization bypass via JWT.** Unverified signatures or weak secrets allow arbitrary `sub`, `role`, or `admin` claims—full account takeover without passwords.

**Session hijacking and CSRF.** Cookies without HttpOnly are readable from XSS; without Secure they may leak on HTTP; without SameSite they are easier to abuse in cross-site requests.

**Compounding failures.** A single microservice may disable TLS verify while sending a bearer token in the header—MITM captures the token and replays it elsewhere.

**Audit and compliance exposure.** Regulated workloads expect demonstrable TLS trust stores, token validation, and session cookie controls; these gaps are frequent audit findings.

## Vulnerable Examples in Other Languages

### Java

```java
// Trust-all TLS + hardcoded API key (insecure coding cluster)
HttpsURLConnection conn = (HttpsURLConnection) new URL(userSuppliedUrl).openConnection();
conn.setSSLSocketFactory(trustAllSocketFactory);
conn.setRequestProperty("Authorization", "Bearer sk_live_hardcoded");

// JWT: signature verification not enforced
Claims claims = Jwts.parser()
    .setSigningKey("changeme")
    .parseClaimsJws(jwt).getBody();

// Cookie without HttpOnly, Secure, or SameSite
Cookie c = new Cookie("session", session.getId());
response.addCookie(c);
```

### C#

```csharp
// HttpClient handler that accepts any server certificate
var handler = new HttpClientHandler {
    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
};
var client = new HttpClient(handler);
var data = await client.GetStringAsync(userUrl);

// JWT without full validation
var token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
var role = token.Claims.First(c => c.Type == "role").Value;

// Cookie missing flags
Response.Cookies.Append("Session", sessionId, new CookieOptions {
    HttpOnly = false,
    Secure = false
});
```

### Go

```go
// Insecure TLS skip (testing helper left in prod)
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
resp, _ := http.Client{Transport: tr}.Get(partnerURL)

// JWT parsed without verifying signature
token, _, _ := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
admin, _ := token.Claims.(jwt.MapClaims)["admin"].(bool)

// Cookie without HttpOnly / Secure / SameSite
http.SetCookie(w, &http.Cookie{Name: "session", Value: sid, Path: "/"})
```

## Fix: Safer Patterns and Libraries to Use

### Python

**TLS: always verify server certificates.** Use default verification; pin corporate roots via `verify=` path or system trust store—not `verify=False`.

```python
import requests

# Default: verifies hostname and certificate chain
resp = requests.get("https://api.partner.example/v1/report", timeout=10)

# Custom CA bundle (corporate proxy) — still verifies
resp = requests.get(url, verify="/etc/ssl/certs/corporate-ca.pem", timeout=10)
```

**Important:** Never set `verify=False` except in isolated tests. If tests need it, gate with an explicit non-production flag that fails closed in CI for release artifacts.

**JWT: verify signature, algorithm, and claims.**

```python
import jwt

def current_user(token: str) -> dict:
    return jwt.decode(
        token,
        key=get_signing_key(),  # from env / JWKS — not a hardcoded demo secret
        algorithms=["RS256"],   # explicit allowlist — never accept "none"
        audience="my-api",
        issuer="https://idp.example/",
        options={"require": ["exp", "sub"]},
    )
```

**Cookies: set HttpOnly, Secure, and SameSite.**

```python
resp.set_cookie(
    "session",
    session_id,
    httponly=True,
    secure=True,
    samesite="Lax",
    max_age=900,
)
```

### Java

```java
// Use default SSL socket factory — do not install trust-all managers
HttpsURLConnection conn = (HttpsURLConnection) new URL(allowlistedUrl).openConnection();

// JWT with explicit key and algorithm (jjwt example)
Jwts.parserBuilder()
    .setSigningKeyResolver(jwkResolver)
    .requireIssuer("https://idp.example/")
    .requireAudience("my-api")
    .build()
    .parseClaimsJws(jwt);

Cookie cookie = new Cookie("JSESSIONID", session.getId());
cookie.setHttpOnly(true);
cookie.setSecure(true);
cookie.setAttribute("SameSite", "Lax");
response.addCookie(cookie);
```

**Important:** `setSigningKey("secretkey")` without rotation, issuer, or audience checks is insufficient for production APIs.

### C#

```csharp
// Default HttpClient validates server certificates
using var client = new HttpClient();
var data = await client.GetStringAsync(allowlistedUrl);

var parameters = new TokenValidationParameters {
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = signingKey,
    ValidIssuer = "https://idp.example/",
    ValidAudience = "my-api",
    ValidateLifetime = true,
};
var principal = new JwtSecurityTokenHandler()
    .ValidateToken(jwt, parameters, out _);

Response.Cookies.Append("Session", sessionId, new CookieOptions {
    HttpOnly = true,
    Secure = true,
    SameSite = SameSiteMode.Lax,
    MaxAge = TimeSpan.FromMinutes(15),
});
```

### Go

```go
// Default client verifies TLS; use custom RootCAs for enterprise CAs only
client := &http.Client{Timeout: 10 * time.Second}
resp, err := client.Get(allowlistedURL)

token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
    if t.Method.Alg() != "RS256" {
        return nil, fmt.Errorf("unexpected alg")
    }
    return publicKey, nil
}, jwt.WithAudience("my-api"), jwt.WithIssuer("https://idp.example/"))

http.SetCookie(w, &http.Cookie{
    Name:     "session",
    Value:    sid,
    Path:     "/",
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteLaxMode,
    MaxAge:   900,
})
```

## Verify During Review

- No production code path uses `verify=False`, trust-all TLS callbacks, or equivalent.
- JWT validation enforces signature, allowed algorithms, `exp`, and `iss`/`aud` where applicable; no `verify_signature=False` in deployed branches.
- Signing keys load from secret stores or JWKS with rotation; no long-lived hardcoded symmetric secrets in source.
- Session cookies use HttpOnly + Secure + deliberate SameSite; lifetimes match policy.
- User-controlled URLs are not fetched with TLS verification disabled (pair with SSRF allowlists).
- Related chapters (hardcoded secrets, CSRF, session management) are checked when any finding above is present.

## Reference

- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Python requests — SSL Cert Verification](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification)
- [Python PyJWT — Usage (decode with verification)](https://pyjwt.readthedocs.io/en/stable/usage.html)
- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [OWASP JSON Web Token Cheat Sheet for Java](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [MDN — Set-Cookie (HttpOnly, Secure, SameSite)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
- [Flask — Set-Cookie parameters](https://flask.palletsprojects.com/en/stable/api/#flask.Response.set_cookie)
- [Microsoft Learn — HttpClient certificate validation](https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/http/httpclient#secure-the-connection)
- [Microsoft Learn — TokenValidationParameters](https://learn.microsoft.com/en-us/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters)
- [Java HttpsURLConnection documentation](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/net/ssl/HttpsURLConnection.html)
- [jjwt — JJWT README (signature verification)](https://github.com/jwtk/jjwt#jws)
- [Go crypto/tls — Config](https://pkg.go.dev/crypto/tls#Config)
- [Go golang-jwt — jwt.Parse](https://pkg.go.dev/github.com/golang-jwt/jwt/v5#Parse)
- [Go net/http — Cookie fields](https://pkg.go.dev/net/http#Cookie)
