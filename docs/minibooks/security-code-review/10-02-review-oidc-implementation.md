---
title: Review OpenID Connect Implementation
keywords:
  - security code review
  - openid connect
  - oidc
  - id token
  - nonce
  - userinfo
description: How to review OpenID Connect code for id_token validation, nonce, issuer, audience, and userinfo endpoint usage.
---

## 10.2 - Review OpenID Connect Implementation

OpenID Connect (OIDC) adds identity claims on top of OAuth 2.0. Review discovery document usage, authorization requests, callback handling, and every place the application trusts `id_token` or UserInfo responses. Confirm issuer, audience, signature, expiration, and nonce are validated before login completes.

## What This Topic Is

This chapter is about **implementation review**, not generic vulnerability hunting. OIDC login is correct only when your code validates the `id_token` as a signed JWT from the expected issuer and rejects tokens meant for another client.

The unsafe assumption is that a base64-decodable `id_token` or a UserInfo JSON body proves identity. Attackers can replay tokens, swap issuers, or present tokens issued for a different `aud` if validation is skipped or delegated to the client without cryptography.

This aligns with [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) and relates to [CWE-347](https://cwe.mitre.org/data/definitions/347.html) (Improper Verification of Cryptographic Signature).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Enterprise SSO, social login, B2B federation, mobile OIDC SDK callbacks |
| **Discovery** | Hardcoded JWKS URLs, skipped `.well-known/openid-configuration`, TLS verify disabled on metadata fetch |
| **id_token handling** | Manual JWT decode without signature verify, trust UserInfo alone, missing `aud`/`iss`/`exp` checks |
| **Nonce** | Missing nonce on authorize request, nonce not validated against `id_token` claim, static nonce |
| **Issuer binding** | Accept any issuer from callback params, string contains check on `iss`, multi-tenant without allowlist |
| **Audience** | `aud` not matched to registered `client_id`, multiple audiences accepted without policy |
| **UserInfo** | Bearer access token sent over HTTP, UserInfo trusted when `id_token` already invalid or absent |
| **Hybrid / implicit** | `id_token` returned in URL fragment without strict validation and short lifetime |

## Abuse Scenarios

Use these scenarios when reviewing OIDC login, account linking, and API authorization that trusts identity claims.

### Scenario 1: Forged id_token (signature not verified)

The application base64-decodes the JWT payload or calls `jwt.decode(..., verify_signature=False)`. An attacker crafts an `id_token` with `sub` of a victim admin and `email` of their choice. The app creates a session without contacting the IdP.

### Scenario 2: Token replay across clients (audience mismatch)

The validator checks signature but not `aud`. An attacker obtains an `id_token` minted for a low-privilege mobile client and replays it to a high-privilege web API that accepts the same issuer.

### Scenario 3: Missing nonce (session fixation)

The authorize request omits `nonce`. An attacker completes IdP login in their browser, then delivers their `id_token` (via hybrid flow fragment or phishing) to bind their IdP identity to the victim's application session.

### Scenario 4: UserInfo as primary identity

The app skips `id_token` validation and calls UserInfo with any bearer token. An attacker presents a stolen API access token (wrong audience) or a token from another client with overlapping scopes.

### Scenario 5: Issuer confusion (multi-tenant)

The app accepts any `iss` matching a substring or loads metadata from attacker-supplied issuer URLs in self-service tenant config. Attacker-operated IdP mints valid-looking tokens for their keys.

### Scenario 6: MITM on discovery/JWKS fetch

TLS verification is disabled when fetching `.well-known/openid-configuration` or JWKS. Attacker serves attacker-controlled keys; signatures verify against wrong trust anchor.

## Language-Specific Libraries and Dangerous Patterns

### Python

```python
# Dangerous: PyJWT decode without signature verification
from jose import jwt as jose_jwt
claims = jose_jwt.get_unverified_claims(id_token)

# Dangerous: UserInfo fetch without TLS
userinfo = httpx.get(f"{ISSUER}/userinfo", verify=False, headers={...})

# Safer: python-jose with JWKS and explicit claims
from jose import jwt as jose_jwt
from jose.backends import RSAKey
claims = jose_jwt.decode(
    id_token, key=jwks[header["kid"]], algorithms=["RS256"],
    audience=CLIENT_ID, issuer=ISSUER,
    options={"verify_at_hash": True},
)
if claims.get("nonce") != session.pop("oidc_nonce"):
    abort(403)
```

Also review: `authlib` `parse_id_token`, `python-jose` without `issuer`/`audience`, manual JWKS fetch without `kid` rotation handling.

### Java

```java
// Dangerous: parse without validation
SignedJWT.parse(raw).getJWTClaimsSet();

// Safer: Nimbus IDTokenValidator or Spring OAuth2 Login (issuer-uri)
IDTokenValidator validator = new IDTokenValidator(
    new Issuer("https://idp.example.com"), new ClientID("web-app"),
    JWSAlgorithm.RS256, jwkSource);
IDTokenClaimsSet claims = validator.validate(idToken, nonce);
```

Also review: `jjwt` without `requireIssuer`, Spring `@AuthenticationPrincipal OidcUser` bypassed by custom parsers.

### C#

```csharp
// Dangerous
var token = handler.ReadJwtToken(id_token);

// Safer: AddOpenIdConnect middleware + TokenValidationParameters
options.Authority = "https://idp.example.com";
options.TokenValidationParameters.ValidateAudience = true;
options.TokenValidationParameters.ValidAudience = clientId;
```

Also review: `Microsoft.IdentityModel.Protocols.OpenIdConnect`, MSAL `ValidateAuthority`.

### JavaScript

```javascript
// Dangerous: client-side id_token parsing
const payload = JSON.parse(atob(idToken.split('.')[1]));

// Safer: openid-client on backend BFF only
import { Issuer, generators } from 'openid-client';
const client = await Issuer.discover(ISSUER);
const params = client.callbackParams(req);
const tokenSet = await client.callback(REDIRECT_URI, params, { nonce, state });
const claims = tokenSet.claims();
```

Also review: `passport-openidconnect`, NextAuth.js `callbacks.jwt`, SPA implicit flow with fragment `id_token`.

### Go

```go
// Dangerous
token, _, _ := new(jwt.Parser).ParseUnverified(rawIDToken, jwt.MapClaims{})

// Safer: coreos/go-oidc
provider, _ := oidc.NewProvider(ctx, "https://idp.example.com")
verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
idToken, err := verifier.Verify(ctx, rawIDToken)
```

See [python-jose documentation](https://python-jose.readthedocs.io/), [openid-client](https://github.com/panva/node-openid-client), [Nimbus OIDC SDK](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk), [Microsoft.IdentityModel](https://learn.microsoft.com/en-us/entra/identity-platform/id-tokens), and [coreos/go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc).

## Sample Vulnerable Code in Python

```python
import httpx
from jose import jwt as jose_jwt
from flask import Flask, request, session, redirect, abort

app = Flask(__name__)
CLIENT_ID = "web-app"
ISSUER = "https://idp.example.com"

@app.route("/oidc/callback")
def oidc_callback():
    id_token = request.args.get("id_token") or session.get("id_token")
    # Signature not verified; attacker forges sub and email
    claims = jose_jwt.get_unverified_claims(id_token)
    # Issuer and audience checks missing; nonce not compared
    session["user_id"] = claims["sub"]
    session["email"] = claims.get("email")
    # UserInfo used as primary identity without binding to validated id_token
    userinfo = httpx.get(
        f"{ISSUER}/userinfo",
        headers={"Authorization": f"Bearer {session.get('access_token')}"},
        verify=False,
    ).json()
    session["name"] = userinfo.get("name")
    return redirect("/home")
```

## Step-by-Step Review Walkthrough

1. **Confirm OIDC discovery.** The client should load issuer metadata from `/.well-known/openid-configuration` and cache `issuer`, `jwks_uri`, and endpoints with TLS verification enabled.
2. **Trace the authorize request.** For code flow, include `scope=openid`, random `state`, PKCE for public clients, and `nonce` stored server-side until callback.
3. **Review id_token validation.** Verify signature with keys from JWKS (`kid` match), check `iss` equals expected issuer, `aud` contains your `client_id`, `exp`/`iat` within skew, and `nonce` matches the authorize request.
4. **Inspect token source.** Reject relying on `id_token` passed only in JavaScript-accessible storage. Prefer code flow where the server exchanges the code and validates tokens server-side.
5. **Evaluate UserInfo usage.** UserInfo supplements claims; it does not replace `id_token` validation. Confirm access token is sent over HTTPS and scopes cover requested attributes.
6. **Check account linking.** Map `sub` + `iss` as the stable external identity key. Do not key accounts on email alone when email is not verified in claims.
7. **Review logout and session fixation.** End-session endpoints should clear local session; new login must issue fresh `state` and `nonce`.

## Risk Impact Analysis

**Authentication bypass.** Forged or swapped `id_token` payloads let attackers sign in as arbitrary users without valid IdP credentials.

**Cross-client token replay.** Accepting tokens with wrong `aud` allows reuse of tokens minted for another OAuth client.

**Session fixation and CSRF.** Missing `nonce` or `state` binds the wrong IdP authentication event to the victim application session.

**Identity confusion.** Trusting unverified email or UserInfo fields enables account takeover when attackers control IdP attributes or MITM metadata.

**Tenant crossover.** Weak issuer allowlists in multi-tenant SaaS may accept tokens from another customer's IdP configuration.

## Vulnerable Examples in Other Languages

### Java

```java
@GetMapping("/login/oauth2/code/idp")
public String callback(@AuthenticationPrincipal OidcUser user) {
    // Custom parser bypasses Spring's validator
    String raw = (String) user.getIdToken().getTokenValue();
    SignedJWT jwt = SignedJWT.parse(raw);
    JWTClaimsSet claims = jwt.getJWTClaimsSet();
    // No explicit iss/aud/nonce verification in custom path
    accountService.link(claims.getSubject(), claims.getStringClaim("email"));
    return "redirect:/app";
}
```

### C#

```csharp
public async Task<IActionResult> Callback(string id_token)
{
    var handler = new JwtSecurityTokenHandler();
    var token = handler.ReadJwtToken(id_token);
    // ReadJwtToken does not validate signature or issuer
    var sub = token.Claims.First(c => c.Type == "sub").Value;
    await SignInUser(sub, token.Claims.First(c => c.Type == "email").Value);
    return Redirect("/");
}
```

### JavaScript

```javascript
function handleOidcCallback() {
  const params = new URLSearchParams(window.location.hash.slice(1));
  const idToken = params.get("id_token");
  const payload = JSON.parse(atob(idToken.split(".")[1]));
  // No signature, iss, aud, or nonce validation in browser
  setUser({ id: payload.sub, email: payload.email });
}
```

### Go

```go
func oidcCallback(w http.ResponseWriter, r *http.Request) {
    rawIDToken := r.URL.Query().Get("id_token")
    token, _, _ := new(jwt.Parser).ParseUnverified(rawIDToken, jwt.MapClaims{})
    claims := token.Claims.(jwt.MapClaims)
    // nonce and aud not checked
    setSession(w, claims["sub"].(string))
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use `python-jose` with issuer JWKS and explicit claim requirements—not unverified payload reads.

```python
import httpx
from jose import jwt as jose_jwt
from jose.utils import base64url_decode
from jose.backends import RSAKey

def load_jwk_for_token(id_token: str, jwks: dict) -> RSAKey:
    header = jose_jwt.get_unverified_header(id_token)
    key_data = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    return RSAKey(key_data, header.get("alg", "RS256"))

@app.route("/oidc/callback")
def oidc_callback():
    id_token = session.pop("id_token_from_code_exchange")
    claims = jose_jwt.decode(
        id_token,
        key=load_jwk_for_token(id_token, fetch_jwks(ISSUER)),
        algorithms=["RS256"],
        audience=CLIENT_ID,
        issuer=ISSUER,
    )
    if claims.get("nonce") != session.pop("oidc_nonce"):
        abort(403)
    session["sub"] = claims["sub"]
    return redirect("/home")
```

**Important:** Never call `get_unverified_claims` on login paths. Exchange the authorization code server-side, then validate the returned `id_token` before creating a session.

### Java

Rely on Spring Security OAuth2 Login with issuer-based configuration, or validate with Nimbus `IDTokenValidator`.

```java
@Bean
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.oauth2Login(oauth -> oauth
        .userInfoEndpoint(user -> user.oidcUserService(oidcUserService()))
    );
    return http.build();
}

// application.yml
// spring.security.oauth2.client.provider.idp.issuer-uri=https://idp.example.com
```

```java
IDTokenValidator validator = new IDTokenValidator(
    new Issuer("https://idp.example.com"),
    new ClientID("web-app"),
    JWSAlgorithm.RS256,
    jwkSource);
IDTokenClaimsSet claims = validator.validate(idToken, expectedNonce);
```

**Important:** Keep `issuer-uri` as the single source of truth. Custom JWT parsing should duplicate all required OIDC checks, not skip them.

### C#

Configure `Microsoft.Identity.Web` or OpenID Connect middleware with authority and token validation.

```csharp
services.AddMicrosoftIdentityWebAppAuthentication(Configuration, "AzureAd");

// Or explicit OpenIdConnect with TokenValidationParameters:
services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddOpenIdConnect(options =>
{
    options.Authority = "https://idp.example.com";
    options.ClientId = Configuration["Oidc:ClientId"];
    options.ClientSecret = Configuration["Oidc:ClientSecret"];
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.UsePkce = true;
    options.SaveTokens = false;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = "https://idp.example.com",
        ValidateAudience = true,
        ValidAudience = Configuration["Oidc:ClientId"],
        ValidateLifetime = true,
        NameClaimType = "name",
    };
});
```

**Important:** `Authority` drives metadata and signing keys. Do not disable issuer or audience validation to fix local dev issues in production builds.

### Go

Use `coreos/go-oidc` for provider discovery and ID token verification.

```go
import "github.com/coreos/go-oidc/v3/oidc"

provider, _ := oidc.NewProvider(ctx, "https://idp.example.com")
verifier := provider.Verifier(&oidc.Config{ClientID: os.Getenv("OIDC_CLIENT_ID")})

func callback(w http.ResponseWriter, r *http.Request) {
    oauth2Token, _ := oauthConfig.Exchange(ctx, r.URL.Query().Get("code"))
    rawIDToken, ok := oauth2Token.Extra("id_token").(string)
    if !ok {
        http.Error(w, "missing id_token", http.StatusUnauthorized)
        return
    }
    idToken, err := verifier.Verify(ctx, rawIDToken)
    if err != nil {
        http.Error(w, "invalid id_token", http.StatusUnauthorized)
        return
    }
    if idToken.Nonce != expectedNonce {
        http.Error(w, "invalid nonce", http.StatusUnauthorized)
        return
    }
    var claims struct{ Sub string `json:"sub"` }
    idToken.Claims(&claims)
}
```

**Important:** Always verify through the provider's `Verifier`. Fetch UserInfo only after access token validation and prefer claims already present in the verified `id_token`.

## Verify During Review

- Client loads **issuer metadata** from `.well-known/openid-configuration` with TLS verification.
- Every login validates **id_token signature**, `iss`, `aud`, `exp`, and **nonce** before creating a session.
- **`sub` + `iss`** is the external identity key; verified claims drive authorization, not raw callback parameters.
- **UserInfo** is optional enrichment; it does not replace id_token validation.
- Public clients use **code flow + PKCE**; tokens are not accepted from URL fragments without strict validation.
- Multi-tenant apps enforce an **issuer allowlist** per tenant or registration.

## Reference

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 7519: JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519)
- [OAuth.net — OpenID Connect](https://oauth.net/2/openid-connect/)
- [OWASP OAuth 2.0 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [python-jose documentation](https://python-jose.readthedocs.io/)
- [openid-client (Node.js)](https://github.com/panva/node-openid-client)
- [Microsoft Identity Web](https://learn.microsoft.com/en-us/entra/msal/dotnet/microsoft-identity-web/)
- [Spring Security — OAuth2 Login](https://docs.spring.io/spring-security/reference/servlet/oauth2/login/index.html)
- [coreos/go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc)
- [coreos/go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc)
