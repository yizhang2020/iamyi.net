---
title: "5.1 Reference — Review Identity and Federation"
description: >
  Libraries, multi-language examples, and fixes for Review Identity and Federation.
---

# 5.1 Reference — Review Identity and Federation

This appendix supports the guiding chapter **[5.1 - Review Identity and Federation](../../5-01-review-identity-and-federation.md)**. Each section below preserves the dense material from a former topic chapter.

**Back to chapter:** [5.1 - Review Identity and Federation](../../5-01-review-identity-and-federation.md)

## OAuth 2.0 {: #oauth }

From former `10-01-review-oauth-implementation.md`. **Guiding chapter section:** [5.1 - Review Identity and Federation § OAuth 2.0](../../5-01-review-identity-and-federation.md#oauth).

## 5.1 - Review OAuth 2.0 Implementation

OAuth 2.0 connects your application to an identity provider or API without sharing user passwords. Review the authorization request, callback handler, token exchange, and storage paths. Confirm the flow uses authorization code with PKCE, binds redirect URIs, validates state, authenticates the client at the token endpoint, and stores tokens safely.

## What This Topic Is

This chapter is about **implementation review**, not generic vulnerability hunting. You are checking whether the OAuth flow matches [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) and current best practice for the client type (public vs confidential).

The unsafe assumption is that receiving a code or token from a redirect means the user authenticated successfully. Attackers can forge callbacks, steal codes via open redirects, or intercept tokens when PKCE, state, and redirect binding are missing.

This maps to broken authentication and session management patterns in [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) and relates to [CWE-287](https://cwe.mitre.org/data/definitions/287.html) (Improper Authentication).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Social login, "Sign in with …", API integrations, mobile deep links, SPA auth |
| **Flow choice** | Implicit or password grant in browser apps; auth code without PKCE for public clients |
| **Redirect URI** | String prefix match, wildcard hosts, user-controlled redirect params, missing exact registration |
| **State / CSRF** | Missing `state`, static state, state not validated on callback, state stored only client-side without binding |
| **Token endpoint** | Missing `client_secret` or mTLS for confidential clients; PKCE verifier not checked server-side |
| **Token storage** | Access or refresh tokens in localStorage, query strings, logs, or non-HttpOnly cookies |
| **Library config** | Custom OAuth glue, disabled TLS verify on token requests, hardcoded client secrets in frontend bundles |

## Abuse Scenarios

Use these scenarios in authorized security tests and design reviews. Each assumes an attacker can influence redirects, callbacks, or client storage.

### Scenario 1: Authorization code interception (no PKCE)

A public SPA uses authorization code flow without PKCE. An attacker who learns the redirect URI registers a look-alike app or exploits an open redirect on the legitimate redirect URI. When the victim completes login, the attacker captures the `code` from the redirect and exchanges it at the token endpoint before the legitimate client does.

### Scenario 2: CSRF on OAuth callback (missing state)

The client omits `state` on the authorize request. An attacker starts their own OAuth login, then tricks the victim into visiting the victim app's callback URL with the attacker's `code`. The victim's session becomes bound to the attacker's IdP account—account linking or session fixation.

### Scenario 3: Redirect URI manipulation

The token exchange accepts `redirect_uri` from the query string or allows prefix matching (`https://app.example.com` matches `https://app.example.com.evil.com`). The attacker exchanges a stolen code using a registered or accepted alternate URI.

### Scenario 4: Token leakage via browser storage

Access or refresh tokens land in `localStorage`, URL fragments (implicit-style), or non-HttpOnly cookies. XSS or physical access to the device yields long-lived API access independent of password strength.

### Scenario 5: Client secret in frontend bundle

A "confidential" client secret is embedded in a mobile app or SPA JavaScript. Attackers extract it and call the token endpoint as the client, combining with stolen refresh tokens or password grant if enabled.

### Scenario 6: TLS verification disabled on token calls

The backend disables certificate verification when calling the IdP token endpoint (`verify=False`). A network attacker MITM's the token exchange and captures refresh tokens or injects malicious token responses.

## Language-Specific Libraries and Dangerous Patterns

Search for OAuth client code and verify library defaults enforce PKCE, state, and TLS.

### Python

```python
# Dangerous patterns
requests.post(token_url, data={...}, verify=False)
session["access_token"] = tokens["access_token"]  # no rotation policy
redirect_uri = request.args.get("redirect_uri")  # attacker-controlled

# Safer: Authlib Flask client
from authlib.integrations.flask_client import OAuth
oauth = OAuth(app)
oauth.register(
    name="idp",
    client_id=os.environ["OAUTH_CLIENT_ID"],
    client_secret=os.environ["OAUTH_CLIENT_SECRET"],
    server_metadata_url="https://idp.example.com/.well-known/openid-configuration",
)
return oauth.idp.authorize_redirect(redirect_uri=FIXED_REDIRECT, state=state, code_challenge=challenge)
```

Also review: `authlib` token exchange, `requests-oauthlib` OAuth2Session without PKCE, `httpx-oauth` with `verify=False` on token URL.

### Ruby

```ruby
# Dangerous: omniauth without state/PKCE; token in session
OmniAuth.config.allowed_request_methods = [:post, :get]

# Safer: omniauth-oauth2 with PKCE and fixed redirect
provider :oidc,
  scope: [:openid, :profile],
  pkce: true,
  redirect_uri: "https://app.example.com/auth/callback"
```

### Java

```java
// Dangerous: Spring RestTemplate token exchange without PKCE; state ignored
restTemplate.postForObject(tokenUrl, body, OAuth2AccessToken.class);

// Safer: Spring Security OAuth2 Client
http.oauth2Login(oauth -> oauth
    .authorizationEndpoint(a -> a.authorizationRequestResolver(pkceResolver)));
// application.yml: authorization-grant-type=authorization_code, issuer-uri=...
```

Also review: `spring-security-oauth2-client`, legacy `spring-security-oauth2` (deprecated), custom `OAuth2AuthorizedClientProvider`.

### C#

```csharp
// Dangerous: manual token POST with user-supplied redirect
await httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(new Dictionary<string, string> {
    ["redirect_uri"] = Request.Query["returnUrl"],
}));

// Safer: Microsoft.Identity.Web / AddOpenIdConnect
services.AddOpenIdConnect(options => {
    options.UsePkce = true;
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.CallbackPath = "/signin-oidc";
});
```

Also review: `Microsoft.Identity.Client` (MSAL) for confidential vs public client patterns, `IdentityModel.OidcClient`.

### JavaScript

```javascript
// Dangerous: implicit flow, localStorage tokens
window.location = `${AUTH}/authorize?response_type=token&client_id=${ID}`;
localStorage.setItem('access_token', hash.get('access_token'));

// Safer: oauth4webapi / openid-client on backend BFF only
// Browser never holds refresh token; backend uses authorization code + PKCE
```

Also review: `passport-oauth2`, `@auth0/nextjs-auth0` config, Electron apps embedding client secrets.

### Go

```go
// Dangerous: no state; redirect from Host header
redirectURI := "https://" + r.Host + "/callback"

// Safer: golang.org/x/oauth2 with PKCE
verifier := oauth2.GenerateVerifier()
url := config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
token, err := config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
```

See [Authlib documentation](https://docs.authlib.org/en/latest/), [Spring Security OAuth2 Client](https://docs.spring.io/spring-security/reference/servlet/oauth2/client/index.html), [Microsoft Identity Web](https://learn.microsoft.com/en-us/entra/msal/dotnet/), and [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2).

## Sample Vulnerable Code in Python

```python
from flask import Flask, request, redirect, session
import requests

app = Flask(__name__)
CLIENT_ID = "app-client"
REDIRECT_URI = "https://app.example.com/oauth/callback"

@app.route("/login")
def login():
    # No state, no PKCE — callback cannot be bound to this session
    auth_url = (
        "https://idp.example.com/oauth/authorize"
        f"?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}"
    )
    return redirect(auth_url)

@app.route("/oauth/callback")
def oauth_callback():
    code = request.args.get("code")
    # Redirect URI taken from query — attacker can register alternate callback
    redirect_uri = request.args.get("redirect_uri", REDIRECT_URI)
    resp = requests.post(
        "https://idp.example.com/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": CLIENT_ID,
            "redirect_uri": redirect_uri,
        },
    )
    tokens = resp.json()
    # Tokens stored in server session without rotation or binding policy
    session["access_token"] = tokens["access_token"]
    session["refresh_token"] = tokens.get("refresh_token")
    return redirect("/dashboard")
```

## Step-by-Step Review Walkthrough

1. **Identify client type.** Public clients (SPA, mobile) must use authorization code with PKCE. Confidential servers may use client secret or mTLS at the token endpoint. Flag implicit or resource-owner password grants in user-facing apps.
2. **Trace the authorization request.** Confirm `response_type=code`, cryptographically random `state`, and for public clients a `code_challenge` derived from a verifier stored server-side or in secure session storage.
3. **Review redirect URI handling.** Registration must use exact match (scheme, host, port, path). Reject prefix-only checks and any callback that reads redirect URI from attacker-controlled input.
4. **Inspect the callback handler.** Validate `state` against the value issued at login start. Reject missing or mismatched state before token exchange. Log and fail closed on error responses from the IdP.
5. **Review token exchange.** Confidential clients must authenticate (`client_secret`, private_key_jwt, or mTLS). Authorization servers must verify PKCE `code_verifier` against the stored challenge for public clients.
6. **Follow token storage and use.** Access tokens belong in memory or HttpOnly cookies for browser apps. Refresh tokens need secure storage, rotation, and revocation on logout. Search logs and analytics for token leakage.
7. **Check logout and error paths.** Confirm tokens are cleared on logout and that OAuth errors do not skip validation steps or expose tokens in URLs.

## Risk Impact Analysis

**Account takeover.** Stolen authorization codes or refresh tokens let attackers obtain access tokens and act as the victim within granted scopes.

**Cross-site request forgery on login.** Missing or weak `state` allows an attacker to bind their IdP session to the victim's application account.

**Redirect manipulation.** Loose redirect URI validation enables code interception via open redirectors or look-alike registered URIs.

**Long-lived compromise.** Refresh tokens in localStorage or without rotation remain usable after XSS or device loss.

**Compliance and audit gaps.** Regulated apps must show OAuth flows align with provider guidance and industry baselines such as [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics).

## Vulnerable Examples in Other Languages

### Java

```java
@GetMapping("/oauth/callback")
public String callback(@RequestParam String code, @RequestParam(required = false) String state) {
    // state ignored — CSRF on account linking
    MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
    body.add("grant_type", "authorization_code");
    body.add("code", code);
    body.add("redirect_uri", "https://app.example.com/callback");
    // Public SPA using confidential-client pattern without PKCE
    OAuth2AccessToken token = restTemplate.postForObject(tokenUrl, body, OAuth2AccessToken.class);
    session.setAttribute("access_token", token.getValue());
    return "redirect:/home";
}
```

### C#

```csharp
[HttpGet("signin-oauth")]
public async Task<IActionResult> Callback(string code)
{
    var token = await httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["grant_type"] = "authorization_code",
        ["code"] = code,
        ["client_id"] = _config["OAuth:ClientId"],
        ["redirect_uri"] = Request.Query["returnUrl"], // attacker-controlled redirect
    }));
    var json = await token.Response.Content.ReadFromJsonAsync<TokenResponse>();
    Response.Cookies.Append("refresh_token", json.RefreshToken); // not HttpOnly
    return Redirect("/");
}
```

### JavaScript

```javascript
// SPA: implicit-style token in fragment or localStorage
function startLogin() {
  const url = `${AUTH}/authorize?response_type=token&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT}`;
  window.location = url;
}

function handleCallback() {
  const hash = new URLSearchParams(window.location.hash.slice(1));
  localStorage.setItem("access_token", hash.get("access_token"));
}
```

### Go

```go
func callback(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    // No state check; redirect URI built from Host header
    redirectURI := "https://" + r.Host + "/callback"
    resp, _ := http.PostForm(tokenURL, url.Values{
        "grant_type":   {"authorization_code"},
        "code":         {code},
        "client_id":    {clientID},
        "redirect_uri": {redirectURI},
    })
    var tok tokenResponse
    json.NewDecoder(resp.Body).Decode(&tok)
    http.SetCookie(w, &http.Cookie{Name: "access_token", Value: tok.AccessToken})
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use Authlib or a maintained OAuth client with PKCE and state built in. Keep client secrets server-side only.

```python
from authlib.integrations.flask_client import OAuth
import secrets
import hashlib
import base64

oauth = OAuth(app)
oauth.register(
    name="idp",
    client_id=os.environ["OAUTH_CLIENT_ID"],
    client_secret=os.environ["OAUTH_CLIENT_SECRET"],
    server_metadata_url="https://idp.example.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email"},
)

@app.route("/login")
def login():
    verifier = secrets.token_urlsafe(64)
    session["oauth_verifier"] = verifier
    session["oauth_state"] = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return oauth.idp.authorize_redirect(
        redirect_uri="https://app.example.com/oauth/callback",
        state=session["oauth_state"],
        code_challenge=challenge,
        code_challenge_method="S256",
    )

@app.route("/oauth/callback")
def oauth_callback():
    if request.args.get("state") != session.pop("oauth_state", None):
        abort(403)
    token = oauth.idp.authorize_access_token(code_verifier=session.pop("oauth_verifier"))
    session["access_token"] = token["access_token"]  # prefer server-side session only
    return redirect("/dashboard")
```

**Important:** Register one exact redirect URI per environment. Never expose `client_secret` in SPA or mobile binaries; use PKCE instead.

### Java

Use Spring Security OAuth2 Client with authorization code and PKCE for public clients.

```java
spring.security.oauth2.client.registration.idp.client-id=${OAUTH_CLIENT_ID}
spring.security.oauth2.client.registration.idp.client-secret=${OAUTH_CLIENT_SECRET}
spring.security.oauth2.client.registration.idp.authorization-grant-type=authorization_code
spring.security.oauth2.client.registration.idp.redirect-uri=https://app.example.com/login/oauth2/code/idp
spring.security.oauth2.client.registration.idp.scope=openid,profile
spring.security.oauth2.client.provider.idp.issuer-uri=https://idp.example.com
```

```java
http.oauth2Login(oauth -> oauth
    .authorizationEndpoint(auth -> auth.authorizationRequestResolver(pkceResolver))
    .successHandler((request, response, authentication) -> {
        OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
            "idp", authentication.getName());
        // Use token server-side; do not echo refresh token to browser
    }));
```

**Important:** Validate redirect URIs in the authorization server with exact match. Enable refresh token rotation when the provider supports it.

### C#

Use `AddOpenIdConnect` or `AddOAuth` with authorization code and PKCE for public clients.

```csharp
services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
})
.AddOpenIdConnect(options =>
{
    options.Authority = "https://idp.example.com";
    options.ClientId = Configuration["OAuth:ClientId"];
    options.ClientSecret = Configuration["OAuth:ClientSecret"];
    options.ResponseType = OpenIdConnectResponseType.Code;
    options.UsePkce = true;
    options.SaveTokens = true;
    options.CallbackPath = "/signin-oidc";
    options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
});
```

**Important:** `SaveTokens = true` stores tokens in the auth cookie payload—ensure cookie encryption and short lifetimes. Prefer downstream API calls from the server using token cache, not browser storage.

### Go

Use `golang.org/x/oauth2` with PKCE via `oauth2.GenerateVerifier` and `S256ChallengeFromVerifier`.

```go
import "golang.org/x/oauth2"

var oauthConfig = &oauth2.Config{
    ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
    ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
    RedirectURL:  "https://app.example.com/oauth/callback",
    Scopes:       []string{"openid", "profile"},
    Endpoint: oauth2.Endpoint{
        AuthURL:  "https://idp.example.com/oauth/authorize",
        TokenURL: "https://idp.example.com/oauth/token",
    },
}

func login(w http.ResponseWriter, r *http.Request) {
    state := secureRandomString(32)
    verifier := oauth2.GenerateVerifier()
    http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: state, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
    http.SetCookie(w, &http.Cookie{Name: "pkce_verifier", Value: verifier, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
    url := oauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
    http.Redirect(w, r, url, http.StatusFound)
}
```

**Important:** Read `state` and PKCE verifier from HttpOnly cookies on callback. Use `oauth2.ReuseTokenSource` with secure server-side storage for refresh tokens.

## Verify During Review

- Browser and mobile clients use **authorization code with PKCE**, not implicit grant or password grant.
- **Redirect URIs** are registered with exact match; callback handlers never trust client-supplied redirect values.
- **State** is generated per login, stored server-side, and validated before token exchange.
- Confidential clients **authenticate at the token endpoint**; public clients rely on PKCE, not embedded secrets.
- **Tokens** are not in URLs, localStorage, or logs; refresh tokens rotate and clear on logout.
- Token and authorize HTTP calls use **TLS with certificate verification** enabled.

## Reference

- [RFC 6749: OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7636: PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OAuth 2.0 for Browser-Based Apps](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)
- [OAuth.net — OAuth 2.0](https://oauth.net/2/)
- [OWASP OAuth 2.0 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- [Authlib documentation](https://docs.authlib.org/en/latest/)
- [Spring Security — OAuth2 Client](https://docs.spring.io/spring-security/reference/servlet/oauth2/client/index.html)
- [ASP.NET Core — OpenID Connect](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/openid-connect)
- [golang.org/x/oauth2](https://pkg.go.dev/golang.org/x/oauth2)

## OpenID Connect {: #oidc }

From former `10-02-review-oidc-implementation.md`. **Guiding chapter section:** [5.1 - Review Identity and Federation § OpenID Connect](../../5-01-review-identity-and-federation.md#oidc).

## 5.2 - Review OpenID Connect Implementation

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

## SAML federation {: #saml }

From former `10-04-review-saml-federation.md`. **Guiding chapter section:** [5.1 - Review Identity and Federation § SAML federation](../../5-01-review-identity-and-federation.md#saml).

## 5.4 - Review SAML Federation

SAML federation lets enterprises sign in through an Identity Provider (IdP). Review Service Provider (SP) endpoints, metadata exchange, and assertion processing code. Confirm signatures are verified with trusted keys, ACS URLs are bound, assertions are replay-protected, and metadata is authenticated before trust is granted.

## What This Topic Is

This chapter is about **implementation review**, not generic vulnerability hunting. SAML security depends on XML signature validation, strict endpoint binding, and one-time use of assertions—not on trusting decoded XML fields after parsing.

The unsafe assumption is that a POST to the Assertion Consumer Service (ACS) URL contains a legitimate IdP response because it arrived over HTTPS. Attackers can forge assertions, replay captured responses, or swap metadata if signature verification and recipient checks are skipped.

This relates to [CWE-347](https://cwe.mitre.org/data/definitions/347.html) and [CWE-294](https://cwe.mitre.org/data/definitions/294.html) (Authentication Bypass by Capture-replay).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Enterprise SSO, B2B federation, legacy Java/.NET portals, cloud app SAML connectors |
| **Signature validation** | `wantAssertionsSigned` false, signature optional, verify response but not assertion |
| **Certificate trust** | IdP cert embedded without expiry check, metadata fetched over HTTP, thumbprint string match only |
| **ACS URL / Recipient** | Missing `Recipient`/`Destination` validation, dynamic ACS from request param, wildcard ACS in metadata |
| **Replay controls** | No `InResponseTo` check, assertion ID not tracked, clock skew unbounded |
| **Conditions** | `NotOnOrAfter` ignored, `AudienceRestriction` missing or not matched to SP entity ID |
| **XML processing** | XXE-enabled parsers, external DTD allowed—see [4.3 Review Parsers § XXE](4-03-review-parsers-and-unsafe-reconstitution.md#xxe) |
| **Metadata exchange** | Unsigned metadata trusted, SP uploads attacker IdP metadata in self-service config |

## Abuse Scenarios

Use these when reviewing SAML SP endpoints, metadata upload flows, and assertion processing.

### Scenario 1: Unsigned assertion acceptance

The SP parses SAML XML and extracts `NameID` without XML signature validation. An attacker POSTs a crafted `SAMLResponse` to the ACS URL and logs in as any user.

### Scenario 2: Assertion replay

A captured legitimate `SAMLResponse` is replayed within `NotOnOrAfter`. The SP does not track assertion IDs or `InResponseTo`, so the same response grants access repeatedly or on another victim session.

### Scenario 3: Wrong recipient / ACS URL

The SP accepts assertions whose `Destination` or `Recipient` does not match the registered ACS URL. Attacker replays assertions intended for a different SP instance or environment.

### Scenario 4: Audience mismatch ignored

`AudienceRestriction` is missing or not compared to SP entity ID. Assertions minted for a staging SP work against production.

### Scenario 5: Malicious IdP metadata import

Self-service tenant onboarding accepts arbitrary metadata URLs. Attacker supplies metadata pointing to attacker IdP; users authenticate against attacker-controlled keys.

### Scenario 6: Open redirect via RelayState

After login, the SP redirects to unvalidated `RelayState`. Attacker phishes victims through a trusted domain to an external site or steals tokens from URL parameters.

## Language-Specific Libraries and Dangerous Patterns

### Python

```python
# Dangerous: manual XML parse without signature
name_id = parse_nameid_from_xml(base64.b64decode(SAMLResponse))

# Safer: python3-saml with strict settings
from onelogin.saml2.auth import OneLogin_Saml2_Auth
auth = OneLogin_Saml2_Auth(request_data, old_settings=settings)
auth.process_response()
if not auth.is_authenticated() or auth.get_errors():
    abort(403)
```

Settings must include `strict: True`, `wantAssertionsSigned: True`, and trusted IdP cert from reviewed metadata.

### Java

```java
// Dangerous: DOM parse NameID only
DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(stream);

// Safer: Spring Security SAML2 Service Provider
http.saml2Login(Customizer.withDefaults());
// RelyingPartyRegistration.fromMetadataLocation(...).entityId(...).assertionConsumerServiceLocation(...)
```

Also review: OpenSAML low-level usage without validation, Pac4j `SAML2Client` misconfiguration, Shibboleth SP `MetadataProvider` accepting unsigned metadata.

### C#

```csharp
// Dangerous
var response = new Response(SAMLResponse);  // validate: false
var nameId = response.GetNameID();

// Safer: ITfoxtec.Identity.Saml2
var saml2AuthnResponse = new Saml2AuthnResponse(config);
saml2AuthnResponse.ReadSamlResponse(Request, validate: true);
```

Also review: `Sustainsys.Saml2`, Azure AD SAML integration defaults.

### JavaScript

```javascript
// Dangerous: regex extract NameID
const nameID = xml.match(/<NameID[^>]*>([^<]+)<\/NameID>/)[1];

// Safer: @node-saml/node-saml or samlify with cert and audience checks
const { SAML } = require('@node-saml/node-saml');
const profile = await saml.validatePostResponseAsync(body);
```

### Go

```go
// Dangerous
nameID := xmlquery.FindOne(doc, "//NameID").InnerText()

// Safer: crewjam/saml
assertion, err := sp.ParseResponse(r, []string{pendingAuthnRequestID})
```

See [OneLogin python3-saml](https://github.com/SAML-Toolkits/python3-saml), [Spring Security SAML2](https://docs.spring.io/spring-security/reference/servlet/saml2/login/index.html), [ITfoxtec.Identity.Saml2](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2), and [crewjam/saml](https://github.com/crewjam/saml).

## Sample Vulnerable Code in Python

```python
from flask import Flask, request, redirect, session
from onelogin.saml2.auth import OneLogin_Saml2_Auth
import base64

app = Flask(__name__)

@app.route("/saml/acs", methods=["POST"])
def saml_acs():
    saml_response = request.form["SAMLResponse"]
    xml = base64.b64decode(saml_response)
    # Parser extracts NameID without verifying assertion signature
    name_id = parse_nameid_from_xml(xml)
    # Recipient, Audience, NotOnOrAfter, InResponseTo not enforced
    session["user"] = name_id
    relay = request.form.get("RelayState", "/")
    return redirect(relay)  # open redirect via unchecked RelayState

def prepare_saml_request(req):
    return {
        "http_host": req.host,
        "script_name": req.path,
        "post_data": req.form,
        "get_data": req.args,
    }

@app.route("/saml/metadata")
def sp_metadata():
    # SP accepts any IdP metadata URL supplied by tenant admin without signature check
    idp_metadata_url = request.args["metadata"]
    load_idp_from_url(idp_metadata_url)
    return "ok"
```

## Step-by-Step Review Walkthrough

1. **Map SP and IdP roles.** Locate metadata files, ACS endpoints, single logout URLs, and libraries (OneLogin python3-saml, Spring SAML, ITfoxtec, etc.).
2. **Verify assertion signatures.** Require signed assertions (or signed outer response with signed assertion). Validate with IdP certificate from trusted metadata, including expiry and key rollover.
3. **Validate ACS binding.** Confirm `Destination` and `Recipient` match the registered ACS URL exactly. Reject assertions POSTed to alternate paths or hosts.
4. **Check replay defenses.** Store used assertion IDs (`ID` attribute) for at least the assertion validity window. Validate `InResponseTo` against the outstanding AuthnRequest ID when SP-initiated.
5. **Inspect conditions.** Enforce `NotBefore`/`NotOnOrAfter` with modest clock skew. Require `AudienceRestriction` containing the SP entity ID.
6. **Review metadata trust.** Metadata should load from configured URLs or signed bundles—not arbitrary user URLs without review. Plan certificate rollover using metadata refresh.
7. **Harden XML parsing.** Disable DTDs and external entities on SAML parsers. Review RelayState allowlists to block open redirects after login.

## Risk Impact Analysis

**Authentication bypass.** Accepting unsigned or wrongly signed assertions lets attackers craft arbitrary NameIDs and attribute statements.

**Assertion replay.** Captured SAML responses reused within validity windows grant access without fresh IdP authentication.

**Wrong IdP trust.** Untrusted metadata imports route logins to attacker-controlled IdPs that mint valid-looking assertions for their keys.

**Account linking errors.** Weak NameID policy (`EmailAddress` without confirmation) may merge attacker IdP identities with victim accounts.

**XML-side attacks.** Unsafe parsers may expose server files or SSRF via XXE before signature logic runs.

## Vulnerable Examples in Other Languages

### Java

```java
@PostMapping("/saml/SSO")
public ResponseEntity<?> acs(@RequestParam String SAMLResponse) {
    byte[] decoded = Base64.getDecoder().decode(SAMLResponse);
    Element root = DocumentBuilderFactory.newInstance()
        .newDocumentBuilder()
        .parse(new ByteArrayInputStream(decoded))
        .getDocumentElement();
    // No XML signature validation
    String nameId = root.getElementsByTagName("NameID").item(0).getTextContent();
    securityContext.setUser(nameId);
    return ResponseEntity.status(302).header("Location", "/").build();
}
```

### C#

```csharp
[HttpPost("sso")]
public IActionResult Sso([FromForm] string SAMLResponse)
{
    var response = new Response(SAMLResponse);
    // Signature validation disabled in config
    var nameId = response.GetNameID();
    await SignInAsync(nameId);
    return Redirect(Request.Form["RelayState"].ToString());
}
```

### JavaScript

```javascript
// Node SP using simplified parser
app.post("/saml/consume", (req, res) => {
  const xml = Buffer.from(req.body.SAMLResponse, "base64").toString("utf8");
  const nameID = xml.match(/<NameID[^>]*>([^<]+)<\/NameID>/)[1];
  req.session.user = nameID;
  res.redirect(req.body.RelayState || "/");
});
```

### Go

```go
func acs(w http.ResponseWriter, r *http.Request) {
    samlResp := r.FormValue("SAMLResponse")
    doc, _ := xmlquery.Parse(strings.NewReader(decode(samlResp)))
    nameID := xmlquery.FindOne(doc, "//NameID").InnerText()
    // Signature, Audience, Recipient not verified
    setSession(w, nameID)
    http.Redirect(w, r, r.FormValue("RelayState"), http.StatusFound)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use `python3-saml` with strict settings and explicit security flags.

```python
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

settings = {
    "strict": True,
    "security": {
        "wantAssertionsSigned": True,
        "wantMessagesSigned": True,
        "rejectDeprecatedAlgorithm": True,
        "allowRepeatAttributeName": False,
    },
    "sp": {
        "entityId": "https://app.example.com/saml/metadata",
        "assertionConsumerService": {
            "url": "https://app.example.com/saml/acs",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
    },
    "idp": {
        "entityId": "https://idp.example.com/metadata",
        "singleSignOnService": {"url": "https://idp.example.com/sso", "binding": "..."},
        "x509cert": IDP_CERT_PEM,
    },
}

@app.route("/saml/acs", methods=["POST"])
def saml_acs():
    auth = OneLogin_Saml2_Auth(prepare_request(request), old_settings=settings)
    auth.process_response()
    errors = auth.get_errors()
    if errors or not auth.is_authenticated():
        abort(403)
    if not auth.validate_timestamps():
        abort(403)
    assertion_id = auth.get_last_assertion_id()
    if replay_cache.seen(assertion_id):
        abort(403)
    replay_cache.remember(assertion_id, ttl=300)
    session["user"] = auth.get_nameid()
    return redirect(safe_relay_state(request.form.get("RelayState")))
```

**Important:** Keep `strict: True`. Load IdP certificates from reviewed metadata; refresh before expiry. Allowlist RelayState targets.

### Java

Use Spring Security SAML2 Service Provider with verified relying party registration.

```java
@Bean
RelyingPartyRegistrationRepository registrations() {
    Saml2MetadataResolver resolver = new Saml2MetadataResolver(
        "https://idp.example.com/metadata/saml2");
    RelyingPartyRegistration registration = RelyingPartyRegistrations
        .fromMetadataLocation("https://idp.example.com/metadata/saml2")
        .registrationId("corp-idp")
        .entityId("https://app.example.com/saml/metadata")
        .assertionConsumerServiceLocation("https://app.example.com/login/saml2/sso/corp-idp")
        .build();
    return new InMemoryRelyingPartyRegistrationRepository(registration);
}

http.saml2Login(saml -> saml
    .loginProcessingUrl("/login/saml2/sso/{registrationId}")
    .successHandler(validatedRelayStateHandler()));
```

**Important:** Spring validates signatures and audience by default when correctly configured. Do not replace with manual DOM parsing.

### C#

Use ITfoxtec Identity SAML2 with signature validation enabled.

```csharp
var config = new Saml2Configuration
{
    Issuer = "https://app.example.com/saml/metadata",
    AllowedAudienceUris = { "https://app.example.com/saml/metadata" },
    CertificateValidationMode = X509CertificateValidationMode.ChainTrust,
    SignatureAlgorithm = Saml2SecurityAlgorithms.RsaSha256Signature,
};

config.AllowedIssuer = "https://idp.example.com/metadata";
config.SignatureValidationCertificates.Add(idpCert);

var saml2AuthnResponse = new Saml2AuthnResponse(config);
saml2AuthnResponse.ReadSamlResponse(Request, validate: true);
if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
    throw new AuthenticationException("SAML auth failed");
var claims = saml2AuthnResponse.CreateClaimsIdentity(config);
await SignInAsync(new ClaimsPrincipal(claims));
```

**Important:** Set `validate: true` on read paths. Store consumed assertion IDs in cache with TTL matching `NotOnOrAfter`.

### Go

Use `crewjam/saml` with SP struct fields and built-in validation.

```go
import "github.com/crewjam/saml"

sp := &saml.ServiceProvider{
    EntityID:    "https://app.example.com/saml/metadata",
    Key:         spKey,
    Certificate: spCert,
    IDPMetadata: idpMetadata,
    AcsURL:      mustParseURL("https://app.example.com/saml/acs"),
    MetadataURL: mustParseURL("https://app.example.com/saml/metadata"),
}

func acs(w http.ResponseWriter, r *http.Request) {
    err := r.ParseForm()
    assertion, err := sp.ParseResponse(r, []string{pendingRequestID})
    if err != nil {
        http.Error(w, "invalid SAML response", http.StatusForbidden)
        return
    }
    if replayCache.Exists(assertion.ID) {
        http.Error(w, "replay detected", http.StatusForbidden)
        return
    }
    replayCache.Add(assertion.ID, assertion.NotOnOrAfter)
    setSession(w, assertion.Subject.NameID.Value)
}
```

**Important:** `ParseResponse` validates signature, destination, and timing when IdP metadata is correct. Track SP-initiated request IDs and enforce them with `InResponseTo`.

## Verify During Review

- Assertions (or outer responses) are **XML signature validated** with current IdP keys from trusted metadata.
- **ACS URL, Destination, and Recipient** match registered SP endpoints exactly.
- **Assertion IDs** are single-use; **InResponseTo** matches outstanding AuthnRequest when applicable.
- **Audience** equals SP entity ID; **NotBefore/NotOnOrAfter** enforced with bounded clock skew.
- IdP metadata and certificates come from **trusted sources** with rollover planned before expiry.
- SAML parsers disable **XXE**; **RelayState** is allowlisted.

## Reference

- [OASIS SAML 2.0 Core](http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [OASIS SAML 2.0 Bindings](http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
- [OASIS SAML 2.0 Metadata](http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)
- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OneLogin python3-saml](https://github.com/SAML-Toolkits/python3-saml)
- [Spring Security — SAML2 Service Provider](https://docs.spring.io/spring-security/reference/servlet/saml2/login/index.html)
- [ITfoxtec Identity SAML2](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2)
- [crewjam/saml](https://github.com/crewjam/saml)

