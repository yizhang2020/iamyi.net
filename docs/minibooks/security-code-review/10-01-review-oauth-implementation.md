---
title: Review OAuth 2.0 Implementation
keywords:
  - security code review
  - oauth 2.0
  - authorization code
  - pkce
  - redirect uri
  - state parameter
description: How to review OAuth 2.0 client and server code for authorization code with PKCE, redirect URI binding, state, client authentication, and token storage.
---

## 10.1 - Review OAuth 2.0 Implementation

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
