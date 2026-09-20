---
title: Review Identity and Federation
keywords:
  - oauth
  - oidc
  - saml
  - federation
  - pkce
description: Review OAuth 2.0, OpenID Connect, and SAML as one federation family.
---

## 5.1 - Review Identity and Federation

### Overview

Identity and federation bugs share one question: can an attacker hijack the redirect or assertion path and become another user? Review redirect URI binding, CSRF/`state`/`nonce`, client authentication, signature and audience checks, and token storage—not only whether a library call exists.

The points below are the ideas this family chapter uses again and again.

1. Federation bugs ask whether an attacker can hijack redirect or assertion paths and become another user.
2. Review redirect URI binding, state/nonce, client authentication, and assertion signature/audience checks.
3. OAuth, OIDC, and SAML share that trust decision with different ceremonies.
4. Token storage and client secrets stay server-side except for public-client PKCE flows.
5. Evidence names the protocol step, missing control, impact, and a proving test.

After reading this chapter, we should be able to review OAuth, OIDC, and SAML implementations against shared federation checks.

## Shared Review Model

Across every variant below, keep the same evidence habit: name the **protocol step or credential**, the **trust decision**, the **missing control**, the **impact**, and a **test** that would prove a fix.

## Variants in This Family

### OAuth 2.0 {: #oauth }

This chapter is about **implementation review**, not generic vulnerability hunting. You are checking whether the OAuth flow matches [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) and current best practice for the client type (public vs confidential).

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Social login, "Sign in with …", API integrations, mobile deep links, SPA auth |
| **Flow choice** | Implicit or password grant in browser apps; auth code without PKCE for public clients |
| **Redirect URI** | String prefix match, wildcard hosts, user-controlled redirect params, missing exact registration |
| **State / CSRF** | Missing `state`, static state, state not validated on callback, state stored only client-side without binding |
| **Token endpoint** | Missing `client_secret` or mTLS for confidential clients; PKCE verifier not checked server-side |
| **Token storage** | Access or refresh tokens in localStorage, query strings, logs, or non-HttpOnly cookies |
| **Library config** | Custom OAuth glue, disabled TLS verify on token requests, hardcoded client secrets in frontend bundles |

**Appendix detail:** [OAuth 2.0 reference](appendix/secure-implementations-reference/5-01-review-identity-and-federation.md#oauth).

### OpenID Connect {: #oidc }

This chapter is about **implementation review**, not generic vulnerability hunting. OIDC login is correct only when your code validates the `id_token` as a signed JWT from the expected issuer and rejects tokens meant for another client.

**Where to look**

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

**Appendix detail:** [OpenID Connect reference](appendix/secure-implementations-reference/5-01-review-identity-and-federation.md#oidc).

### SAML federation {: #saml }

This chapter is about **implementation review**, not generic vulnerability hunting. SAML security depends on XML signature validation, strict endpoint binding, and one-time use of assertions—not on trusting decoded XML fields after parsing.

**Where to look**

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

**Appendix detail:** [SAML federation reference](appendix/secure-implementations-reference/5-01-review-identity-and-federation.md#saml).

## Worked Example (OAuth 2.0)

We walk **OAuth 2.0** in depth. Apply the same tracing steps to the other variants, adjusting protocol steps and sinks from the tables above.

### Sample vulnerable code (Python)

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

### Step-by-step review walkthrough

1. **Identify client type.** Public clients (SPA, mobile) must use authorization code with PKCE. Confidential servers may use client secret or mTLS at the token endpoint. Flag implicit or resource-owner password grants in user-facing apps.
2. **Trace the authorization request.** Confirm `response_type=code`, cryptographically random `state`, and for public clients a `code_challenge` derived from a verifier stored server-side or in secure session storage.
3. **Review redirect URI handling.** Registration must use exact match (scheme, host, port, path). Reject prefix-only checks and any callback that reads redirect URI from attacker-controlled input.
4. **Inspect the callback handler.** Validate `state` against the value issued at login start. Reject missing or mismatched state before token exchange. Log and fail closed on error responses from the IdP.
5. **Review token exchange.** Confidential clients must authenticate (`client_secret`, private_key_jwt, or mTLS). Authorization servers must verify PKCE `code_verifier` against the stored challenge for public clients.
6. **Follow token storage and use.** Access tokens belong in memory or HttpOnly cookies for browser apps. Refresh tokens need secure storage, rotation, and revocation on logout. Search logs and analytics for token leakage.
7. **Check logout and error paths.** Confirm tokens are cleared on logout and that OAuth errors do not skip validation steps or expose tokens in URLs.

## Risk Impact (Family)

**Account takeover.** Stolen authorization codes or refresh tokens let attackers obtain access tokens and act as the victim within granted scopes.

**Cross-site request forgery on login.** Missing or weak `state` allows an attacker to bind their IdP session to the victim's application account.

**Redirect manipulation.** Loose redirect URI validation enables code interception via open redirectors or look-alike registered URIs.

**Long-lived compromise.** Refresh tokens in localStorage or without rotation remain usable after XSS or device loss.

**Compliance and audit gaps.** Regulated apps must show OAuth flows align with provider guidance and industry baselines such as [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics).

## Fix Principles

Primary safer patterns for the worked example follow. For other languages and variant-specific fixes, use the [family appendix](appendix/secure-implementations-reference/5-01-review-identity-and-federation.md).

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

Use the checklist below as a family-level pass over the variants above. Each item should map to evidence in the change under review.

- Browser and mobile clients use **authorization code with PKCE**, not implicit grant or password grant.
- **Redirect URIs** are registered with exact match; callback handlers never trust client-supplied redirect values.
- **State** is generated per login, stored server-side, and validated before token exchange.
- Confidential clients **authenticate at the token endpoint**; public clients rely on PKCE, not embedded secrets.
- **Tokens** are not in URLs, localStorage, or logs; refresh tokens rotate and clear on logout.
- Token and authorize HTTP calls use **TLS with certificate verification** enabled.
- Client loads **issuer metadata** from `.well-known/openid-configuration` with TLS verification.
- Every login validates **id_token signature**, `iss`, `aud`, `exp`, and **nonce** before creating a session.
- **`sub` + `iss`** is the external identity key; verified claims drive authorization, not raw callback parameters.
- **UserInfo** is optional enrichment; it does not replace id_token validation.
- Public clients use **code flow + PKCE**; tokens are not accepted from URL fragments without strict validation.
- Multi-tenant apps enforce an **issuer allowlist** per tenant or registration.
- Assertions (or outer responses) are **XML signature validated** with current IdP keys from trusted metadata.
- **ACS URL, Destination, and Recipient** match registered SP endpoints exactly.
- **Assertion IDs** are single-use; **InResponseTo** matches outstanding AuthnRequest when applicable.
- **Audience** equals SP entity ID; **NotBefore/NotOnOrAfter** enforced with bounded clock skew.
- IdP metadata and certificates come from **trusted sources** with rollover planned before expiry.
- SAML parsers disable **XXE**; **RelayState** is allowlisted.

## Implementation Reference (Appendix)

Library sinks, multi-language examples, and full fix catalogs for every variant live in **[5.1 reference — Review Identity and Federation](appendix/secure-implementations-reference/5-01-review-identity-and-federation.md)**.

## Reference

- Appendix — [5.1 reference](appendix/secure-implementations-reference/5-01-review-identity-and-federation.md)

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
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 7519: JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519)
- [OAuth.net — OpenID Connect](https://oauth.net/2/openid-connect/)
- [python-jose documentation](https://python-jose.readthedocs.io/)
- [openid-client (Node.js)](https://github.com/panva/node-openid-client)
- [Microsoft Identity Web](https://learn.microsoft.com/en-us/entra/msal/dotnet/microsoft-identity-web/)
- [Spring Security — OAuth2 Login](https://docs.spring.io/spring-security/reference/servlet/oauth2/login/index.html)
- [coreos/go-oidc](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc)
- [OASIS SAML 2.0 Core](http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [OASIS SAML 2.0 Bindings](http://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
- [OASIS SAML 2.0 Metadata](http://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)
- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OneLogin python3-saml](https://github.com/SAML-Toolkits/python3-saml)
- [Spring Security — SAML2 Service Provider](https://docs.spring.io/spring-security/reference/servlet/saml2/login/index.html)
- [ITfoxtec Identity SAML2](https://github.com/ITfoxtec/ITfoxtec.Identity.Saml2)
- [crewjam/saml](https://github.com/crewjam/saml)
