---
title: Review Secrets, Defaults, and Dangerous APIs
keywords:
  - hardcoded secrets
  - dangerous functions
  - secure defaults
  - client-side validation
description: Review secrets, obsolete code, dangerous APIs, framework defaults, and client-only validation.
---

## 4.9 - Review Secrets, Defaults, and Dangerous APIs

### Overview

These patterns are foot-guns and misplaced trust: secrets in source, obsolete APIs, dangerous primitives, weak framework defaults, and validation that exists only in the browser. Hunt for them as inventory passes, then prove impact.

The points below are the ideas this family chapter uses again and again.

1. Secrets in source, dangerous dynamic APIs, weak defaults, and client-only validation expand blast radius.
2. Prefer secret stores, safe APIs, and secure framework defaults.
3. Client validation is UX; server enforcement is the control.
4. Related variants share misplaced trust in code, config, or the browser.
5. Evidence names the secret or API, missing control, impact, and a proving test.

After reading this chapter, we should be able to find hardcoded secrets, dangerous APIs, weak defaults, and client-only validation with shared habits.

## Shared Review Model

Across every variant below, keep the same evidence habit: name the **source**, the **sink**, the **missing control**, the **impact**, and a **test** that would prove a fix.

## Variants in This Family

### Hardcoded secrets {: #secrets }

Hardcoded secrets are credentials or cryptographic material stored in source code instead of a secret manager or environment configuration. Anyone with repository access—or an attacker who extracts strings from a binary or container image—may recover them. Hardcoded authentication bypasses are especially dangerous because they often survive code review as "temporary" test hooks.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login handlers, API gateways, third-party SDK init, mobile app config, CI/CD scripts |
| **Input entry** | Password verification, header API-key checks, webhook signature validation |
| **Static fields** | `const`, `private static final`, module-level variables, `.env.example` with real values |
| **Bypass branches** | `if (password.equals("..."))` alongside bcrypt checks, debug flags in production paths |
| **Crypto material** | AES keys, HMAC secrets, JWT signing keys, PEM blocks committed to git |
| **Connection strings** | JDBC, MongoDB, Redis, SMTP URLs with embedded usernames and passwords |
| **Client exposure** | JavaScript bundles, mobile source, public config endpoints shipping server keys |

**Appendix detail:** [Hardcoded secrets code reference](appendix/code-level-reference/4-09-review-secrets-defaults-and-dangerous-apis.md#secrets).

### Dangerous functions {: #dangerous-functions }

Some language and platform APIs execute arbitrary code or commands when passed a string. `eval()` in JavaScript and Python, `Function()` constructors, script engines, and shell invocation with concatenated arguments are common examples. When attacker-controlled data reaches these functions, the impact is often full code execution in the application's process context.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Formula evaluators, rule engines, admin scripting, plugin loaders, template logic |
| **Dynamic execution** | `eval`, `exec`, `compile`, `Function(`, `setTimeout` with string arguments |
| **Shell invocation** | `subprocess` with `shell=True`, `/bin/sh -c`, `Runtime.exec` with concatenated commands |
| **Reflection** | `Class.forName`, `importlib`, user-controlled method or class names at runtime |
| **Plugin loading** | JARs, `.so` files, or scripts loaded from user-upload paths |
| **Template logic** | Jinja2 unsafe extensions, Velocity user templates, server-side scriptlets |
| **Deserialization overlap** | Native object deserialization treated as dynamic instantiation (see deserialization chapter) |

**Appendix detail:** [Dangerous functions code reference](appendix/code-level-reference/4-09-review-secrets-defaults-and-dangerous-apis.md#dangerous-functions).

### Obsolete code {: #obsolete }

Dead code, test hooks, and outdated modules often linger after refactors. Some paths are still reachable through direct URLs, old API versions, or feature toggles left enabled. Obsolete authentication helpers, deprecated encryption routines, and temporary admin endpoints may lack the hardening applied to newer code. Attackers probe forgotten routes; insiders may know URLs that documentation no longer mentions.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Legacy login routes, old API versions (`/v0/`, `/v1/`), debug endpoints, profiling handlers |
| **Test artifacts** | Hardcoded users, mock payment flows, QA bypasses without environment gating |
| **Feature flags** | Toggles defaulting to on, experiments never removed, alternate upload paths |
| **Deprecated handlers** | `@Deprecated` controllers, duplicate login implementations, pre-refactor validation |
| **Commented blocks** | Disabled auth checks left in comments, large duplicated logic with weaker controls |
| **Build gaps** | Debug controllers in Release builds, test packages bundled into production JARs |
| **Static analysis hits** | Unreferenced methods, unreachable branches flagged by coverage or linters |

**Appendix detail:** [Obsolete code code reference](appendix/code-level-reference/4-09-review-secrets-defaults-and-dangerous-apis.md#obsolete).

### Framework secure defaults {: #defaults }

Secure by default means the standard configuration is safe without extra steps. Web frameworks often provide CSRF middleware, template auto-escaping, secure session cookies, and parameterized data access. Teams can undermine these benefits with `DEBUG=True`, disabled CSRF, raw template modes, or secrets in source control.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Config surfaces** | `settings.py`, `application.yml`, `appsettings.json`, `config/environments/*.rb`, Express `app.js` |
| **Debug in prod** | `DEBUG=True`, `app.debug`, verbose stack traces, Werkzeug debugger exposed |
| **CSRF disabled** | `@csrf_exempt`, `csrf().disable()`, missing CSRF on cookie-auth forms |
| **Raw output** | `\|safe`, `th:utext`, `@Html.Raw` on user-controlled model fields |
| **Cookie flags** | Missing `Secure`, `HttpOnly`, `SameSite` on session identifiers |
| **Hardcoded secrets** | `SECRET_KEY`, JWT secrets, DB passwords committed in config files |

**Appendix detail:** [Framework secure defaults code reference](appendix/code-level-reference/4-09-review-secrets-defaults-and-dangerous-apis.md#defaults).

### Client-side validation {: #client-validation }

Missing server-side validation is a business logic and input-trust flaw. Browsers can enforce `pattern`, `required`, `maxlength`, and JavaScript checks for user experience. Attackers bypass these controls with modified requests, custom HTTP clients, or browser devtools.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Checkout, registration, transfers, profile update, admin forms, SPA JSON APIs |
| **Client-only guards** | HTML5 `pattern`, `min`, `max`, `required`; React/Vue validators with no server mirror |
| **Hidden/trusted fields** | `role`, `price`, `userId`, `discount` in POST bodies accepted without server recomputation |
| **API parity gaps** | Mobile and third-party callers hit endpoints with weaker validation than the web UI |
| **Missing server libs** | Handlers with no Bean Validation, Pydantic, FluentValidation, or Go validator tags |
| **Partial persistence** | Invalid input rejected in UI but partially saved when API calls skip validation |

**Appendix detail:** [Client-side validation code reference](appendix/code-level-reference/4-09-review-secrets-defaults-and-dangerous-apis.md#client-validation).

### Insecure coding practice {: #insecure-practice }

These flaws come from convenience shortcuts, copy-pasted samples, or framework defaults left unchanged. The application still “uses HTTPS” or “uses JWT,” but the code does not actually validate the peer, token, or cookie the way the design assumes.

**Where to look**

| Pattern | Where to look | Red flags |
| --- | --- | --- |
| **TLS / HTTPS verification disabled** | `requests.get(..., verify=False)`, custom `TrustManager` that accepts all certs, `NODE_TLS_REJECT_UNAUTHORIZED=0`, gRPC/HTTP clients with insecure channel creds | Comments like “fix cert later,” test code shipped to prod |
| **JWT signature / key mishandling** | `get_unverified_claims`, hardcoded HMAC secrets, accepting `alg: none`, JWKS without issuer/audience checks | Auth middleware that trusts base64 payload segments |
| **Insecure HTTP cookie flags** | `set_cookie` without `httponly`/`secure`/`samesite`, legacy servlet cookies, framework session defaults | Session ID in URL, year-long `Max-Age`, logout that only clears client cookie |
| **Hardcoded secrets** (related) | API keys, DB passwords, signing keys in source | See [4.9 § Hardcoded secrets](4-09-review-secrets-defaults-and-dangerous-apis.md#secrets) |
| **Weak or custom crypto** (related) | MD5 passwords, home-grown AES, mixed hash/encrypt | See [4.8 Review Cryptography in Application Code § Cryptographic implementation](4-08-review-cryptography-in-application-code.md#implementation), [4.8 Review Cryptography in Application Code § Non-standard crypto practices](4-08-review-cryptography-in-application-code.md#non-standard), [4.8 Review Cryptography in Application Code § Encryption and decryption mistakes](4-08-review-cryptography-in-application-code.md#enc-dec) |
| **Dangerous dynamic execution** (related) | `eval`, `exec`, script engines on user input | See [4.9 § Dangerous functions](4-09-review-secrets-defaults-and-dangerous-apis.md#dangerous-functions) |
| **Sensitive data in logs or URLs** (related) | Tokens/passwords in logs, credentials in GET | See [4.7 Review Information Disclosure and Logging § Sensitive data in URL](4-07-review-information-disclosure-and-logging.md#url-data), [4.7 Review Information Disclosure and Logging § Sensitive logging](4-07-review-information-disclosure-and-logging.md#sensitive-logging) |
| **Secrets in comments** (related) | Password hints in HTML/JS comments | See [4.7 § Sensitive code comments](4-07-review-information-disclosure-and-logging.md#comments) |
| **Insecure deserialization** (related) | `pickle.loads` on untrusted bytes | See [4.3 § Insecure deserialization](4-03-review-parsers-and-unsafe-reconstitution.md#deserialization) |
| **Framework defaults left weak** (related) | DEBUG=True, permissive CORS, CSRF off | See [4.9 § Framework secure defaults](4-09-review-secrets-defaults-and-dangerous-apis.md#defaults) |

**Suggested additions for the same review pass:** debug endpoints left enabled in production, permissive CORS with credentials, missing CSRF on state-changing cookie auth ([4.5 Review Authentication, Session, and Access Control § CSRF](4-05-review-authentication-session-and-access.md#csrf)), trust-all proxy headers without validation, and disabling security headers (CSP, HSTS) at the edge.

**Appendix detail:** [Insecure coding practice code reference](appendix/code-level-reference/4-09-review-secrets-defaults-and-dangerous-apis.md#insecure-practice).

## Worked Example (Hardcoded secrets)

We walk **Hardcoded secrets** in depth. Apply the same tracing steps to the other variants, adjusting sources and sinks from the tables above.

### Sample vulnerable code (Python)

```python
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

@app.route("/admin/sync")
def admin_sync():
    api_key = request.headers.get("X-API-Key")
    # Hardcoded bypass key grants admin access without user authentication
    if api_key == "nightly-etl-bypass-7k9m":
        return admin_dashboard()
    return "", 403

def sign_token(payload: dict) -> str:
    # JWT signing key embedded in source — cannot rotate without redeploy
    return jwt.encode(payload, "prod-jwt-hmac-static-v3", algorithm="HS256")
```

### Step-by-step review walkthrough

1. **Search authentication checks.** Look for `equals`, `==`, or `compare` against user-supplied passwords or API keys with string literals on either side.
2. **Inspect constants and config modules.** Read `config.py`, `.env` files in git, and `settings.py` for API keys, connection strings, and OAuth client secrets.
3. **Review bypass branches.** Flag OR conditions on password verification that accept a fixed string alongside normal hash checks.
4. **Trace encryption and signing.** Follow JWT, HMAC, and field-encryption code for hardcoded keys, IVs, and salts instead of key-management services.
5. **Check client-side code.** Mobile apps and front-end bundles must not ship server secrets; only public identifiers belong in client code.
6. **Follow third-party SDK initialization.** Stripe, Twilio, and cloud SDK calls often hide inline keys in setup blocks.
7. **Confirm CI/CD injects secrets at runtime.** Dockerfiles, Helm charts, and Terraform in git should reference secret names, not literal values.

## Risk Impact (Family)

**Authentication bypass.** Hardcoded backdoor passwords or API keys let attackers skip normal credential checks entirely.

**Credential theft and replay.** Keys in source propagate to forks, backups, and decompiled binaries; stolen keys work until manual rotation.

**Cloud and data exposure.** Embedded AWS or database credentials may grant broad infrastructure access beyond the application tier.

**Compliance and audit failure.** Regulators and customers expect secrets in vaults with rotation logs; hardcoded values fail basic control reviews.

**Incident response delay.** When a key leaks, teams must redeploy code instead of rotating a secret in a manager within minutes.

## Fix Principles

Primary safer patterns for the worked example follow. For other languages and variant-specific fixes, use the [family appendix](appendix/code-level-reference/4-09-review-secrets-defaults-and-dangerous-apis.md).

### Python

Load secrets from environment or a secret backend. Remove test bypasses from production paths.

```python
import os
import jwt

def get_secret(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required secret: {name}")
    return value

@app.route("/admin/sync")
def admin_sync():
    expected = get_secret("ADMIN_SYNC_API_KEY")
    if secrets.compare_digest(request.headers.get("X-API-Key", ""), expected):
        return admin_dashboard()
    return "", 403

def sign_token(payload: dict) -> str:
    key = get_secret("JWT_SIGNING_KEY")
    return jwt.encode(payload, key, algorithm="HS256")
```

Use `pydantic-settings` or `django-environ` for typed configuration. Run [gitleaks](https://github.com/gitleaks/gitleaks) or GitHub secret scanning in CI.

## Verify During Review

Use the checklist below as a family-level pass over the variants above. Each item should map to evidence in the change under review.

- No passwords, API keys, tokens, or private keys appear as string literals in application code.
- Authentication logic has no hardcoded bypass branches alongside normal credential checks.
- Secrets load from environment variables, secret managers, or encrypted configuration at runtime.
- Front-end and mobile clients use public identifiers only; sensitive keys stay on the server.
- Secret scanning runs in CI and on historical commits when onboarding a repository.
- Rotation procedures exist for every secret class; hardcoded values cannot be rotated without redeploying code.
- User-controlled input does not reach `eval`, equivalent dynamic execution, or unsafe deserialization APIs.
- Shell commands use argument arrays and allowlists; no `shell=True` or `sh -c` with interpolated user data.
- Plugin and template features use restricted DSLs or admin-only authoring with code review, not open user scripting.
- Dangerous functions in legacy modules are scheduled for removal or isolated from production routes.
- Static analysis and security tests cover known dangerous API usage in the codebase.
- Dead code, duplicate legacy endpoints, and test-only routes are removed or strictly environment-gated.
- Feature flags that expose alternate code paths have owners, expiry dates, and production defaults that fail secure.
- Deprecated API versions receive the same authentication, authorization, and input validation as current versions—or are shut down.
- Production builds exclude debug, profiling, and administrative utilities not required in prod.
- Coverage or static analysis confirms unreachable security-sensitive code is deleted, not commented out.
- Technical debt tickets for obsolete security paths are prioritized alongside new feature work.
- Framework secure defaults are enabled and not overridden in production configuration.
- Debug, verbose errors, and permissive CORS are confined to local development.
- Session and CSRF protections match the authentication model (cookie sessions need CSRF).
- Template and API output paths use framework escaping unless a documented exception exists.
- Dependencies are current and monitored; configuration drift is reviewed in each release.
- Every user-editable field has equivalent server-side validation before business logic runs.
- HTML5, JavaScript, and mobile validations are treated as UX only, not security controls.
- Trusted values (price, role, user ID, discount eligibility) are computed server-side, not read from the client.
- Invalid input returns consistent 400 responses with safe error messages; handlers do not partially persist bad data.
- API endpoints used by SPAs and mobile apps enforce the same rules as server-rendered forms.
- Security tests bypass the front end and send out-of-range, missing, and malformed fields to each endpoint.
- No production code path uses `verify=False`, trust-all TLS callbacks, or equivalent.
- JWT validation enforces signature, allowed algorithms, `exp`, and `iss`/`aud` where applicable; no `verify_signature=False` in deployed branches.
- Signing keys load from secret stores or JWKS with rotation; no long-lived hardcoded symmetric secrets in source.
- Session cookies use HttpOnly + Secure + deliberate SameSite; lifetimes match policy.
- User-controlled URLs are not fetched with TLS verification disabled (pair with SSRF allowlists).
- Related chapters (hardcoded secrets, CSRF, session management) are checked when any finding above is present.

## Code Reference (Appendix)

Payloads, language-specific sinks, multi-language examples, and full fix catalogs for every variant live in **[4.9 code reference — Review Secrets, Defaults, and Dangerous APIs](appendix/code-level-reference/4-09-review-secrets-defaults-and-dangerous-apis.md)**.

## Reference

- Appendix — [4.9 code reference](appendix/code-level-reference/4-09-review-secrets-defaults-and-dangerous-apis.md)

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [NIST SP 800-57: Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [AWS Secrets Manager documentation](https://docs.aws.amazon.com/secretsmanager/)
- [HashiCorp Vault documentation](https://developer.hashicorp.com/vault/docs)
- [Python os.environ](https://docs.python.org/3/library/os.html#os.environ)
- [pydantic-settings documentation](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)
- [Spring Cloud Config](https://docs.spring.io/spring-cloud-config/docs/current/reference/html/)
- [Azure Key Vault configuration provider](https://learn.microsoft.com/en-us/aspnet/core/security/key-vault-configuration)
- [Go crypto/subtle ConstantTimeCompare](https://pkg.go.dev/crypto/subtle#ConstantTimeCompare)
- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code](https://cwe.mitre.org/data/definitions/95.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [Python ast.literal_eval](https://docs.python.org/3/library/ast.html#ast.literal_eval)
- [Python subprocess security considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [Java ProcessBuilder](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/ProcessBuilder.html)
- [System.Text.Json documentation](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/overview)
- [Go exec.Command](https://pkg.go.dev/os/exec#Command)
- [CWE-561: Dead Code](https://cwe.mitre.org/data/definitions/561.html)
- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
- [OWASP Web Security Testing Guide — Configuration and Deployment Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)
- [Go build constraints](https://go.dev/doc/go1.17#build-constraints)
- [Python vulture](https://github.com/jendrikseipp/vulture)
- [ArchUnit user guide](https://www.archunit.org/userguide/html/000_Index.html)
- [staticcheck documentation](https://staticcheck.dev/docs/checks/)
- [OWASP — Secure Configuration Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Configuration_Cheat_Sheet.html)
- [Django — Deployment checklist](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/)
- [Django — Settings reference](https://docs.djangoproject.com/en/stable/ref/settings/)
- [Flask — Configuration handling](https://flask.palletsprojects.com/en/stable/config/)
- [Spring Security — Getting started](https://docs.spring.io/spring-security/reference/getting-started.html)
- [ASP.NET Core — Security overview](https://learn.microsoft.com/en-us/aspnet/core/security/)
- [Gin — Mode and middleware](https://gin-gonic.com/en/docs/examples/custom-middleware/)
- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Pydantic v2 — field constraints](https://docs.pydantic.dev/latest/concepts/fields/)
- [Marshmallow documentation](https://marshmallow.readthedocs.io/en/latest/)
- [Jakarta Bean Validation](https://jakarta.ee/specifications/bean-validation/3.0/)
- [Hibernate Validator](https://hibernate.org/validator/documentation/)
- [ASP.NET Core model validation](https://learn.microsoft.com/en-us/aspnet/core/mvc/models/validation)
- [FluentValidation](https://docs.fluentvalidation.net/)
- [go-playground/validator](https://pkg.go.dev/github.com/go-playground/validator/v10)
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
