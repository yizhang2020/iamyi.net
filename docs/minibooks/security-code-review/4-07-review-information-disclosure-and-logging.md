---
title: Review Information Disclosure and Logging
keywords:
  - error disclosure
  - logging
  - username enumeration
  - sensitive data
description: Review errors, URLs, enumeration, comments, and sensitive logging as disclosure paths.
---

## 4.7 - Review Information Disclosure and Logging

### Overview

Disclosure findings leak secrets or decision logic through messages, URLs, comments, or logs. Ask what a stranger learns from each channel and whether sensitive fields are redacted before they leave the trust boundary.

The points below are the ideas this family chapter uses again and again.

1. Disclosure findings leak secrets, PII, or internals through errors, URLs, logs, or comments.
2. Enumeration and verbose errors teach attackers what exists.
3. Logging is both a control and a sink for sensitive data.
4. Related variants share one question: what should never leave the trust boundary.
5. Evidence names the channel, the sensitive value, missing control, impact, and a proving test.

After reading this chapter, we should be able to find disclosure paths in errors, URLs, enumeration, logging, and comments with shared evidence habits.

## Shared Review Model

Across every variant below, keep the same evidence habit: name the **source**, the **sink**, the **missing control**, the **impact**, and a **test** that would prove a fix.

## Variants in This Family

### Error page disclosure {: #errors }

Information disclosure through errors happens when the application answers a failure with more detail than the user should see. Default servlet containers, reverse proxies, and frameworks often ship verbose error pages that name server software and version. Application code may print exceptions directly to the response writer or include SQL fragments, file paths, and library versions in JSON error bodies.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | API error JSON, catch blocks, global exception handlers, health endpoints on failure |
| **Response sinks** | `printStackTrace`, `traceback.format_exc()`, returning `ex.Message` or `ex.StackTrace` |
| **Debug flags** | `DEBUG=True`, `app.debug`, developer exception page enabled in production deploy paths |
| **Missing error pages** | No catch-all `/error` route; container defaults expose version banners |
| **Partial handlers** | 404/500 pages configured without general fallback hiding stack traces |
| **Version banners** | `Server`, `X-Powered-By`, framework version strings in production configs |

**Appendix detail:** [Error page disclosure code reference](appendix/code-level-reference/4-07-review-information-disclosure-and-logging.md#errors).

### Sensitive data in URL {: #url-data }

Sensitive data exposure via URLs occurs when passwords, tokens, session identifiers, or personal data appear in the query string or path where GET semantics apply. Browsers store URLs in history. Load balancers and CDNs often log full request lines. Third-party sites may receive secrets when users follow external links from a page that included them in the URL.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login, registration, password reset, magic links, API key auth, OAuth callbacks, shareable report URLs |
| **Input entry** | GET query params, bookmarkable links, email links with embedded tokens, front-end URL builders |
| **Sensitive fields** | Passwords, API keys, access tokens, session IDs, reset tokens, PII in query strings |
| **Logging sinks** | Access logs, APM, error trackers, analytics beacons that capture full request URIs |
| **Weak controls** | `@app.route(..., methods=["GET", "POST"])` on login, `[FromQuery] password`, redirect URLs echoing credentials |
| **Referrer leakage** | Pages with secrets in the URL linked from external sites without `Referrer-Policy` |

**Appendix detail:** [Sensitive data in URL code reference](appendix/code-level-reference/4-07-review-information-disclosure-and-logging.md#url-data).

### Username enumeration {: #enumeration }

Username enumeration is an information disclosure issue in authentication and account recovery. The application behaves differently when a username or email is registered versus when it is not. Attackers compile lists of valid accounts for credential stuffing, phishing, or targeted attacks.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login, password reset, registration, invite acceptance, MFA enrollment, OAuth account linking |
| **Input entry** | Email or username fields on public-facing auth endpoints |
| **Branching logic** | `if user is None`, `if token != null`, different HTTP status or JSON error codes |
| **Side channels** | Response time when DB lookup is skipped, email send only when account exists |
| **Weak controls** | 404 for unknown email, explicit "already registered", distinct login failure messages |
| **API leaks** | JSON fields like `exists: true`, different error codes per case |

**Appendix detail:** [Username enumeration code reference](appendix/code-level-reference/4-07-review-information-disclosure-and-logging.md#enumeration).

### Sensitive logging {: #sensitive-logging }

Sensitive logging is the practice of writing data to logs that should remain confidential. If logs are copied to analytics, emailed on alert, or accessed by operators with broad read rights, a single `log.info("password=" + password)` can cause a breach as serious as database exposure.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login, payment, password reset, OAuth token exchange, API key validation, crypto operations |
| **Log sinks** | Application loggers, access logs, APM traces, exception handlers, stdout in containers |
| **Sensitive fields** | Passwords, session IDs, bearer tokens, API keys, PAN/CVV, reset tokens, connection strings |
| **Weak controls** | Interpolating `request.json`, full header dumps, `debug` logging on auth paths in production |
| **Missing positives** | No audit trail for login failure, lockout, or admin actions without storing secrets |
| **Shipping risk** | Log aggregation to Splunk, CloudWatch, or ELK without redaction filters |

**Appendix detail:** [Sensitive logging code reference](appendix/code-level-reference/4-07-review-information-disclosure-and-logging.md#sensitive-logging).

### Secure logging {: #secure-logging }

Logs are a secondary data store. They often have weaker access controls than production databases, longer retention, and broad read access for operations teams. When applications log secrets, session identifiers, or personal data, a log breach may cause the same harm as a database leak. Missing security events—failed logins, authorization denials, admin actions—blind incident response and forensics.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login, logout, password reset, payment, admin config, file upload handlers |
| **Secret leakage** | Logged passwords, API keys, `Authorization` headers, cookies, connection strings |
| **Missing audit events** | Auth flows without success/failure logging, absent logout and password-change records |
| **PII and PCI** | Full card numbers, bank accounts, government IDs, health data in log fields |
| **Oververbose debug** | `logger.debug(request)` serializing entire HTTP requests in production paths |
| **Log injection** | User input embedded in log messages without sanitization |
| **Admin activity gaps** | Privileged actions without immutable audit trail |

**Appendix detail:** [Secure logging code reference](appendix/code-level-reference/4-07-review-information-disclosure-and-logging.md#secure-logging).

### Sensitive code comments {: #comments }

Source code comments are not executed, but they are often stored in version control, included in builds, and visible to anyone with repository access. When comments contain passwords, password hints, API keys, or instructions to weaken security, they create an information disclosure risk. Attackers who obtain source may use those notes to bypass authentication or reach hidden functionality.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Comment types** | Block comments, HTML `<!-- -->`, Javadoc, docstrings, TODO/FIXME/HACK markers |
| **Credential language** | `password`, `secret`, `key`, `token`, example values that look real |
| **Bypass hints** | Instructions to skip MFA, disable validation, or use a backdoor account |
| **Internal topology** | Internal hostnames, database names, unreleased feature flags in comments |
| **HTML exposure** | JSP, Thymeleaf, static HTML comments visible in page source |
| **Commented-out code** | Disabled auth checks and hardcoded overrides left for debugging |

**Appendix detail:** [Sensitive code comments code reference](appendix/code-level-reference/4-07-review-information-disclosure-and-logging.md#comments).

## Worked Example (Error page disclosure)

We walk **Error page disclosure** in depth. Apply the same tracing steps to the other variants, adjusting sources and sinks from the tables above.

### Sample vulnerable code (Python)

```python
import traceback
import logging
import uuid
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
logger = logging.getLogger("reports")

@app.get("/reports/run")
async def run_report(request: Request):
    try:
        return await generate_report()
    except Exception as exc:
        # Stack trace returned to client — reveals paths, ORM queries, and library versions
        return JSONResponse(
            {"error": str(exc), "trace": traceback.format_exc()},
            status_code=500,
        )
```

### Step-by-step review walkthrough

1. **Locate every catch block and exception handler** that writes to HTTP responses or API error payloads.
2. **Trace the FastAPI report route.** In the sample, `traceback.format_exc()` in JSON responses exposes internal paths and ORM details.
3. **Check framework and server configuration.** `web.xml` error pages, Spring `server.error.*`, Django `DEBUG`, FastAPI exception handlers, and Express error middleware.
4. **Trace whether stack traces reach clients** in any environment via `printStackTrace`, `e.message`, or full exception serialization.
5. **Review API layers** that serialize exceptions into JSON (`detail`, `stack`, embedded file paths).
6. **Confirm a catch-all error page exists** so undefined HTTP error codes do not fall back to container defaults.
7. **Inspect health and diagnostic endpoints** that echo environment variables or build metadata on failure.
8. **Verify logging sends stack traces to secure server logs**, not to the user agent.

## Risk Impact (Family)

**Targeted exploitation.** Stack traces reveal framework versions, file paths, and SQL fragments attackers use to craft precise exploits.

**Architecture mapping.** Error details expose internal module names, dependency versions, and deployment layout.

**Credential and query leakage.** Database exceptions may include connection hints, table names, or parameter values.

**Compliance exposure.** Verbose errors conflict with policies requiring minimal client-facing diagnostic data.

**Support confusion.** Raw exceptions shown to end users erode trust and complicate incident triage.

## Fix Principles

Primary safer patterns for the worked example follow. For other languages and variant-specific fixes, use the [family appendix](appendix/code-level-reference/4-07-review-information-disclosure-and-logging.md).

### Python

Register error handlers that return generic messages. Log full exceptions server-side with a correlation ID.

```python
import traceback
import logging
import uuid
from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()
logger = logging.getLogger("reports")

@app.exception_handler(Exception)
async def handle_error(request, exc):
    request_id = str(uuid.uuid4())
    logger.exception("unhandled error request_id=%s", request_id)
    return JSONResponse(
        {"error": "An internal error occurred.", "request_id": request_id},
        status_code=500,
    )

@app.get("/reports/run")
async def run_report():
    return await generate_report()
```

**Important:** Keep Django `DEBUG=False` in production. Use `handler500` and logging settings for details. Never return `traceback.format_exc()` to users.

## Verify During Review

Use the checklist below as a family-level pass over the variants above. Each item should map to evidence in the change under review.

- No stack traces, SQL errors, or file paths appear in HTTP responses in production configurations.
- Catch-all and per-status error pages are configured so container defaults never leak versions.
- Framework debug modes and detailed error middleware are disabled outside local development.
- APIs return stable, minimal error shapes; support staff use correlation IDs tied to server logs.
- Exception logging is complete server-side but excludes secrets already covered in logging review.
- Security headers and custom error content are defense in depth, not the only control.
- Passwords, API keys, and long-lived tokens never appear in GET query strings or shareable URLs.
- Login and registration use POST with secrets in body or `Authorization` header over HTTPS.
- Access logs, APM, and error reporting do not store full URLs for authentication endpoints.
- Redirects after sensitive operations strip credentials from the visible URL bar.
- `Referrer-Policy` and cache headers are set where pages might still touch sensitive flows.
- OpenAPI or public docs do not advertise secret-bearing query parameters.
- Login, reset, and registration responses do not differ in wording, status, or structure based on account existence.
- Email and SMS are triggered only server-side; clients cannot infer delivery from response alone.
- Timing and workload are similar enough that trivial timing attacks are not trivially enabled.
- Rate limits and monitoring protect public authentication endpoints.
- Intentional enumeration (admin consoles) is role-gated and documented.
- API documentation matches uniform external behavior.
- Passwords, session IDs, access tokens, API keys, and connection strings never appear in application or access logs.
- Security-relevant events (login, logout, reset attempts, authz failures, admin actions) are logged with useful non-secret context.
- Debug logging of full requests is disabled in production or heavily redacted.
- Log shipping and retention policies treat log buckets as sensitive data stores.
- Developers removed temporary debug prints of tokens from reset and OAuth flows.
- Exception messages returned to users are separate from rich detail allowed only in server-side logs.
- All login attempts — successful and unsuccessful
- Log-outs
- Password changes and reset attempts
- User creation and removal, and changes to a user's authorization
- Authorization failures when a user is denied access to a resource
- Input validation failures, such as unexpected values from dropdown lists
- System administration activity
- Integrity events and submission of user-generated content — especially file uploads
- Access to sensitive data such as payment card information and keys
- Application source code and commercially sensitive information
- Session IDs, access tokens, and authentication passwords
- Sensitive personal data, bank account, or payment cardholder data
- Database connection strings, encryption keys, and other secrets
- Information that is illegal to collect or that the user has opted out of collecting
- Production log level defaults to INFO or WARN; DEBUG and TRACE do not emit PII in steady state.
- Error responses to users remain generic while server-side logs capture detail without secrets.
- Log aggregation storage has encryption, retention limits, and role-based access aligned with compliance needs.
- No passwords, API keys, tokens, or bypass instructions appear in comments, HTML, or commit messages in the repository.
- TODO and FIXME items on security work are tracked in issue trackers with restricted access, not as inline hints.
- Commented-out authentication, authorization, or validation code is removed rather than left as a re-enable target.
- Static secret scanning runs on every push and blocks merges when comments contain high-risk patterns.
- Production page source does not expose sensitive HTML comments to unauthenticated users.

## Code Reference (Appendix)

Payloads, language-specific sinks, multi-language examples, and full fix catalogs for every variant live in **[4.7 code reference — Review Information Disclosure and Logging](appendix/code-level-reference/4-07-review-information-disclosure-and-logging.md)**.

## Reference

- Appendix — [4.7 code reference](appendix/code-level-reference/4-07-review-information-disclosure-and-logging.md)

- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-497: Exposure of Sensitive System Information](https://cwe.mitre.org/data/definitions/497.html)
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [RFC 7807: Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc7807)
- [Django — Error reporting](https://docs.djangoproject.com/en/stable/howto/error-reporting/)
- [Flask — Error handling](https://flask.palletsprojects.com/en/stable/errorhandling/)
- [Spring Boot — Error handling properties](https://docs.spring.io/spring-boot/docs/current/reference/html/application-properties.html#appendix.application-properties.server)
- [ASP.NET Core — Handle errors](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/error-handling)
- [Go log/slog package](https://pkg.go.dev/log/slog)
- [CWE-598: Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
- [OWASP — Information exposure through query strings in URL](https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url)
- [MDN — Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)
- [Flask — HTTP methods](https://flask.palletsprojects.com/en/stable/quickstart/#http-methods)
- [FastAPI — Header parameters](https://fastapi.tiangolo.com/tutorial/header-params/)
- [Spring Security — Form Login](https://docs.spring.io/spring-security/reference/servlet/authentication/passwords/form.html)
- [ASP.NET Core — Prevent cross-site request forgery](https://learn.microsoft.com/en-us/aspnet/core/security/anti-request-forgery)
- [Go net/http — Request handling](https://pkg.go.dev/net/http#Request)
- [CWE-204: Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html)
- [OWASP — Testing for Account Enumeration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Django — Password reset views](https://docs.djangoproject.com/en/stable/topics/auth/default/#django.contrib.auth.views.PasswordResetView)
- [ASP.NET Core Identity — UserManager](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.identity.usermanager-1)
- [Spring Security — Authentication failure handling](https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html)
- [bcrypt — Python documentation](https://pypi.org/project/bcrypt/)
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [OWASP — Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Python logging — Filters](https://docs.python.org/3/library/logging.html#filter-objects)
- [SLF4J — Structured logging](https://www.slf4j.org/manual.html)
- [Serilog — Destructure policies](https://github.com/serilog/serilog/wiki/Formatting-Output)
- [Go slog package](https://pkg.go.dev/log/slog)
- [ASP.NET Core — Logging](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/logging)
- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [Python logging documentation](https://docs.python.org/3/library/logging.html)
- [structlog documentation](https://www.structlog.org/en/stable/)
- [SLF4J manual](https://www.slf4j.org/manual.html)
- [Serilog destructuring](https://github.com/serilog/serilog/wiki/Structured-Data)
- [Go zap logger](https://pkg.go.dev/go.uber.org/zap)
- [CWE-615: Inclusion of Sensitive Information in Source Code Comments](https://cwe.mitre.org/data/definitions/615.html)
- [OWASP — Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [Python os.environ](https://docs.python.org/3/library/os.html#os.environ)
- [dotnet user-secrets](https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets)
- [Azure Key Vault configuration provider](https://learn.microsoft.com/en-us/aspnet/core/security/key-vault-configuration)
- [HashiCorp Vault](https://developer.hashicorp.com/vault/docs)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
