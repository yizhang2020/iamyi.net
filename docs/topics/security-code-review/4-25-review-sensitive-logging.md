---
title: Review Sensitive Logging
keywords:
  - security code review
  - sensitive logging
  - log injection
  - credentials in logs
  - audit logging
description: How to read code for sensitive data written to application and access logs that must never be recorded.
---

## 4.25 - Review Sensitive Logging

Logs are a secondary data store. Review log statements, structured logging fields, exception serializers, and APM exporters for passwords, tokens, and payment data. Confirm security-relevant events are captured while secrets and regulated personal data are excluded or redacted.

## What This Vulnerability Is

Sensitive logging is the practice of writing data to logs that should remain confidential. If logs are copied to analytics, emailed on alert, or accessed by operators with broad read rights, a single `log.info("password=" + password)` can cause a breach as serious as database exposure.

The unsafe assumption is that logs are internal and low risk. In practice, log platforms aggregate production traffic, retain data for months, and sync to third parties. This maps to [CWE-532](https://cwe.mitre.org/data/definitions/532.html) (Insertion of Sensitive Information into Log File).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login, payment, password reset, OAuth token exchange, API key validation, crypto operations |
| **Log sinks** | Application loggers, access logs, APM traces, exception handlers, stdout in containers |
| **Sensitive fields** | Passwords, session IDs, bearer tokens, API keys, PAN/CVV, reset tokens, connection strings |
| **Weak controls** | Interpolating `request.json`, full header dumps, `debug` logging on auth paths in production |
| **Missing positives** | No audit trail for login failure, lockout, or admin actions without storing secrets |
| **Shipping risk** | Log aggregation to Splunk, CloudWatch, or ELK without redaction filters |

## Attack Payloads

These are abuse scenarios for what attackers or insiders may recover from logs—not payloads to send to the app. Use them to design log review checklists and redaction tests.

### Pattern 1: Credential capture in application logs

```text
INFO login attempt user=admin password=Secret123!
DEBUG auth body={"password":"x","token":"eyJ..."}
```

### Pattern 2: Token and session leakage

```text
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
Set-Cookie: session=deadbeef; Path=/
API key validated: sk_live_abc123xyz
```

### Pattern 3: Payment and regulated data

```text
card=4111111111111111 cvv=123 exp=12/29
ssn=123-45-6789
```

### Pattern 4: Log injection via user-controlled fields (secondary risk)

```text
username=admin%0aINFO Forged audit: admin logged in
```

Newline or forged severity in usernames may confuse parsers or SIEM rules.

### Pattern 5: Exception and stack trace disclosure

```text
SQLException: connection failed for user 'dbadmin' password 'DbP@ss!' at jdbc:mysql://internal-db:3306/prod
```

### Pattern 6: Full request dumps in debug mode

```text
REQUEST_HEADERS={... Authorization: Bearer ... Cookie: session=...}
REQUEST_BODY={"password":"..."}
```

## Language-Specific Sinks and Dangerous APIs

Search for log calls and serializers that include request objects, headers, or exception messages with user data.

### Python

```python
logger.info("login %s %s", user, password)
logger.debug("headers %s body %s", request.headers, request.get_data())
app.logger.exception(e)  # may include SQL with secrets
```

`print(request.json)` in containers; structlog with unfiltered `request` dict.

### Java

```java
log.info("token={}", accessToken);
log.debug("request {}", request.toString());
e.printStackTrace();  // stderr captured by log agents
```

Log4j/SLF4J MDC with full `Authorization` header; Spring `CommonsRequestLoggingFilter` without masking.

### C#

```csharp
_logger.LogInformation("Password {Pwd}", password);
_logger.LogDebug("Request {@Request}", request);
```

Serilog destructuring of entire request DTOs; `ILogger` with connection strings in messages.

### JavaScript

```javascript
console.log("auth", req.headers.authorization, req.body);
logger.info({ headers: req.headers, body: req.body });
```

Winston/Pino serializers that pass through `req` unchanged.

### Go

```go
log.Printf("login user=%s pass=%s", user, pass)
log.Printf("req=%+v", r)  // may dump Authorization header
```

### Access and infrastructure logs

```text
# nginx — full URI with secrets if clients use GET login
GET /login?password=secret HTTP/1.1
```

## Sample Vulnerable Code in Python

```python
from flask import Flask, request

app = Flask(__name__)

@app.post("/pay")
def pay():
    card = request.json
    # Sink: full payment payload including PAN and CVV written to logs
    app.logger.debug("charge payload=%s", card)
    return charge(card)
```

## Step-by-Step Review Walkthrough

1. **Search log calls with request data.** Look for interpolation of parameters, headers, cookies, or full JSON bodies.
2. **Trace the Python payment handler.** In the sample, `card` may contain PAN and CVV. Debug level does not make the data safe in production.
3. **Review exception handlers.** Messages that echo SQL or user input can land in log files and APM.
4. **Inspect access log configuration.** Query strings and `Authorization` headers must not appear on auth endpoints.
5. **Check reset and MFA flows.** Tokens or OTP codes left in stdout or logs from development leftovers are common findings.
6. **Review aggregation filters.** Redaction must run before ship to external log platforms.
7. **Confirm audit events record outcome without credentials.** Log actor, action, and result—not secrets.

## Risk Impact Analysis

**Credential and token exposure.** Operators, support staff, and compromised log accounts may read secrets written to shared platforms.

**PCI and regulatory breach.** Cardholder data in logs can expand PCI scope and trigger notification obligations.

**Long retention windows.** Log retention often exceeds database row lifetimes. A single mistake persists for months.

**Supply chain to third parties.** Log SaaS vendors and analytics pipelines receive copies of whatever the application emits.

## Vulnerable Examples in Other Languages

### Java

```java
public void login(String username, String password) {
    logger.info("Login attempt user={} password={}", username, password);
    boolean ok = authService.authenticate(username, password);
    logger.info("Login result user={} success={}", username, ok);
}

@ExceptionHandler(Exception.class)
public ResponseEntity<String> handleError(Exception ex, HttpServletRequest req) {
    logger.error("request failed uri={} query={} body={}",
        req.getRequestURI(), req.getQueryString(), readBody(req), ex);
    return ResponseEntity.status(500).body(ex.getMessage());
}
```

### C#

```csharp
[HttpPost("pay")]
public IActionResult Pay([FromBody] PaymentRequest req)
{
    _logger.LogDebug("charge payload {@Card}", req.Card);
    return Ok(_billing.Charge(req));
}

[HttpGet("admin/sync")]
public IActionResult Sync()
{
    _logger.LogInformation("API call Authorization: {Auth}",
        Request.Headers["Authorization"]);
    return Ok(_sync.Run());
}
```

### Go

```go
func reset(w http.ResponseWriter, r *http.Request) {
    token := generateToken()
    log.Printf("issued reset token=%s for %s", token, r.FormValue("email"))
    mailer.SendReset(r.FormValue("email"), token)
}

func pay(w http.ResponseWriter, r *http.Request) {
    var payload map[string]interface{}
    json.NewDecoder(r.Body).Decode(&payload)
    log.Printf("charge request=%+v", payload) // may include PAN and CVV
    processPayment(payload)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Log event metadata, not secrets. Use filters to redact sensitive keys before emit.

```python
import logging
import re

SENSITIVE_KEYS = re.compile(r"(password|token|secret|authorization|cvv|pan)", re.I)

class RedactFilter(logging.Filter):
    def filter(self, record):
        if isinstance(record.msg, str):
            record.msg = SENSITIVE_KEYS.sub("[REDACTED]", record.msg)
        return True

@app.post("/pay")
def pay():
    payload = request.json
    current_app.logger.info(
        "charge_attempt user_id=%s amount=%s result=pending",
        session.get("user_id"),
        payload.get("amount"),
    )
    return charge(payload)
```

```python
# Register filter on the app logger
logging.getLogger("werkzeug").addFilter(RedactFilter())
```

**Important:** Never log `request.data`, `request.form`, or full headers on authentication routes.

### Java

Use structured logging with fixed fields. Never pass raw passwords to the logger.

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

private static final Logger log = LoggerFactory.getLogger(AuthService.class);

public void login(String username, String password) {
    MDC.put("event", "LOGIN_ATTEMPT");
    MDC.put("username", username);
    boolean ok = authenticate(username, password);
    log.info("login result={}", ok ? "SUCCESS" : "FAILURE");
    MDC.clear();
}
```

### C#

Use explicit log templates. Do not pass raw header dictionaries.

```csharp
_logger.LogInformation(
    "Login attempt for user {UserId} result {Result}",
    userId,
    success ? "Success" : "Failure");
```

```csharp
// Serilog destructuring policy example
Log.Logger = new LoggerConfiguration()
    .Destructure.ByTransforming<LoginRequest>(r => new { r.Username })
    .CreateLogger();
```

### Go

Use `slog` with an allowlist of attributes. Implement `LogValuer` for types that redact secrets.

```go
import "log/slog"

func handleLogin(w http.ResponseWriter, r *http.Request) {
    user := r.FormValue("user")
    ok := authenticate(user, r.FormValue("pass"))
    slog.Info("login_attempt",
        slog.String("user", user),
        slog.String("result", map[bool]string{true: "success", false: "failure"}[ok]),
    )
}
```

```go
type redactedString string

func (s redactedString) LogValue() slog.Value {
    return slog.StringValue("[REDACTED]")
}
```

## Verify During Review

- Passwords, session IDs, access tokens, API keys, and connection strings never appear in application or access logs.
- Security-relevant events (login, logout, reset attempts, authz failures, admin actions) are logged with useful non-secret context.
- Debug logging of full requests is disabled in production or heavily redacted.
- Log shipping and retention policies treat log buckets as sensitive data stores.
- Developers removed temporary debug prints of tokens from reset and OAuth flows.
- Exception messages returned to users are separate from rich detail allowed only in server-side logs.

## Reference

- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [OWASP — Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Python logging — Filters](https://docs.python.org/3/library/logging.html#filter-objects)
- [SLF4J — Structured logging](https://www.slf4j.org/manual.html)
- [Serilog — Destructure policies](https://github.com/serilog/serilog/wiki/Formatting-Output)
- [Go slog package](https://pkg.go.dev/log/slog)
- [ASP.NET Core — Logging](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/logging)
