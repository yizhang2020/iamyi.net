---
title: Review Error Page Disclosure
keywords:
  - security code review
  - error handling
  - stack trace
  - information disclosure
  - verbose errors
description: How to read code for information disclosure through error pages—verify production returns generic messages while diagnostics stay in server logs.
---

## 4.21 - Review Error Page Disclosure

Error handling can leak implementation details when stack traces, framework versions, or internal paths reach the HTTP response. Review catch blocks, global exception handlers, API error serializers, and deployment settings for debug mode. Confirm production returns generic messages while detailed diagnostics stay in server-side logs.

## What This Vulnerability Is

Information disclosure through errors happens when the application answers a failure with more detail than the user should see. Default servlet containers, reverse proxies, and frameworks often ship verbose error pages that name server software and version. Application code may print exceptions directly to the response writer or include SQL fragments, file paths, and library versions in JSON error bodies.

The unsafe assumption is that only legitimate users will trigger errors. Attackers probe inputs to force exceptions and harvest clues for targeted exploits. This behavior relates to [CWE-209](https://cwe.mitre.org/data/definitions/209.html) (Generation of Error Message Containing Sensitive Information) and [CWE-497](https://cwe.mitre.org/data/definitions/497.html) (Exposure of Sensitive System Information to an Unauthorized Control Sphere).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | API error JSON, catch blocks, global exception handlers, health endpoints on failure |
| **Response sinks** | `printStackTrace`, `traceback.format_exc()`, returning `ex.Message` or `ex.StackTrace` |
| **Debug flags** | `DEBUG=True`, `app.debug`, developer exception page enabled in production deploy paths |
| **Missing error pages** | No catch-all `/error` route; container defaults expose version banners |
| **Partial handlers** | 404/500 pages configured without general fallback hiding stack traces |
| **Version banners** | `Server`, `X-Powered-By`, framework version strings in production configs |

## Sample Vulnerable Code in Python

```python
import traceback
from flask import Flask

app = Flask(__name__)

@app.route("/report")
def report():
    try:
        return generate_report()
    except Exception as exc:
        # Stack trace returned to client — reveals paths, libraries, and query details
        return {"error": str(exc), "trace": traceback.format_exc()}, 500
```

## Step-by-Step Review Walkthrough

1. **Locate every catch block and exception handler** that writes to HTTP responses or API error payloads.
2. **Check framework and server configuration.** `web.xml` error pages, Spring `server.error.*`, Django `DEBUG`, Flask `PROPAGATE_EXCEPTIONS`, and Express error middleware.
3. **Trace whether stack traces reach clients** in any environment via `printStackTrace`, `e.message`, or full exception serialization.
4. **Review API layers** that serialize exceptions into JSON (`detail`, `stack`, embedded file paths).
5. **Confirm a catch-all error page exists** so undefined HTTP error codes do not fall back to container defaults.
6. **Inspect health and diagnostic endpoints** that echo environment variables or build metadata on failure.
7. **Verify logging sends stack traces to secure server logs**, not to the user agent.

## Risk Impact Analysis

**Targeted exploitation.** Stack traces reveal framework versions, file paths, and SQL fragments attackers use to craft precise exploits.

**Architecture mapping.** Error details expose internal module names, dependency versions, and deployment layout.

**Credential and query leakage.** Database exceptions may include connection hints, table names, or parameter values.

**Compliance exposure.** Verbose errors conflict with policies requiring minimal client-facing diagnostic data.

**Support confusion.** Raw exceptions shown to end users erode trust and complicate incident triage.

## Vulnerable Examples in Other Languages

### Java

```java
try {
    processOrder(orderId);
} catch (Exception e) {
    e.printStackTrace(response.getWriter());
}
```

### C#

```csharp
catch (Exception ex)
{
    return StatusCode(500, new { message = ex.Message, stack = ex.StackTrace });
}
```

### Go

```go
func handler(w http.ResponseWriter, r *http.Request) {
    if err := runJob(); err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        fmt.Fprintf(w, "%+v", err)
        return
    }
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Register error handlers that return generic messages. Log full exceptions server-side with a correlation ID.

```python
import logging
import uuid
from flask import Flask, jsonify

app = Flask(__name__)
app.config["DEBUG"] = False
logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_error(exc):
    request_id = str(uuid.uuid4())
    logger.exception("unhandled error request_id=%s", request_id)
    return jsonify({
        "error": "An internal error occurred.",
        "request_id": request_id,
    }), 500

@app.route("/report")
def report():
    return generate_report()
```

**Important:** Keep Django `DEBUG=False` in production. Use `handler500` and logging settings for details. Never return `traceback.format_exc()` to users.

### Java

Map errors to static pages in `web.xml`. Configure Spring Boot to exclude stack traces in production.

```xml
<error-page>
  <exception-type>java.lang.Exception</exception-type>
  <location>/error/generic.html</location>
</error-page>
<error-page>
  <error-code>500</error-code>
  <location>/error/500.html</location>
</error-page>
```

```properties
# application-prod.properties
server.error.include-stacktrace=never
server.error.include-message=never
server.error.include-exception=false
```

```java
@ControllerAdvice
public class GlobalErrors {
    private static final Logger log = LoggerFactory.getLogger(GlobalErrors.class);

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handle(Exception ex) {
        String id = UUID.randomUUID().toString();
        log.error("request_id={}", id, ex);
        ProblemDetail body = ProblemDetail.forStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        body.setTitle("Internal error");
        body.setProperty("request_id", id);
        return ResponseEntity.status(500).body(body);
    }
}
```

**Important:** Log full exceptions with SLF4J. Return RFC 7807 Problem Details without internal paths in public APIs.

### C#

Use exception handler middleware in production. Restrict developer exception page to Development environment.

```csharp
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/error");
    app.UseHsts();
}

app.Map("/error", () => Results.Problem(
    title: "An error occurred.",
    statusCode: StatusCodes.Status500InternalServerError));
```

```csharp
catch (Exception ex)
{
    var requestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
    _logger.LogError(ex, "Unhandled error {RequestId}", requestId);
    return StatusCode(500, new { error = "An internal error occurred.", requestId });
}
```

**Important:** Set `DetailedErrors=false` in production. Map to ProblemDetails without stack traces.

### Go

Return generic HTTP errors. Log errors with structured logging and recover from panics in middleware.

```go
func handler(w http.ResponseWriter, r *http.Request) {
    if err := runJob(); err != nil {
        requestID := middleware.RequestIDFromContext(r.Context())
        slog.Error("job failed", "request_id", requestID, "err", err)
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }
}

func recoverMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if rec := recover(); rec != nil {
                slog.Error("panic", "recover", rec)
                http.Error(w, "internal error", http.StatusInternalServerError)
            }
        }()
        next.ServeHTTP(w, r)
    })
}
```

**Important:** Disable Gin/Echo debug mode in production. Use nginx or Envoy custom error pages as defense in depth.

## Verify During Review

- No stack traces, SQL errors, or file paths appear in HTTP responses in production configurations.
- Catch-all and per-status error pages are configured so container defaults never leak versions.
- Framework debug modes and detailed error middleware are disabled outside local development.
- APIs return stable, minimal error shapes; support staff use correlation IDs tied to server logs.
- Exception logging is complete server-side but excludes secrets already covered in logging review.
- Security headers and custom error content are defense in depth, not the only control.

## Reference

- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-497: Exposure of Sensitive System Information](https://cwe.mitre.org/data/definitions/497.html)
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [RFC 7807: Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc7807)
- [Django — Error reporting](https://docs.djangoproject.com/en/stable/howto/error-reporting/)
- [Flask — Error handling](https://flask.palletsprojects.com/en/stable/errorhandling/)
- [Spring Boot — Error handling properties](https://docs.spring.io/spring-boot/docs/current/reference/html/application-properties.html#appendix.application-properties.server)
- [ASP.NET Core — Handle errors](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/error-handling)
- [Go log/slog package](https://pkg.go.dev/log/slog)
