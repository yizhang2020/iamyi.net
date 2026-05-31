---
title: Review Obsolete Code
keywords:
  - security code review
  - dead code
  - technical debt
  - feature flags
  - unreachable code
description: How to read code for dead, obsolete, and test-only paths that increase attack surface and hide security regressions.
---

## 4.34 - Review Obsolete Code

Obsolete code increases attack surface when dead paths, test artifacts, or deprecated features remain reachable in production. Review feature flags, commented branches, unused endpoints, and legacy modules. Ask whether each block is still executed, whether it bypasses current security controls, and whether it should be removed.

## What This Vulnerability Is

Dead code, test hooks, and outdated modules often linger after refactors. Some paths are still reachable through direct URLs, old API versions, or feature toggles left enabled. Obsolete authentication helpers, deprecated encryption routines, and temporary admin endpoints may lack the hardening applied to newer code. Attackers probe forgotten routes; insiders may know URLs that documentation no longer mentions.

The unsafe assumption is that unused code is harmless because "nobody calls it." Reachability is not the same as discoverability. Static links, mobile app bundles, integration partners, and scanners can still hit old endpoints. Removing obsolete code improves readability and reduces the set of behaviors that must stay secure.

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Legacy login routes, old API versions (`/v0/`, `/v1/`), debug endpoints, profiling handlers |
| **Test artifacts** | Hardcoded users, mock payment flows, QA bypasses without environment gating |
| **Feature flags** | Toggles defaulting to on, experiments never removed, alternate upload paths |
| **Deprecated handlers** | `@Deprecated` controllers, duplicate login implementations, pre-refactor validation |
| **Commented blocks** | Disabled auth checks left in comments, large duplicated logic with weaker controls |
| **Build gaps** | Debug controllers in Release builds, test packages bundled into production JARs |
| **Static analysis hits** | Unreferenced methods, unreachable branches flagged by coverage or linters |

## Sample Vulnerable Code in Python

```python
import os
from flask import Flask, request

app = Flask(__name__)

# Legacy upload path — still registered when flag is enabled in production
if os.getenv("ENABLE_OLD_UPLOAD") == "1":
    @app.route("/upload/v0", methods=["POST"])
    def upload_v0():
        # Old path without virus scan or size limits
        save_raw(request.files["file"])
        return "", 204

@app.route("/debug/reset-db", methods=["POST"])
def reset_db():
    # Test helper never removed — reachable if deployed
    if request.headers.get("X-Debug") == "1":
        db.execute("DELETE FROM users")
    return "ok"
```

## Step-by-Step Review Walkthrough

1. **Identify unreachable code.** Use static analysis, coverage reports, and route audits to find unreferenced controllers and handlers still deployed.
2. **Search for test artifacts.** Look for hardcoded users, mock payment flows, and debug endpoints not guarded by environment checks.
3. **Review feature flags and toggles.** Confirm disabled experiments are removed after launch or fail closed in production.
4. **Trace deprecated API versions.** Compare auth, validation, and rate limiting on legacy endpoints against current implementations.
5. **Inspect bit-rot modules.** Outdated dependencies and pre-refactor validation logic may lack fixes applied elsewhere.
6. **Check duplicate implementations.** When login, upload, or admin functions exist twice, verify both received security fixes.
7. **Verify build exclusions.** Production artifacts must not include test-only packages or debug handlers.

## Risk Impact Analysis

**Forgotten attack surface.** Legacy endpoints may skip MFA, authorization, or input validation added to newer code paths.

**Authentication bypass.** Test backdoors and debug routes with weak or missing checks provide direct entry points.

**Information disclosure.** Profiling and debug handlers (`pprof`, status pages) may expose internals to unauthenticated callers.

**Maintenance drift.** Security fixes applied to primary code paths may never reach duplicate legacy implementations.

**Compliance scope expansion.** Every reachable endpoint counts toward audit scope even if product teams consider it unused.

## Vulnerable Examples in Other Languages

### Java

```java
// Legacy upload — still registered when ENABLE_OLD_UPLOAD=1 in production
@PostMapping("/upload/v0")
public void uploadV0(@RequestParam MultipartFile file) throws IOException {
    // Old path without virus scan or size limits
    file.transferTo(Path.of("/data/uploads", file.getOriginalFilename()));
}

@PostMapping("/debug/reset-db")
public String resetDb(@RequestHeader("X-Debug") String debug) {
    if ("1".equals(debug)) {
        jdbcTemplate.execute("DELETE FROM users");
    }
    return "ok";
}
```

### C#

```csharp
#if DEBUG
public IActionResult ResetAllUsers() { /* wipes database */ }
#endif
// Same endpoint duplicated outside DEBUG guard — ships in Release builds
public IActionResult ResetAllUsersRelease() { /* ... */ }

[HttpPost("upload/v0")]
public async Task<IActionResult> UploadV0(IFormFile file)
{
    // Old path without virus scan or size limits
    await file.CopyToAsync(File.Create(Path.Combine("/data/uploads", file.FileName)));
    return Ok();
}
```

### Go

```go
// Unused since 2021 — still registered at startup
http.HandleFunc("/debug/pprof/", pprof.Index)
http.HandleFunc("/internal/backdoor/status", statusHandler)

if os.Getenv("ENABLE_OLD_UPLOAD") == "1" {
    http.HandleFunc("/upload/v0", uploadV0) // weaker validation than /upload/v2
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Gate debug routes behind environment checks and remove obsolete paths on schedule.

```python
from flask import Flask, abort
from werkzeug.middleware.profiler import ProfilerMiddleware

app = Flask(__name__)

def register_debug_routes(application: Flask) -> None:
    if not application.config.get("DEBUG"):
        return

    @application.route("/debug/health-detail")
    def health_detail():
        return {"db": db_pool_status()}

# Production settings module — DEBUG is False; debug routes never register
if os.getenv("ENABLE_OLD_UPLOAD") == "1" and app.config["ENV"] == "development":
    raise RuntimeError("ENABLE_OLD_UPLOAD is not allowed outside development")
```

Run [vulture](https://github.com/jendrikseipp/vulture) or coverage-guided deletion after refactors. Document API deprecation timelines and remove old routes on schedule.

### Java

Delete deprecated controllers after migration windows. Return `410 Gone` during sunset if partners need notice.

```java
@GetMapping("/legacyLogin")
public ResponseEntity<Void> legacyLogin() {
    return ResponseEntity.status(HttpStatus.GONE)
        .header("Sunset", "2024-06-01")
        .build();
}
```

Use [ArchUnit](https://www.archunit.org/) to forbid production code depending on test packages. Manage feature flags with expiry dates in LaunchDarkly or similar.

### C#

Verify Release builds exclude debug-only controllers. Enable analyzer rules for unused internal classes.

```csharp
#if DEBUG
[ApiController]
[Route("debug/[controller]")]
public class DiagnosticsController : ControllerBase
{
    [HttpGet("ping")]
    public IActionResult Ping() => Ok("debug");
}
#endif
```

Enable [CA1812](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca1812) and related rules. Use Azure App Configuration with mandatory flag retirement.

### Go

Isolate debug handlers behind build tags not used in production builds.

```go
//go:build debug

package main

import "net/http/pprof"

func registerDebug(mux *http.ServeMux) {
    mux.HandleFunc("/debug/pprof/", pprof.Index)
}
```

```go
//go:build !debug

package main

func registerDebug(mux *http.ServeMux) {}
```

Periodically diff registered routes against documentation. Run [staticcheck](https://staticcheck.dev/) unused-code reports before release branches.

## Verify During Review

- Dead code, duplicate legacy endpoints, and test-only routes are removed or strictly environment-gated.
- Feature flags that expose alternate code paths have owners, expiry dates, and production defaults that fail secure.
- Deprecated API versions receive the same authentication, authorization, and input validation as current versions—or are shut down.
- Production builds exclude debug, profiling, and administrative utilities not required in prod.
- Coverage or static analysis confirms unreachable security-sensitive code is deleted, not commented out.
- Technical debt tickets for obsolete security paths are prioritized alongside new feature work.

## Reference

- [CWE-561: Dead Code](https://cwe.mitre.org/data/definitions/561.html)
- [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)
- [OWASP Web Security Testing Guide — Configuration and Deployment Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)
- [Go build constraints](https://go.dev/doc/go1.17#build-constraints)
- [Python vulture](https://github.com/jendrikseipp/vulture)
- [ArchUnit user guide](https://www.archunit.org/userguide/html/000_Index.html)
- [staticcheck documentation](https://staticcheck.dev/docs/checks/)
