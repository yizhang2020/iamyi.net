---
title: Review Hardcoded Secrets
keywords:
  - security code review
  - hardcoded secrets
  - credentials
  - authentication bypass
  - CWE-798
description: How to read code for hardcoded passwords, API keys, and authentication bypasses embedded in source instead of secret managers.
---

## 4.32 - Review Hardcoded Secrets

Hardcoded secrets appear when passwords, API keys, or bypass values are embedded directly in source code. Review authentication flows, integration clients, encryption helpers, and feature-flag branches. Search for string literals compared against credentials and for static fields that hold keys meant to rotate.

## What This Vulnerability Is

Hardcoded secrets are credentials or cryptographic material stored in source code instead of a secret manager or environment configuration. Anyone with repository access—or an attacker who extracts strings from a binary or container image—may recover them. Hardcoded authentication bypasses are especially dangerous because they often survive code review as "temporary" test hooks.

The unsafe assumption is that source is private and that obscurity protects embedded values. Secrets in code resist rotation, appear in logs and stack traces, and propagate across forks and backups. This pattern maps to [CWE-798](https://cwe.mitre.org/data/definitions/798.html) (Use of Hard-coded Credentials) and related CWE entries for hard-coded cryptographic keys.

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login handlers, API gateways, third-party SDK init, mobile app config, CI/CD scripts |
| **Input entry** | Password verification, header API-key checks, webhook signature validation |
| **Static fields** | `const`, `private static final`, module-level variables, `.env.example` with real values |
| **Bypass branches** | `if (password.equals("..."))` alongside bcrypt checks, debug flags in production paths |
| **Crypto material** | AES keys, HMAC secrets, JWT signing keys, PEM blocks committed to git |
| **Connection strings** | JDBC, MongoDB, Redis, SMTP URLs with embedded usernames and passwords |
| **Client exposure** | JavaScript bundles, mobile source, public config endpoints shipping server keys |

## Sample Vulnerable Code in Python

```python
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

@app.route("/admin/sync")
def admin_sync():
    api_key = request.headers.get("X-API-Key")
    # Hardcoded bypass key grants admin access without user authentication
    if api_key == "internal-sync-key-2024":
        return admin_dashboard()
    return "", 403

def sign_token(payload: dict) -> str:
    # JWT signing key embedded in source — cannot rotate without redeploy
    return jwt.encode(payload, "super-secret-key-not-for-production", algorithm="HS256")
```

## Step-by-Step Review Walkthrough

1. **Search authentication checks.** Look for `equals`, `==`, or `compare` against user-supplied passwords or API keys with string literals on either side.
2. **Inspect constants and config modules.** Read `config.py`, `.env` files in git, and `settings.py` for API keys, connection strings, and OAuth client secrets.
3. **Review bypass branches.** Flag OR conditions on password verification that accept a fixed string alongside normal hash checks.
4. **Trace encryption and signing.** Follow JWT, HMAC, and field-encryption code for hardcoded keys, IVs, and salts instead of key-management services.
5. **Check client-side code.** Mobile apps and front-end bundles must not ship server secrets; only public identifiers belong in client code.
6. **Follow third-party SDK initialization.** Stripe, Twilio, and cloud SDK calls often hide inline keys in setup blocks.
7. **Confirm CI/CD injects secrets at runtime.** Dockerfiles, Helm charts, and Terraform in git should reference secret names, not literal values.

## Risk Impact Analysis

**Authentication bypass.** Hardcoded backdoor passwords or API keys let attackers skip normal credential checks entirely.

**Credential theft and replay.** Keys in source propagate to forks, backups, and decompiled binaries; stolen keys work until manual rotation.

**Cloud and data exposure.** Embedded AWS or database credentials may grant broad infrastructure access beyond the application tier.

**Compliance and audit failure.** Regulators and customers expect secrets in vaults with rotation logs; hardcoded values fail basic control reviews.

**Incident response delay.** When a key leaks, teams must redeploy code instead of rotating a secret in a manager within minutes.

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
    if ("internal-sync-key-2024".equals(apiKey)) {
        return ResponseEntity.ok(adminDashboard());
    }
    return ResponseEntity.status(403).build();
}

private static final String STRIPE_SECRET = "sk_live_abc123xyz";
String jwt = Jwts.builder()
    .signWith(SignatureAlgorithm.HS256, "super-secret-key-not-for-production".getBytes())
    .compact();
```

### C#

```csharp
private const string AdminSyncKey = "internal-sync-key-2024";
private const string JwtSigningKey = "super-secret-key-not-for-production";

[HttpGet("admin/sync")]
public IActionResult AdminSync()
{
    if (Request.Headers["X-API-Key"] == AdminSyncKey)
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
    internalAPIKey = "internal-sync-key-2024"
    jwtSecret      = "super-secret-key-not-for-production"
)

func adminSync(w http.ResponseWriter, r *http.Request) {
    if r.Header.Get("X-API-Key") == internalAPIKey {
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

## Verify During Review

- No passwords, API keys, tokens, or private keys appear as string literals in application code.
- Authentication logic has no hardcoded bypass branches alongside normal credential checks.
- Secrets load from environment variables, secret managers, or encrypted configuration at runtime.
- Front-end and mobile clients use public identifiers only; sensitive keys stay on the server.
- Secret scanning runs in CI and on historical commits when onboarding a repository.
- Rotation procedures exist for every secret class; hardcoded values cannot be rotated without redeploying code.

## Reference

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
