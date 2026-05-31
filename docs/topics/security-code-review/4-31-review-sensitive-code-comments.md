---
title: Review Sensitive Code Comments
keywords:
  - security code review
  - sensitive comments
  - information disclosure
  - hardcoded credentials
  - CWE-615
description: How to read code for sensitive information in comments, TODO notes, and inline documentation that should not be in source control.
---

## 4.31 - Review Sensitive Code Comments

Comments and TODO notes can leak passwords, bypass hints, internal hostnames, and unfinished security work. Review HTML comments, block comments, and commit messages referenced in code. Search for credential language, admin paths, and temporary workarounds that describe how to defeat a control.

## What This Vulnerability Is

Source code comments are not executed, but they are often stored in version control, included in builds, and visible to anyone with repository access. When comments contain passwords, password hints, API keys, or instructions to weaken security, they create an information disclosure risk. Attackers who obtain source may use those notes to bypass authentication or reach hidden functionality.

The unsafe assumption is that comments are private or harmless. In practice, comments travel with the codebase across environments and may appear in diffs, IDE tooltips, and generated documentation. This maps to [CWE-615](https://cwe.mitre.org/data/definitions/615.html) (Inclusion of Sensitive Information in Source Code Comments).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Comment types** | Block comments, HTML `<!-- -->`, Javadoc, docstrings, TODO/FIXME/HACK markers |
| **Credential language** | `password`, `secret`, `key`, `token`, example values that look real |
| **Bypass hints** | Instructions to skip MFA, disable validation, or use a backdoor account |
| **Internal topology** | Internal hostnames, database names, unreleased feature flags in comments |
| **HTML exposure** | JSP, Thymeleaf, static HTML comments visible in page source |
| **Commented-out code** | Disabled auth checks and hardcoded overrides left for debugging |

## Sample Vulnerable Code in Python

```python
def verify_admin(user, password):
    # Backdoor for QA — remove before launch (still here in prod)
    if password == "qa_override_2024":
        return True
    return check_password_hash(user.password_hash, password)
```

## Step-by-Step Review Walkthrough

1. **Search for credential language in comments.** Look for passwords, secrets, tokens, keys, admin, bypass, or temporary fixes across the repository.
2. **Trace the Python admin verifier.** In the sample, a comment documents a live backdoor password. Remove the bypass and track QA needs in a secure runbook.
3. **Review HTML comments in templates.** These often survive into production pages and appear in browser view-source.
4. **Inspect TODO and FIXME markers near auth, crypto, and payment flows.** Long-lived security TODOs are findings when they describe known weaknesses.
5. **Check deployment and IaC comments.** Dockerfiles and Terraform files may embed operational secrets in comments.
6. **Follow commented-out code blocks.** Old credentials or disabled security checks are easy to re-enable.
7. **Confirm operational details live in access-controlled runbooks.** Not inline in application source.

## Risk Impact Analysis

**Authentication bypass.** Backdoor passwords and skip instructions in comments give attackers a direct path past controls.

**Credential theft from repos.** API keys and connection strings in comments leak through git history, forks, and CI artifacts.

**Targeted attacks.** Internal hostnames and topology notes help attackers map the environment after partial access.

**Compliance and trust.** Sensitive comments in production code undermine secure development attestations.

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

## Verify During Review

- No passwords, API keys, tokens, or bypass instructions appear in comments, HTML, or commit messages in the repository.
- TODO and FIXME items on security work are tracked in issue trackers with restricted access, not as inline hints.
- Commented-out authentication, authorization, or validation code is removed rather than left as a re-enable target.
- Static secret scanning runs on every push and blocks merges when comments contain high-risk patterns.
- Production page source does not expose sensitive HTML comments to unauthenticated users.

## Reference

- [CWE-615: Inclusion of Sensitive Information in Source Code Comments](https://cwe.mitre.org/data/definitions/615.html)
- [OWASP — Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [Python os.environ](https://docs.python.org/3/library/os.html#os.environ)
- [dotnet user-secrets](https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets)
- [Azure Key Vault configuration provider](https://learn.microsoft.com/en-us/aspnet/core/security/key-vault-configuration)
- [HashiCorp Vault](https://developer.hashicorp.com/vault/docs)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
