---
title: Review Cryptographic Implementation
keywords:
  - security code review
  - cryptography
  - TLS
  - secrets management
  - encryption
  - hashing
description: How to read code for weak cryptographic implementation—trace secret loading, TLS settings, hashing vs encryption, and data at rest and in transit.
---

## 4.12 - Review Cryptographic Implementation

Cryptographic mistakes often hide in configuration and small utility classes rather than in obvious crypto modules. Review how secrets are loaded, which protocols protect data in transit, and whether hashing and encryption are used for the right purpose. Trace sensitive fields from storage through outbound HTTP clients and confirm established libraries handle algorithms and key material.

## What This Vulnerability Is

Cryptographic implementation flaws weaken confidentiality, integrity, or authenticity of sensitive data. Common problems include hardcoded keys, disabled certificate verification, weak or custom algorithms, confusing hashing with encryption, and storing or transmitting secrets without protection.

The unsafe assumption is that obscurity, home-grown routines, or legacy protocols are good enough. Attackers who obtain ciphertext, traffic, or source code can often recover secrets or impersonate services. This review area spans [CWE-326](https://cwe.mitre.org/data/definitions/326.html) (Inadequate Encryption Strength), [CWE-327](https://cwe.mitre.org/data/definitions/327.html) (Use of a Broken or Risky Cryptographic Algorithm), and [CWE-798](https://cwe.mitre.org/data/definitions/798.html) (Use of Hard-coded Credentials).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Password storage, API clients, file encryption helpers, payment tokenization, webhook signing |
| **Secret loading** | Environment variables, config files, KMS integrations, literals in source or committed test fixtures |
| **TLS clients** | `requests.get`, `HttpClient`, custom SSL contexts, outbound webhooks, import-from-URL features |
| **Hash vs encrypt** | Password "encryption," MD5/SHA1 for credentials, bare SHA-256 without salt, reversible credential storage |
| **Custom crypto** | XOR loops, ECB mode, static IVs, hand-rolled AES, missing authentication on ciphertext |
| **Data at rest** | Database columns, flat files, S3 objects, backups, and caches holding PII, tokens, or payment data |

## Sample Vulnerable Code in Python

```python
import hashlib
import requests

SECRET_KEY = "dev-only-change-me"
PASSWORD_STORE = {}

def register(username, password):
    # MD5 is not a password hash; no salt
    PASSWORD_STORE[username] = hashlib.md5(password.encode()).hexdigest()

def save_customer_ssn(user_id, ssn):
    # Sensitive data written to disk in cleartext
    with open(f"/var/data/{user_id}.dat", "w") as f:
        f.write(ssn)

def fetch_partner_report(url):
    # TLS verification disabled; attacker can MITM
    return requests.get(url, verify=False, timeout=10).text
```

## Step-by-Step Review Walkthrough

1. **Find secret and key loading.** Search for API keys, JWT signing keys, database passwords, and Fernet keys in source, fixtures, and default config. Confirm production keys come from environment, vault, or cloud secret stores.
2. **Trace outbound HTTPS and TLS client configuration.** Inspect `verify=False`, permissive hostname verifiers, SSLv3/TLS 1.0, and trust-all certificate callbacks in HTTP clients.
3. **Locate password and token handling.** Distinguish one-way hashing for verification from reversible encryption for data that must be recovered. Flag MD5, SHA1, or unsalted SHA-256 used for passwords.
4. **Search for custom crypto.** Hand-rolled AES, RSA padding choices, ECB mode, static IVs, and "simple obfuscation" helpers used for real protection are high priority.
5. **Review data at rest.** Follow PII, tokens, and payment fields into database columns, file writes, backups, and caches. Confirm field-level or envelope encryption where policy requires it.
6. **Review data in transit.** Check service-to-service calls, webhooks, message queues, and mobile API clients for plain HTTP on reachable networks.
7. **Confirm operational hygiene.** Key rotation, separation of dev and prod secrets, and logs that never print keys, seeds, or decrypted payloads.

## Risk Impact Analysis

**Credential and key exposure.** Hardcoded secrets in source or images let anyone with repo or container access impersonate services or decrypt stored data.

**Traffic interception.** Disabled TLS verification allows man-in-the-middle attacks on outbound calls, exposing tokens, PII, and session data in transit.

**Password recovery.** Weak or unsalted hashes enable offline cracking when database dumps leak; reversible "encryption" of passwords exposes cleartext to anyone with the key.

**Data breach amplification.** Cleartext storage of SSNs, health records, or payment data turns a filesystem or backup leak into a reportable incident.

**Compliance and trust.** Weak crypto undermines PCI, HIPAA, and contractual security requirements and erodes customer confidence after disclosure.

## Vulnerable Examples in Other Languages

### Java

```java
public class ApiClient {
    private static final String API_KEY = "sk_live_abc123";

    public String fetch(String url) throws Exception {
        TrustManager[] trustAll = { new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new SecureRandom());
        HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
        conn.setSSLSocketFactory(ctx.getSocketFactory());
        conn.setRequestProperty("Authorization", "Bearer " + API_KEY);
        return new String(conn.getInputStream().readAllBytes());
    }
}
```

### C#

```csharp
public string Protect(string plaintext)
{
    var key = Encoding.UTF8.GetBytes("My16ByteKey!!!!!");
    using var aes = Aes.Create();
    aes.Key = key;
    aes.Mode = CipherMode.ECB;
    aes.Padding = PaddingMode.PKCS7;
    using var enc = aes.CreateEncryptor();
    return Convert.ToBase64String(enc.TransformFinalBlock(
        Encoding.UTF8.GetBytes(plaintext), 0, plaintext.Length));
}
```

### Go

```go
func hashPassword(pw string) string {
    h := sha1.Sum([]byte(pw))
    return hex.EncodeToString(h[:])
}

func downloadReport(url string) ([]byte, error) {
    tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
    client := &http.Client{Transport: tr}
    resp, err := client.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    return io.ReadAll(resp.Body)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Load secrets from the environment and fail fast when missing. Use slow password hashes and authenticated encryption for application-level secrets at rest.

```python
import os
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
import requests

ph = PasswordHasher()
FERNET_KEY = os.environ["APP_FERNET_KEY"].encode()
fernet = Fernet(FERNET_KEY)

def register(username, password):
    PASSWORD_STORE[username] = ph.hash(password)

def save_customer_ssn(user_id, ssn):
    token = fernet.encrypt(ssn.encode())
    db.execute("UPDATE users SET ssn_enc = ? WHERE id = ?", (token, user_id))

def fetch_partner_report(url):
    return requests.get(url, verify=True, timeout=10).text
```

**Important:** Never commit production keys. Use `ssl.create_default_context()` for custom TLS clients and enforce TLS 1.2+.

### Java

Use platform TLS defaults and vetted password encoders. Prefer AEAD modes with random IVs.

```java
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public byte[] encryptField(byte[] plaintext, byte[] key) throws Exception {
    byte[] iv = new byte[12];
    new SecureRandom().nextBytes(iv);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
    byte[] ciphertext = cipher.doFinal(plaintext);
    // prepend IV for storage
    return ByteBuffer.allocate(iv.length + ciphertext.length).put(iv).put(ciphertext).array();
}

public String hashPassword(String raw) {
    return new BCryptPasswordEncoder().encode(raw);
}
```

**Important:** Load API keys from vault or environment. Do not disable certificate verification in production HTTP clients.

### C#

Use `AesGcm` with unique nonces and ASP.NET Identity or PBKDF2 for passwords.

```csharp
public static string Protect(string plaintext, byte[] key)
{
    var nonce = RandomNumberGenerator.GetBytes(12);
    var plainBytes = Encoding.UTF8.GetBytes(plaintext);
    var cipher = new byte[plainBytes.Length];
    var tag = new byte[16];
    using var aes = new AesGcm(key, tagSizeInBytes: 16);
    aes.Encrypt(nonce, plainBytes, cipher, tag);
    return Convert.ToBase64String(nonce.Concat(tag).Concat(cipher).ToArray());
}

// ASP.NET Core Identity handles password hashing:
// await _userManager.CreateAsync(user, password);
```

**Important:** Inject connection strings and API keys from Azure Key Vault, AWS Secrets Manager, or configuration providers—not source code.

### Go

Use bcrypt or Argon2 for passwords and GCM for application encryption. Keep TLS verification enabled.

```go
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "golang.org/x/crypto/bcrypt"
)

func hashPassword(pw string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
    return string(hash), err
}

func encryptField(key, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }
    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}
```

**Important:** Set `MinVersion: tls.VersionTLS12` on custom transports. Fetch secrets at runtime from Vault or cloud SDKs.

## Verify During Review

- No production secrets in source, images, or default configuration checked into the repository.
- TLS clients verify certificates and hostnames; minimum protocol is TLS 1.2 or 1.3.
- Passwords use slow password hashes; reversible encryption is reserved for data that must be recovered.
- Application crypto uses vetted libraries and modern AEAD modes; no custom ciphers or ECB for structured data.
- Sensitive data at rest is encrypted or tokenized; backups and replicas inherit the same controls.
- Internal and external API calls that carry secrets use HTTPS or equivalent mutual TLS.
- Logging and error paths do not emit keys, seeds, plaintext passwords, or decrypted payloads.

## Reference

- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-132: Password-Based Key Derivation](https://csrc.nist.gov/publications/detail/sp/800-132/final)
- [Python cryptography library](https://cryptography.io/en/latest/)
- [argon2-cffi documentation](https://argon2-cffi.readthedocs.io/en/stable/)
- [Spring Security — Password Storage](https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html)
- [ASP.NET Core — Data Protection](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/introduction)
- [Go crypto/tls package](https://pkg.go.dev/crypto/tls)
- [Go golang.org/x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt)
