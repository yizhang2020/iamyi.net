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

## Abuse Scenarios

Use these patterns in authorized tests and code search. They are not injection strings—they show how weak crypto choices fail in practice.

### Pattern 1: Weak password hashing (MD5, SHA1, unsalted SHA-256)

```text
createApiKey("billing-bot", "s3cr3t-k3y")
# Stored: 5ebe2294ecd0e0f08eabebfd92c7820cd8881592  (SHA1 — crackable offline)
```

### Pattern 2: TLS verification disabled (`verify=False`)

```python
httpx.get("https://payments.example/webhook", verify=False)
# MITM can replace response or steal HMAC secrets in transit
```

### Pattern 3: ECB mode and static IV (pattern leakage)

```text
# Two blocks of identical PAN digits produce identical ciphertext blocks
encrypt_ecb(b"4111111111111111")  # card numbers with repeated digits leak structure
```

### Pattern 4: Hardcoded or default keys in source

```text
WEBHOOK_SIGNING_KEY = "dev-signing-key"
JWT signing with staging secret shipped to production
```

### Pattern 5: Custom XOR or “obfuscation” treated as encryption

```text
def mask_pan(p): return ''.join(chr(ord(c) ^ 0x42) for c in p)
# Trivially reversible; not a substitute for AES-GCM or tokenization
```

## Language-Specific Sinks and Dangerous APIs

Search for these symbols when reviewing crypto, TLS, and secret handling.

### Python

```python
import hashlib, ssl, requests
hashlib.md5(password.encode()).hexdigest()
hashlib.sha1(data).digest()
from Crypto.Cipher import AES
AES.new(key, AES.MODE_ECB).encrypt(plain)
requests.get(url, verify=False)
ssl._create_unverified_context()
```

### Java

```java
MessageDigest.getInstance("MD5").digest(password.getBytes());
Cipher.getInstance("AES/ECB/PKCS5Padding");
SSLContext.getInstance("SSL").init(null, trustAllCerts, null);
HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
```

### C#

```csharp
MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(password));
Aes.Create(); aes.Mode = CipherMode.ECB;
new HttpClient(new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true });
```

### JavaScript (Node.js)

```javascript
const crypto = require('crypto');
crypto.createHash('md5').update(password).digest('hex');
crypto.createCipheriv('aes-128-ecb', key, null);
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
```

### Go

```go
md5.Sum([]byte(password))
aes.NewCipher(key) // used in ECB-style loops without GCM
http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
```

### C

```c
MD5(password, len, digest);
EVP_aes_128_ecb();
SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
```

## Sample Vulnerable Code in Python

```python
import hashlib
import httpx

WEBHOOK_SIGNING_KEY = "dev-only-signing-key"
API_KEY_STORE = {}

def create_api_key(client_name, secret):
    # SHA1 is not a password hash; no salt or slow hash
    API_KEY_STORE[client_name] = hashlib.sha1(secret.encode()).hexdigest()

def store_payment_token(user_id, pan):
    # Sensitive card data written to disk in cleartext
    with open(f"/var/data/tokens/{user_id}.txt", "w") as f:
        f.write(pan)

def deliver_webhook(url, payload):
    # TLS verification disabled; attacker can MITM
    return httpx.post(url, content=payload, verify=False, timeout=10).text
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
public class WebhookClient {
    private static final String HMAC_SECRET = "wh_live_abc123";

    public String post(String url, byte[] body) throws Exception {
        TrustManager[] trustAll = { new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new SecureRandom());
        HttpsURLConnection conn = (HttpsURLConnection) new URL(url).openConnection();
        conn.setSSLSocketFactory(ctx.getSocketFactory());
        conn.setRequestProperty("X-Signature", hmacSha1(body, HMAC_SECRET));
        return new String(conn.getInputStream().readAllBytes());
    }
}
```

### C#

```csharp
public string TokenizePan(string pan)
{
    var key = Encoding.UTF8.GetBytes("Static16ByteKey!");
    using var aes = Aes.Create();
    aes.Key = key;
    aes.Mode = CipherMode.ECB;
    aes.Padding = PaddingMode.PKCS7;
    using var enc = aes.CreateEncryptor();
    return Convert.ToBase64String(enc.TransformFinalBlock(
        Encoding.UTF8.GetBytes(pan), 0, pan.Length));
}
```

### Go

```go
func hashApiSecret(secret string) string {
    h := md5.Sum([]byte(secret))
    return hex.EncodeToString(h[:])
}

func postWebhook(url string, body []byte) ([]byte, error) {
    tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
    client := &http.Client{Transport: tr}
    req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
    req.Header.Set("X-Signature", signHmacMD5(body, os.Getenv("DEV_HMAC")))
    resp, err := client.Do(req)
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
import httpx

ph = PasswordHasher()
FERNET_KEY = os.environ["TOKEN_VAULT_KEY"].encode()
fernet = Fernet(FERNET_KEY)

def create_api_key(client_name, secret):
    API_KEY_STORE[client_name] = ph.hash(secret)

def store_payment_token(user_id, pan):
    token = fernet.encrypt(pan.encode())
    db.execute("UPDATE users SET pan_token = ? WHERE id = ?", (token, user_id))

def deliver_webhook(url, payload):
    return httpx.post(url, content=payload, verify=True, timeout=10).text
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
