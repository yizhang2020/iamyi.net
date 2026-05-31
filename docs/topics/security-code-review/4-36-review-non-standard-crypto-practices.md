---
title: Review Non-Standard Crypto Practices
keywords:
  - security code review
  - custom cryptography
  - crypto misuse
  - reinvent the wheel
  - CWE-327
description: How to read code for custom or non-standard cryptographic implementations that should use vetted libraries and algorithms.
---

## 4.36 - Review Non-Standard Crypto Practices

Non-standard crypto practices appear when developers implement custom ciphers, roll their own password storage, or mix hashing with encryption incorrectly. Review password utilities, token generators, field-level encryption, and checksum code labeled "secure." Prefer established libraries and documented algorithms over homegrown schemes.

## What This Vulnerability Is

Cryptography is easy to get wrong in subtle ways. Custom XOR "encryption," MD5 for passwords, static salts, ECB mode, and hand-rolled random number generators may look plausible but fail under analysis. Reinventing crypto also skips peer review, test vectors, and upstream patching that maintained libraries provide.

The unsafe assumption is that obscurity or simplicity equals security. Hashing verifies integrity or stores password digests; encryption protects confidentiality. They are not interchangeable. Weak or custom algorithms may allow offline cracking, ciphertext manipulation, or key recovery. This pattern maps to [CWE-327](https://cwe.mitre.org/data/definitions/327.html) (Use of a Broken or Risky Cryptographic Algorithm) and related misimplementation CWEs.

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Password utilities, session tokens, field encryption, "secure" checksum helpers |
| **Custom modules** | `CryptoUtil`, `EncryptHelper`, `SecureHash`, XOR loops, Caesar shifts |
| **Weak hashes** | MD5, SHA-1, or single-round SHA-256 for passwords without adaptive work factors |
| **Mode misuse** | AES-ECB, static IVs, nonce reuse in GCM implementations |
| **Bad randomness** | `Math.random`, `random.random`, time-seeded generators for tokens and keys |
| **Hash vs encrypt confusion** | Reversible password "encryption," symmetric ciphers used for credential storage |
| **TLS bypass** | `InsecureSkipVerify`, disabled hostname checks, legacy protocol enablement |

## Sample Vulnerable Code in Python

```python
import hashlib
import random

def hash_password(password: str) -> str:
    # MD5 without salt or work factor — offline cracking is trivial
    return hashlib.md5(password.encode()).hexdigest()

def make_session_token() -> str:
    # Non-cryptographic PRNG — predictable tokens
    return hashlib.md5(str(random.random()).encode()).hexdigest()

def encrypt_field(value: str, secret: str) -> bytes:
    # Custom XOR labeled as encryption — no authentication, weak key schedule
    return bytes(a ^ b for a, b in zip(value.encode(), secret.encode()))
```

## Step-by-Step Review Walkthrough

1. **Search homegrown crypto modules.** Look for custom classes named `CryptoUtil`, `EncryptHelper`, or `SecureHash`.
2. **Review password storage.** Confirm adaptive hashes (bcrypt, scrypt, Argon2) with per-user salts, not MD5 or SHA-1 alone.
3. **Inspect symmetric encryption.** Check for AES-GCM or ChaCha20-Poly1305 with random IVs; flag DES, RC4, and ECB mode.
4. **Check randomness sources.** Tokens and keys must come from cryptographically secure generators.
5. **Follow TLS configuration.** Verify certificate validation is not disabled for convenience in HTTP clients.
6. **Review signing and MAC usage.** Expect HMAC with SHA-256 or stronger, not plain hash concatenation.
7. **Confirm key provenance.** Keys should come from a key management service, not hardcoded strings or predictable derivation.

## Risk Impact Analysis

**Offline password cracking.** Weak or unsalted hashes fall to rainbow tables and GPU attacks within hours.

**Token prediction.** Non-cryptographic randomness lets attackers guess session or reset tokens.

**Ciphertext manipulation.** Custom XOR and ECB modes lack authentication; attackers may alter encrypted fields.

**Compliance failure.** PCI, HIPAA, and SOC audits expect industry-standard algorithms with documented parameters.

**False confidence.** Code labeled "encrypt" or "secure" discourages further review while providing little protection.

## Vulnerable Examples in Other Languages

### Java

```java
public static String encryptPassword(String password) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("MD5");
    return Base64.getEncoder().encodeToString(md.digest(password.getBytes()));
}

public static String obfuscate(String data, String key) {
    char[] out = new char[data.length()];
    for (int i = 0; i < data.length(); i++) {
        out[i] = (char) (data.charAt(i) ^ key.charAt(i % key.length()));
    }
    return new String(out);
}

public static String sessionToken() {
    return DigestUtils.md5Hex(String.valueOf(Math.random()));
}
```

### C#

```csharp
public string HashPassword(string password)
{
    using var sha = SHA256.Create();
    return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(password)));
}

public byte[] EncryptEcb(byte[] data, byte[] key)
{
    using var aes = Aes.Create();
    aes.Mode = CipherMode.ECB;
    using var enc = aes.CreateEncryptor(key, new byte[16]);
    return enc.TransformFinalBlock(data, 0, data.Length);
}

public string SessionToken() => Guid.NewGuid().ToString("N"); // not crypto-strength when misused for auth tokens
```

### C

```c
#include <openssl/md5.h>
#include <time.h>

void hash_password(const char *password, char *out_hex) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)password, strlen(password), digest);
    /* single-round MD5, no salt or work factor */
}

void xor_encrypt(const char *data, const char *key, char *out) {
    for (size_t i = 0; data[i]; i++)
        out[i] = data[i] ^ key[i % strlen(key)];
}

char *session_token(void) {
    static char buf[32];
    snprintf(buf, sizeof(buf), "%ld", (long)time(NULL)); /* predictable */
    return buf;
}
```

### Go

```go
func hashPassword(pw string) string {
    h := sha1.Sum([]byte(pw))
    return hex.EncodeToString(h[:])
}

func encryptField(value, secret string) []byte {
    out := make([]byte, len(value))
    for i := 0; i < len(value); i++ {
        out[i] = value[i] ^ secret[i%len(secret)]
    }
    return out
}

func token() string {
    return fmt.Sprintf("%d", time.Now().UnixNano())
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use adaptive password hashing and cryptographically secure tokens.

```python
import secrets
import bcrypt

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

def make_session_token() -> str:
    return secrets.token_urlsafe(32)
```

For authenticated encryption, use [cryptography](https://cryptography.io/en/latest/) Fernet or AES-GCM instead of manual XOR. See [Python secrets module](https://docs.python.org/3/library/secrets.html).

### Java

Use Spring Security Crypto or JCA with modern algorithms.

```java
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

public String hashPassword(String password) {
    return encoder.encode(password);
}

public boolean verifyPassword(String raw, String stored) {
    return encoder.matches(raw, stored);
}
```

Generate IVs with `SecureRandom` and use `Cipher.getInstance("AES/GCM/NoPadding")`. See [Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/21/security/java-cryptography-architecture-jca-reference-guide.html).

### C#

Use ASP.NET Core Identity password hasher or Argon2/PBKDF2 via framework APIs.

```csharp
public string HashPassword(string password)
{
    return _passwordHasher.HashPassword(_user, password);
}

public byte[] EncryptAead(byte[] plaintext, byte[] key)
{
    var nonce = RandomNumberGenerator.GetBytes(12);
    var ciphertext = new byte[plaintext.Length];
    var tag = new byte[16];
    using var aes = new AesGcm(key, tag.Length);
    aes.Encrypt(nonce, plaintext, ciphertext, tag);
    return nonce.Concat(ciphertext).Concat(tag).ToArray();
}
```

See [RandomNumberGenerator](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator) and [AesGcm](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm).

### Go

Use bcrypt or argon2 for passwords and crypto/rand for tokens.

```go
import (
    "golang.org/x/crypto/bcrypt"
    "crypto/rand"
    "encoding/base64"
)

func hashPassword(pw string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
    return string(hash), err
}

func sessionToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}
```

See [golang.org/x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt) and [crypto/rand](https://pkg.go.dev/crypto/rand).

## Verify During Review

- Passwords use adaptive hashing with per-user salts; no MD5, SHA-1, or unsalted SHA-256 for credentials.
- Symmetric encryption uses modern AEAD modes with random nonces and keys from a secure store.
- Tokens and session identifiers come from cryptographically secure random generators.
- No custom XOR, substitution, or "simple encrypt" helpers protect production data.
- TLS clients validate certificates and use current protocol versions.
- Crypto code references standards or library documentation; custom algorithms require explicit security review and are avoided by default.

## Reference

- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-328: Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [NIST SP 800-131A: Transitioning Cryptographic Algorithms](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Python secrets module](https://docs.python.org/3/library/secrets.html)
- [Python cryptography library](https://cryptography.io/en/latest/)
- [Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/21/security/java-cryptography-architecture-jca-reference-guide.html)
- [Spring Security BCryptPasswordEncoder](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder.html)
- [ASP.NET Core PasswordHasher](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.identity.passwordhasher-1)
- [Go crypto/rand](https://pkg.go.dev/crypto/rand)
