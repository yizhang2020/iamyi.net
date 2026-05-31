---
title: Review Encryption and Decryption Mistakes
keywords:
  - security code review
  - encryption mistakes
  - decryption
  - key management
  - authenticated encryption
  - CWE-311
description: How to read code for encryption and decryption mistakes including missing authentication, static IVs, and key handling errors.
---

## 4.38 - Review Encryption and Decryption Mistakes

Encryption and decryption mistakes appear when data is protected with weak algorithms, static IVs, missing authentication, or keys stored alongside ciphertext. Review field-level encryption, token wrapping, file protection, and database column encryptors. Confirm each use case needs confidentiality, integrity, or both—and that the implementation matches.

## What This Vulnerability Is

Encryption protects confidentiality; without authentication, attackers may tamper with ciphertext or perform padding oracle attacks. Common mistakes include AES-ECB for structured data, reusing IVs with GCM, deriving keys from passwords without KDFs, storing keys next to ciphertext, and confusing encoding (Base64) with encryption. Decryption endpoints may also become oracle surfaces when they return distinct errors for bad padding versus bad data.

The unsafe assumption is that any encryption call makes data safe. Correct designs choose AEAD modes, manage keys in HSMs or vaults, rotate material, and separate duties between encrypting systems and key custodians. Hashing is for verification and password storage; it does not replace encryption when reversible access is required. This pattern relates to [CWE-311](https://cwe.mitre.org/data/definitions/311.html) (Missing Encryption of Sensitive Data) and [CWE-326](https://cwe.mitre.org/data/definitions/326.html) (Inadequate Encryption Strength).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Field-level encryption, token wrapping, PII tokenization, backup protection, file at rest |
| **Weak modes** | AES-ECB, DES, 3DES, RC4, CBC without HMAC |
| **IV/nonce issues** | Hardcoded IV arrays, counters reset on restart, GCM nonce reuse |
| **Key handling** | Keys in source, config in git, keys stored beside ciphertext in the same database |
| **Missing authentication** | Encrypt-then-none patterns without GCM or encrypt-then-MAC |
| **Oracle behavior** | Decryption endpoints returning different errors for padding vs format failures |
| **Wrong primitive** | Reversible encryption of passwords instead of adaptive hashing |

## Sample Vulnerable Code in Python

```python
from Crypto.Cipher import AES

KEY = b"0123456789012345"  # hardcoded key in source

def encrypt(data: bytes) -> bytes:
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(data))

def decrypt(token: bytes) -> bytes:
    try:
        return unpad(AES.new(KEY, AES.MODE_ECB).decrypt(token))
    except ValueError:
        # Distinct error reveals padding validity to attackers
        raise BadPaddingError("invalid padding")
```

## Step-by-Step Review Walkthrough

1. **Map each encryption use case.** Identify data at rest, in transit, token wrapping, PII tokenization, and backup protection flows.
2. **Identify algorithm and mode.** Prefer AES-GCM or ChaCha20-Poly1305; flag DES, RC4, and AES-ECB.
3. **Check IV or nonce generation.** Nonces must be unique per message with GCM; static IVs break confidentiality.
4. **Verify authentication.** Ciphertext should include MAC or use AEAD; encryption alone does not provide integrity.
5. **Trace key storage.** Keys should not live in source, git config, or the same database row as ciphertext without access controls.
6. **Review password-based encryption.** Use PBKDF2, scrypt, or Argon2 with high work factors before deriving keys.
7. **Inspect decryption error handling.** Avoid distinguishable error messages that leak padding validity to attackers.

## Risk Impact Analysis

**Ciphertext tampering.** Without authentication, attackers may alter encrypted fields, tokens, or files without detection.

**Padding oracle attacks.** Distinct decryption errors on CBC-mode ciphertext may leak plaintext byte by byte.

**Key compromise from source leaks.** Hardcoded keys in repositories expose all historical ciphertext when the repo is copied or forked.

**Nonce reuse in GCM.** Reusing a GCM nonce with the same key catastrophically breaks confidentiality and integrity.

**Regulatory exposure.** Unencrypted or weakly encrypted PII and payment data fail PCI, HIPAA, and GDPR technical control expectations.

## Vulnerable Examples in Other Languages

### Java

```java
private static final byte[] KEY = "0123456789012345".getBytes(StandardCharsets.UTF_8);

public byte[] encrypt(byte[] plaintext) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    SecretKeySpec spec = new SecretKeySpec(KEY, "AES");
    cipher.init(Cipher.ENCRYPT_MODE, spec);
    return cipher.doFinal(plaintext);
}

public byte[] decrypt(byte[] ciphertext) throws Exception {
    try {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, "AES"));
        return cipher.doFinal(ciphertext);
    } catch (BadPaddingException e) {
        throw new BadPaddingError("invalid padding"); // distinguishable error
    }
}

private static final byte[] IV = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
```

### C#

```csharp
private static readonly byte[] Key = Encoding.UTF8.GetBytes("0123456789012345");

public string Encrypt(string plain)
{
    using var aes = Aes.Create();
    aes.Key = Key;
    aes.Mode = CipherMode.ECB;
    using var enc = aes.CreateEncryptor();
    return Convert.ToBase64String(enc.TransformFinalBlock(
        Encoding.UTF8.GetBytes(plain), 0, plain.Length));
}

public string Decrypt(string token)
{
    try {
        /* ECB decrypt */
    } catch (CryptographicException) {
        throw new BadPaddingException("invalid padding"); // leaks validity to callers
    }
}
```

### Go

```go
var appKey = []byte("sixteen-byte-key")

func Encrypt(data []byte) []byte {
    block, _ := aes.NewCipher(appKey)
    ciphertext := make([]byte, len(data))
    block.Encrypt(ciphertext, data) // ECB-style block loop without authentication
    return ciphertext
}

func Decrypt(token []byte) ([]byte, error) {
    block, _ := aes.NewCipher(appKey)
    out := make([]byte, len(token))
    block.Decrypt(out, token)
    if !validPadding(out) {
        return nil, errors.New("bad padding") // oracle-friendly error
    }
    return out, nil
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use AES-GCM with random nonces and keys from environment or KMS.

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def get_key() -> bytes:
    return bytes.fromhex(os.environ["DATA_ENCRYPTION_KEY"])

def encrypt(plaintext: bytes) -> bytes:
    key = get_key()
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data=None)
    return nonce + ciphertext

def decrypt(blob: bytes) -> bytes:
    key = get_key()
    nonce, ciphertext = blob[:12], blob[12:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data=None)
    except Exception:
        raise ValueError("decryption failed")  # generic error to callers
```

See [cryptography AESGCM](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM) and [Fernet](https://cryptography.io/en/latest/fernet/) for opinionated token formats.

### Java

Use AES/GCM with SecureRandom IVs per operation. Wrap data keys with KMS.

```java
public byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception {
    byte[] iv = new byte[12];
    SecureRandom.getInstanceStrong().nextBytes(iv);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    GCMParameterSpec spec = new GCMParameterSpec(128, iv);
    cipher.init(Cipher.ENCRYPT_MODE, key, spec);
    byte[] ciphertext = cipher.doFinal(plaintext);
    return ByteBuffer.allocate(iv.length + ciphertext.length)
        .put(iv).put(ciphertext).array();
}
```

Integrate [AWS KMS](https://docs.aws.amazon.com/kms/) or [Google Cloud KMS](https://cloud.google.com/kms/docs) for envelope encryption.

### C#

Use AesGcm with proper nonce handling and Key Vault for key storage.

```csharp
public byte[] Encrypt(byte[] plaintext, byte[] key)
{
    var nonce = RandomNumberGenerator.GetBytes(12);
    var ciphertext = new byte[plaintext.Length];
    var tag = new byte[16];
    using var aes = new AesGcm(key, tag.Length);
    aes.Encrypt(nonce, plaintext, ciphertext, tag);
    return nonce.Concat(ciphertext).Concat(tag).ToArray();
}
```

Use [ASP.NET Core Data Protection](https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/introduction) for key ring management and rotation.

### Go

Use crypto/cipher.NewGCM with random nonces from crypto/rand.

```go
func Encrypt(key, plaintext []byte) ([]byte, error) {
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

See [crypto/cipher NewGCM](https://pkg.go.dev/crypto/cipher#NewGCM) and [age](https://age-encryption.org/docs) for higher-level file encryption.

## Verify During Review

- Sensitive data at rest and in tokens uses modern AEAD with unique nonces per encryption operation.
- Keys are stored in KMS, HSM, or secret managers—not in source control or client bundles.
- Passwords are hashed with adaptive algorithms; reversible encryption is reserved for data that must be read back.
- Decryption failures return generic errors to callers; logs do not leak padding or oracle details to untrusted users.
- Key rotation and access logging exist for production encryption keys.
- Encoding (Base64, hex) is not mistaken for encryption in design documents or variable names.

## Reference

- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [NIST SP 800-38D: GCM Mode](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Python cryptography AESGCM](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
- [Java Cipher AES/GCM/NoPadding](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html)
- [ASP.NET Core AesGcm](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm)
- [Go crypto/cipher NewGCM](https://pkg.go.dev/crypto/cipher#NewGCM)
