---
title: Review Cryptography in Application Code
keywords:
  - cryptography
  - encryption
  - hashing
  - non-standard crypto
description: Review cryptographic implementation, non-standard crypto, and enc/dec mistakes.
---

## 4.8 - Review Cryptography in Application Code

### Overview

Application crypto fails when we invent protocols, misuse modes/IVs, or treat encoding as confidentiality. Prefer vetted libraries, current algorithms, and explicit key management—then verify those choices in code.

The points below are the ideas this family chapter uses again and again.

1. Application crypto fails when algorithms, modes, keys, or randomness are wrong for the threat.
2. Prefer vetted libraries and standard constructions over home-grown designs.
3. Implementation mistakes, non-standard practices, and enc/dec errors share that failure.
4. Separate confidentiality from integrity; know when AEAD is required.
5. Evidence names the crypto decision, missing control, impact, and a proving test.

After reading this chapter, we should be able to review application cryptography for standard constructions, key handling, and integrity needs.

## Shared Review Model

Across every variant below, keep the same evidence habit: name the **source**, the **sink**, the **missing control**, the **impact**, and a **test** that would prove a fix.

## Variants in This Family

### Cryptographic implementation {: #implementation }

Cryptographic implementation flaws weaken confidentiality, integrity, or authenticity of sensitive data. Common problems include hardcoded keys, disabled certificate verification, weak or custom algorithms, confusing hashing with encryption, and storing or transmitting secrets without protection.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Password storage, API clients, file encryption helpers, payment tokenization, webhook signing |
| **Secret loading** | Environment variables, config files, KMS integrations, literals in source or committed test fixtures |
| **TLS clients** | `requests.get`, `HttpClient`, custom SSL contexts, outbound webhooks, import-from-URL features |
| **Hash vs encrypt** | Password "encryption," MD5/SHA1 for credentials, bare SHA-256 without salt, reversible credential storage |
| **Custom crypto** | XOR loops, ECB mode, static IVs, hand-rolled AES, missing authentication on ciphertext |
| **Data at rest** | Database columns, flat files, S3 objects, backups, and caches holding PII, tokens, or payment data |

**Appendix detail:** [Cryptographic implementation code reference](appendix/code-level-reference/4-08-review-cryptography-in-application-code.md#implementation).

### Non-standard crypto practices {: #non-standard }

Cryptography is easy to get wrong in subtle ways. Custom XOR "encryption," MD5 for passwords, static salts, ECB mode, and hand-rolled random number generators may look plausible but fail under analysis. Reinventing crypto also skips peer review, test vectors, and upstream patching that maintained libraries provide.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Password utilities, session tokens, field encryption, "secure" checksum helpers |
| **Custom modules** | `CryptoUtil`, `EncryptHelper`, `SecureHash`, XOR loops, Caesar shifts |
| **Weak hashes** | MD5, SHA-1, or single-round SHA-256 for passwords without adaptive work factors |
| **Mode misuse** | AES-ECB, static IVs, nonce reuse in GCM implementations |
| **Bad randomness** | `Math.random`, `random.random`, time-seeded generators for tokens and keys |
| **Hash vs encrypt confusion** | Reversible password "encryption," symmetric ciphers used for credential storage |
| **TLS bypass** | `InsecureSkipVerify`, disabled hostname checks, legacy protocol enablement |

**Appendix detail:** [Non-standard crypto practices code reference](appendix/code-level-reference/4-08-review-cryptography-in-application-code.md#non-standard).

### Encryption and decryption mistakes {: #enc-dec }

Encryption protects confidentiality; without authentication, attackers may tamper with ciphertext or perform padding oracle attacks. Common mistakes include AES-ECB for structured data, reusing IVs with GCM, deriving keys from passwords without KDFs, storing keys next to ciphertext, and confusing encoding (Base64) with encryption. Decryption endpoints may also become oracle surfaces when they return distinct errors for bad padding versus bad data.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Field-level encryption, token wrapping, PII tokenization, backup protection, file at rest |
| **Weak modes** | AES-ECB, DES, 3DES, RC4, CBC without HMAC |
| **IV/nonce issues** | Hardcoded IV arrays, counters reset on restart, GCM nonce reuse |
| **Key handling** | Keys in source, config in git, keys stored beside ciphertext in the same database |
| **Missing authentication** | Encrypt-then-none patterns without GCM or encrypt-then-MAC |
| **Oracle behavior** | Decryption endpoints returning different errors for padding vs format failures |
| **Wrong primitive** | Reversible encryption of passwords instead of adaptive hashing |

**Appendix detail:** [Encryption and decryption mistakes code reference](appendix/code-level-reference/4-08-review-cryptography-in-application-code.md#enc-dec).

## Worked Example (Cryptographic implementation)

We walk **Cryptographic implementation** in depth. Apply the same tracing steps to the other variants, adjusting sources and sinks from the tables above.

### Sample vulnerable code (Python)

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

### Step-by-step review walkthrough

1. **Find secret and key loading.** Search for API keys, JWT signing keys, database passwords, and Fernet keys in source, fixtures, and default config. Confirm production keys come from environment, vault, or cloud secret stores.
2. **Trace outbound HTTPS and TLS client configuration.** Inspect `verify=False`, permissive hostname verifiers, SSLv3/TLS 1.0, and trust-all certificate callbacks in HTTP clients.
3. **Locate password and token handling.** Distinguish one-way hashing for verification from reversible encryption for data that must be recovered. Flag MD5, SHA1, or unsalted SHA-256 used for passwords.
4. **Search for custom crypto.** Hand-rolled AES, RSA padding choices, ECB mode, static IVs, and "simple obfuscation" helpers used for real protection are high priority.
5. **Review data at rest.** Follow PII, tokens, and payment fields into database columns, file writes, backups, and caches. Confirm field-level or envelope encryption where policy requires it.
6. **Review data in transit.** Check service-to-service calls, webhooks, message queues, and mobile API clients for plain HTTP on reachable networks.
7. **Confirm operational hygiene.** Key rotation, separation of dev and prod secrets, and logs that never print keys, seeds, or decrypted payloads.

## Risk Impact (Family)

**Credential and key exposure.** Hardcoded secrets in source or images let anyone with repo or container access impersonate services or decrypt stored data.

**Traffic interception.** Disabled TLS verification allows man-in-the-middle attacks on outbound calls, exposing tokens, PII, and session data in transit.

**Password recovery.** Weak or unsalted hashes enable offline cracking when database dumps leak; reversible "encryption" of passwords exposes cleartext to anyone with the key.

**Data breach amplification.** Cleartext storage of SSNs, health records, or payment data turns a filesystem or backup leak into a reportable incident.

**Compliance and trust.** Weak crypto undermines PCI, HIPAA, and contractual security requirements and erodes customer confidence after disclosure.

## Fix Principles

Primary safer patterns for the worked example follow. For other languages and variant-specific fixes, use the [family appendix](appendix/code-level-reference/4-08-review-cryptography-in-application-code.md).

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

## Verify During Review

Use the checklist below as a family-level pass over the variants above. Each item should map to evidence in the change under review.

- No production secrets in source, images, or default configuration checked into the repository.
- TLS clients verify certificates and hostnames; minimum protocol is TLS 1.2 or 1.3.
- Passwords use slow password hashes; reversible encryption is reserved for data that must be recovered.
- Application crypto uses vetted libraries and modern AEAD modes; no custom ciphers or ECB for structured data.
- Sensitive data at rest is encrypted or tokenized; backups and replicas inherit the same controls.
- Internal and external API calls that carry secrets use HTTPS or equivalent mutual TLS.
- Logging and error paths do not emit keys, seeds, plaintext passwords, or decrypted payloads.
- Passwords use adaptive hashing with per-user salts; no MD5, SHA-1, or unsalted SHA-256 for credentials.
- Symmetric encryption uses modern AEAD modes with random nonces and keys from a secure store.
- Tokens and session identifiers come from cryptographically secure random generators.
- No custom XOR, substitution, or "simple encrypt" helpers protect production data.
- TLS clients validate certificates and use current protocol versions.
- Crypto code references standards or library documentation; custom algorithms require explicit security review and are avoided by default.
- Sensitive data at rest and in tokens uses modern AEAD with unique nonces per encryption operation.
- Keys are stored in KMS, HSM, or secret managers—not in source control or client bundles.
- Passwords are hashed with adaptive algorithms; reversible encryption is reserved for data that must be read back.
- Decryption failures return generic errors to callers; logs do not leak padding or oracle details to untrusted users.
- Key rotation and access logging exist for production encryption keys.
- Encoding (Base64, hex) is not mistaken for encryption in design documents or variable names.

## Code Reference (Appendix)

Payloads, language-specific sinks, multi-language examples, and full fix catalogs for every variant live in **[4.8 code reference — Review Cryptography in Application Code](appendix/code-level-reference/4-08-review-cryptography-in-application-code.md)**.

## Reference

- Appendix — [4.8 code reference](appendix/code-level-reference/4-08-review-cryptography-in-application-code.md)

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
- [CWE-328: Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
- [NIST SP 800-131A: Transitioning Cryptographic Algorithms](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)
- [Python secrets module](https://docs.python.org/3/library/secrets.html)
- [Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/21/security/java-cryptography-architecture-jca-reference-guide.html)
- [Spring Security BCryptPasswordEncoder](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder.html)
- [ASP.NET Core PasswordHasher](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.identity.passwordhasher-1)
- [Go crypto/rand](https://pkg.go.dev/crypto/rand)
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [NIST SP 800-38D: GCM Mode](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Python cryptography AESGCM](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
- [Java Cipher AES/GCM/NoPadding](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html)
- [ASP.NET Core AesGcm](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesgcm)
- [Go crypto/cipher NewGCM](https://pkg.go.dev/crypto/cipher#NewGCM)
