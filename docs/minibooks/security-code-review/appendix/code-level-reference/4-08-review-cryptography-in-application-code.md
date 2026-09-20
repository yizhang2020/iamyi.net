---
title: "4.8 Code Reference — Review Cryptography in Application Code"
description: >
  Payloads, sinks, multi-language examples, and fixes for Review Cryptography in Application Code.
---

# 4.8 Code Reference — Review Cryptography in Application Code

## Cryptographic implementation {: #implementation }

From former `4-13-review-cryptographic-implementation.md`. **Guiding chapter section:** [4.8 - Review Cryptography in Application Code § Cryptographic implementation](../../4-08-review-cryptography-in-application-code.md#implementation).

# 4.13 Code Reference — Review Cryptographic Implementation

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

## Non-standard crypto practices {: #non-standard }

From former `4-37-review-non-standard-crypto-practices.md`. **Guiding chapter section:** [4.8 - Review Cryptography in Application Code § Non-standard crypto practices](../../4-08-review-cryptography-in-application-code.md#non-standard).

# 4.37 Code Reference — Review Non-Standard Crypto Practices

## Attack Payloads

Use these in authorized offline tests against password hashes, tokens, and custom "encryption" helpers—not live brute-force against production without approval.

### Pattern 1: Weak password hash cracking

```text
# MD5('password') = 5f4dcc3b5aa765d61d8327deb882cf99
# SHA-1('password') = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
# Rainbow tables and hashcat recover unsalted digests in seconds
```

### Pattern 2: Predictable token guessing

```text
# Token derived from Math.random(), time(), or sequential counters
session=5f4dcc3b5aa765d61d8327deb882cf99
session=1704067200
session=00000001, 00000002, ...
```

### Pattern 3: ECB block manipulation

```text
# Identical plaintext blocks produce identical ciphertext blocks
# Attacker may swap blocks or infer structure in repeated-field messages
```

### Pattern 4: XOR key recovery (known plaintext)

```text
# If attacker knows plaintext prefix (e.g. JSON {"role":")
# XOR ciphertext with known bytes to recover key bytes for that position
```

### Pattern 5: Static IV / nonce reuse

```text
# GCM nonce reuse with same key leaks authentication key and plaintext XOR
# Reused IV in CBC enables pattern analysis across messages
```

## Language-Specific Sinks and Dangerous APIs

### Python

```python
hashlib.md5(password.encode()).hexdigest()
hashlib.sha1(password.encode()).hexdigest()
hashlib.sha256(password.encode()).hexdigest()  # single round, no salt
random.random()  # token generation
random.randint(0, 2**32)
from Crypto.Cipher import AES; AES.new(key, AES.MODE_ECB)
bytes(a ^ b for a, b in zip(data, key))  # custom XOR
Fernet(key) with hardcoded key in source
requests.get(url, verify=False)
urllib3.util.ssl_.create_urllib3_context()  # custom context without verification
```

Also review: `passlib` misconfiguration, `hmac.new` with weak key, `uuid.uuid4()` mistaken for crypto-strength session IDs.

### Java

```java
MessageDigest.getInstance("MD5");
MessageDigest.getInstance("SHA-1");
Cipher.getInstance("DES/ECB/PKCS5Padding");
Cipher.getInstance("AES/ECB/PKCS5Padding");
new SecureRandom(); // not used — Math.random() for tokens instead
DigestUtils.md5Hex(password);
TrustManager that accepts all certificates
```

### C#

```csharp
MD5.Create().ComputeHash(passwordBytes);
SHA256.Create().ComputeHash(passwordBytes);  // no salt, no work factor
Aes.Create(); aes.Mode = CipherMode.ECB;
Random().Next() for session tokens
Guid.NewGuid() as auth token without additional entropy
ServicePointManager.ServerCertificateValidationCallback = (_, _, _, _) => true;
```

### C

```c
MD5(password, len, digest);
DES_encrypt(...);
rand() for session tokens;
srand(time(NULL));
XOR loop labeled "encrypt";
SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
```

### Go

```go
md5.Sum([]byte(pw))
sha1.Sum([]byte(pw))
aes.NewCipher(key) // ECB-style manual loop
math/rand for tokens
crypto/tls.Config{InsecureSkipVerify: true}
```

### JavaScript

```javascript
crypto.createHash('md5').update(password).digest('hex');
Math.random().toString(36);  // session token
CryptoJS.AES.encrypt(data, passphrase);  // weak KDF defaults if misused
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
```

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

## Encryption and decryption mistakes {: #enc-dec }

From former `4-39-review-encryption-decryption-mistakes.md`. **Guiding chapter section:** [4.8 - Review Cryptography in Application Code § Encryption and decryption mistakes](../../4-08-review-cryptography-in-application-code.md#enc-dec).

# 4.39 Code Reference — Review Encryption and Decryption Mistakes

## Attack Payloads

Use these in authorized cryptographic review and lab testing—not against production decryption endpoints without approval.

### Pattern 1: Padding oracle probing (CBC)

```text
# Send modified ciphertext blocks; observe distinct error responses:
# "bad padding" vs "invalid format" vs HTTP 500 timing differences
# Each distinguishable response may leak one plaintext byte
```

### Pattern 2: ECB pattern analysis

```text
# Encrypt repeated 16-byte blocks; identical ciphertext blocks reveal structure
# Example: identical blocks in encrypted JSON with repeated keys
{"user":"admin","role":"admin"}  # repeated "admin" blocks align in ECB
```

### Pattern 3: GCM nonce reuse

```text
# Reusing (key, nonce) pair with different plaintexts breaks GCM confidentiality
# Attackers XOR ciphertexts to derive plaintext XOR relationships
```

### Pattern 4: Static IV exploitation

```text
# Same IV + same key + different messages → deterministic ciphertext prefixes
# Enables equality leaks and some chosen-plaintext analysis
```

### Pattern 5: Hardcoded key from source leak

```text
# Fernet key committed in settings.py: FIELD_KEY = b'abc123xyz7890123456789012345678='
# Decrypt all historical field ciphertext after repo fork or leak
grep -r "FIELD_KEY" config/
```

## Language-Specific Sinks and Dangerous APIs

### Python

```python
AES.new(KEY, AES.MODE_ECB)
AES.new(KEY, AES.MODE_CBC, iv=STATIC_IV)  # no HMAC
from Crypto.Cipher import DES3
Fernet(HARDCODED_KEY)
hashlib.pbkdf2_hmac(..., iterations=1000)  # too low
cryptography.hazmat... without AEAD
base64.b64encode(data)  # mistaken for encryption
```

Also review: `pycryptodome` without authentication tag, password-based keys without salt/KDF.

### Java

```java
Cipher.getInstance("AES/ECB/PKCS5Padding");
Cipher.getInstance("DES/ECB/PKCS5Padding");
Cipher.getInstance("AES/CBC/PKCS5Padding");  // no GCM/HMAC
SecretKeySpec(hardcodedBytes, "AES");
IvParameterSpec(staticIv);
PBEWithMD5AndDES
BadPaddingException caught and rethrown with distinct message
```

### C#

```csharp
Aes.Create(); aes.Mode = CipherMode.ECB;
Aes.Create(); aes.Mode = CipherMode.CBC;  // no GCM
RijndaelManaged with static IV
ProtectedData.Protect with hardcoded entropy
Convert.ToBase64String(plaintext)  // encoding only
CryptographicException message leaked to client
```

### Go

```go
aes.NewCipher(key)  // manual ECB loop
cipher.NewCBCEncrypter(block, staticIV)
des.NewCipher(key)
// missing cipher.NewGCM for authenticated encryption
errors.New("bad padding") returned to HTTP client
```

### C

```c
AES_ecb_encrypt(...);
AES_cbc_encrypt(..., iv, AES_ENCRYPT);  // static iv
DES_ncbc_encrypt(...);
EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), ...);
```

### SQL / config

```sql
-- Key stored beside ciphertext in same row
UPDATE users SET encrypted_ssn = ..., encryption_key = '...' WHERE id = 1;
```

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

