---
title: Review TLS and SSL Protocol Configuration
keywords:
  - security code review
  - TLS
  - TLS 1.2
  - TLS 1.3
  - cipher suites
  - certificate verification
  - hostname validation
description: How to review TLS client and server configuration—protocol versions, cipher suites, certificate chain validation, and hostname checks without legacy SSL.
---

## 10.5 - Review TLS and SSL Protocol Configuration

Transport Layer Security (TLS) protects data in transit when clients and servers negotiate versions, ciphers, and trust correctly. Review server listeners, outbound HTTP clients, SDK defaults, and reverse-proxy settings together. Focus on TLS 1.2 and TLS 1.3, strong cipher selection, full chain validation, and hostname matching—not legacy SSL or SSLv3.

## What This Vulnerability Is

TLS misconfiguration weakens confidentiality and authenticity even when URLs use `https://`. Common failures include enabling obsolete protocols, accepting weak ciphers, skipping certificate chain validation, or not checking that the certificate matches the intended host name.

The unsafe assumption is that any TLS handshake is equivalent to a verified, correctly scoped connection. Attackers may downgrade traffic, decrypt weak sessions, or intercept calls through man-in-the-middle (MITM) when verification is disabled or incomplete. This maps to [CWE-295](https://cwe.mitre.org/data/definitions/295.html) (Improper Certificate Validation) and [CWE-326](https://cwe.mitre.org/data/definitions/326.html) (Inadequate Encryption Strength).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Server termination** | Nginx, Apache, HAProxy, cloud load balancers, Kubernetes Ingress, embedded Tomcat/Jetty/uvicorn listeners |
| **Client libraries** | `requests`, `httpx`, `HttpClient`, `RestTemplate`, `fetch`, gRPC channels, database and message-broker drivers |
| **Protocol policy** | Explicit `ssl.PROTOCOL_*`, `MinProtocol`/`MaxProtocol`, cipher list overrides, “compatibility mode” flags |
| **Trust stores** | Custom CA bundles, corporate root injection, `verify=False`, trust-all callbacks, empty trust managers |
| **Hostname checks** | Disabled `check_hostname`, custom `SSLContext` without server name indication (SNI), IP literals without SAN coverage |
| **Certificate lifecycle** | Expired or self-signed certs in prod, missing intermediate chain, wildcard certs on unrelated services |

## Abuse Scenarios

Use these when reviewing outbound HTTPS clients, API integrations, and TLS termination configuration.

### Scenario 1: MITM on outbound API calls (`verify=False`)

A microservice calls partner APIs with certificate verification disabled to work around a corporate proxy or self-signed test cert. The misconfiguration ships to production. A network attacker presents any certificate and reads OAuth tokens, API keys, and PII from TLS plaintext.

### Scenario 2: Global TLS disable in Node.js

`NODE_TLS_REJECT_UNAUTHORIZED=0` is set in a Docker image or systemd unit for "development" and never removed. Every `https` request from that process accepts forged certificates.

### Scenario 3: Trust-all Java TrustManager

Custom `X509TrustManager` with empty `checkServerTrusted` ships in a shared HTTP utility class. All Java services using the helper are vulnerable to MITM regardless of URL scheme.

### Scenario 4: Hostname verification disabled

Client validates the certificate chain but sets `check_hostname = False` or `InsecureSkipVerify: true`. Attacker presents a valid certificate for `attacker.example` while the app intended `api.partner.example`.

### Scenario 5: Protocol downgrade

Server or client still accepts TLS 1.0/1.1 or weak cipher suites. Attacker forces downgrade to exploit known protocol weaknesses or weak crypto.

### Scenario 6: Incomplete server chain

Server presents only the leaf certificate without intermediates. Some clients fail; others may prompt or fall back to insecure trust-on-first-use patterns in internal tools.

## Language-Specific Libraries and Dangerous Patterns

### Python

```python
# Dangerous
requests.get(url, verify=False)
httpx.Client(verify=False)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

# Safer: default verification; corporate CA via verify= path
import requests
resp = requests.get("https://api.partner.example/v1/data", timeout=10)
resp = requests.get(url, verify="/etc/ssl/certs/corp-ca.pem", timeout=10)
```

Also review: `aiohttp` `TCPConnector(ssl=False)`, `urllib.request.urlopen` with custom context, `boto3`/`botocore` `verify=False`.

See [Python requests SSL verification](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification) and [httpx SSL](https://www.python-httpx.org/advanced/ssl/).

### Java

```java
// Dangerous
conn.setSSLSocketFactory(trustAllFactory);
conn.setHostnameVerifier((h, s) -> true);
HttpClients.custom().setSSLContext(trustAll).build();

// Safer: default SSLContext and HttpClient
HttpClient client = HttpClient.newBuilder().build();
// Apache HttpClient 5: use system trust store, default hostname verifier
```

Also review: `RestTemplate` with custom `HttpComponentsClientHttpRequestFactory`, gRPC `usePlaintext()`, JDBC `sslmode=disable`.

See [Java JSSE Reference Guide](https://docs.oracle.com/en/java/javase/21/security/java-secure-socket-extension-jsse-reference-guide.html).

### C#

```csharp
// Dangerous
handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;

// Safer: default HttpClient
var client = new HttpClient();
await client.GetStringAsync("https://api.example.com/v1/export");
```

Also review: `ServicePointManager.ServerCertificateValidationCallback`, legacy `ServicePointManager.SecurityProtocol` enabling SSL3/TLS1.

See [HttpClient certificate validation](https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/http/httpclient#secure-the-connection).

### JavaScript

```javascript
// Dangerous
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
https.get(url, { rejectUnauthorized: false });
axios.get(url, { httpsAgent: new https.Agent({ rejectUnauthorized: false }) });

// Safer: default agent; pin corporate CA via ca: fs.readFileSync('corp.pem')
```

See [Node.js TLS documentation](https://nodejs.org/api/tls.html).

### Go

```go
// Dangerous
tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionSSL30}

// Safer: system pool + MinVersion TLS 1.2
pool, _ := x509.SystemCertPool()
tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
```

Also review: `grpc.WithTransportCredentials(insecure.NewCredentials())`, database drivers with `sslmode=disable`.

See [Go crypto/tls](https://pkg.go.dev/crypto/tls).

## Sample Vulnerable Code in Python

```python
import aiohttp
import ssl

async def fetch_partner_data(host: str) -> bytes:
    # Weak protocol range and trust-all context — no meaningful peer authentication
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1  # obsolete minimum
    url = f"https://{host}/v1/export"
    connector = aiohttp.TCPConnector(ssl=ctx)
    async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=10)) as session:
        async with session.get(url) as resp:
            return await resp.read()
```

## Step-by-Step Review Walkthrough

1. **Inventory TLS endpoints.** List every server listener and outbound HTTPS client in the change. Include sidecars, webhooks, health checks, and batch jobs—not only user-facing APIs.
2. **Confirm minimum protocol version.** Require TLS 1.2 or TLS 1.3 per [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) and [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final). Reject SSLv2, SSLv3, TLS 1.0, and TLS 1.1 ([RFC 8996](https://www.rfc-editor.org/rfc/rfc8996)).
3. **Review cipher suites.** On TLS 1.3, prefer AEAD suites from the standard set. On TLS 1.2, prefer ECDHE with AES-GCM or ChaCha20-Poly1305; avoid NULL, EXPORT, RC4, and 3DES. Align with [Mozilla Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS) or your platform baseline.
4. **Trace certificate validation.** Follow trust store loading: system store, custom CA file, or mTLS bundle. Flag `verify=False`, `CERT_NONE`, and callbacks that return true for all certificates.
5. **Verify hostname matching.** Confirm the client checks the peer name against Subject Alternative Name (SAN) or legacy Common Name per [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125). Disabled `check_hostname` is a finding even when `verify_mode` is `CERT_REQUIRED`.
6. **Inspect server certificate chains.** Server configs must present leaf plus intermediates. Clients must build a chain to a trusted anchor—not only trust the leaf if it is self-signed in non-dev environments.
7. **Check environment parity.** Staging must not relax TLS for convenience while production is strict, unless the relaxation is isolated and documented. Test harnesses must not ship trust-all clients in release builds.

## Risk Impact Analysis

**Man-in-the-middle interception.** Skipping verification or hostname checks lets attackers present arbitrary certificates and read or modify HTTPS traffic, including OAuth tokens and API secrets.

**Downgrade and weak-crypto exposure.** Permitting old protocols or weak ciphers enables decryption or session manipulation against clients and servers that negotiate insecure parameters.

**Service impersonation.** Missing hostname validation allows connections to a valid certificate for a different domain, breaking the intended trust boundary between services.

**Compliance and audit findings.** Regulated environments expect documented TLS baselines aligned with [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final) and industry transport guidance such as [OWASP Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html).

**Silent failure in automation.** Batch jobs and internal microservice clients often disable verification “temporarily,” then remain in production for years.

## Vulnerable Examples in Other Languages

### Java

```java
// Trust-all TrustManager and permissive hostname verifier
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, new TrustManager[] {
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) {}
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
}, new SecureRandom());
HttpsURLConnection conn = (HttpsURLConnection) new URL("https://api.example.com").openConnection();
conn.setSSLSocketFactory(ctx.getSocketFactory());
conn.setHostnameVerifier((h, s) -> true);
```

### C#

```csharp
var handler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
};
var client = new HttpClient(handler);
return await client.GetStringAsync("https://payments.internal/api");
```

### JavaScript

```javascript
// Node.js: global TLS verification disabled for "dev"
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const https = require("https");
https.get("https://partner.example/api", { rejectUnauthorized: false }, (res) => {
  // MITM possible even over https URL
});
```

### Go

```go
tr := &http.Transport{
    TLSClientConfig: &tls.Config{
        InsecureSkipVerify: true, // skips chain and hostname validation
        MinVersion:         tls.VersionSSL30, // obsolete
    },
}
client := &http.Client{Transport: tr}
resp, _ := client.Get("https://api.example.com/v1/data")
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use default verification in HTTP libraries. Restrict protocols and ciphers only through explicit, documented baselines.

```python
import aiohttp
import ssl

async def fetch_export(base_url: str, ca_file: str | None = None) -> bytes:
    ssl_ctx = ssl.create_default_context(cafile=ca_file) if ca_file else True
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=ssl_ctx),
        timeout=aiohttp.ClientTimeout(total=10),
    ) as session:
        async with session.get(f"{base_url.rstrip('/')}/v1/export") as resp:
            resp.raise_for_status()
            return await resp.read()
```

**Important:** Custom `SSLContext` changes need a comment linking to your TLS baseline. Never set `check_hostname = False` or `verify_mode = CERT_NONE` in production paths. For corporate CAs, load a dedicated bundle with `verify=` or `ctx.load_verify_locations()`—do not disable verification.

See [Python ssl module](https://docs.python.org/3/library/ssl.html) and [httpx SSL documentation](https://www.python-httpx.org/advanced/ssl/).

### Java

Use the platform default `SSLContext` and hostname verification. Pin corporate roots via trust store configuration, not accept-all managers.

```java
import javax.net.ssl.SSLContext;
import java.net.http.HttpClient;

SSLContext ctx = SSLContext.getDefault();
HttpClient client = HttpClient.newBuilder()
    .sslContext(ctx)
    .build();
// Default hostname verification remains enabled
```

For Apache HttpClient 5, use `TlsSocketStrategy` with default trust material and avoid custom `NoopHostnameVerifier`.

**Important:** `TrustAllStrategy` and `NoopHostnameVerifier` belong only in isolated test fixtures excluded from production artifacts.

See [Java Secure Socket Extension (JSSE) Reference Guide](https://docs.oracle.com/en/java/javase/21/security/java-secure-socket-extension-jsse-reference-guide.html).

### C#

Use `HttpClient` with default certificate validation. Configure corporate roots via `X509ChainTrustMode` or machine trust stores.

```csharp
var handler = new HttpClientHandler();
// Default: validates chain and name against https:// URI host
var client = new HttpClient(handler);
var json = await client.GetStringAsync("https://api.example.com/v1/export");
```

**Important:** `ServerCertificateCustomValidationCallback` that always returns `true` is equivalent to `verify=False`. Restrict callbacks to narrowly scoped test or private-PKI scenarios with explicit documentation.

See [HttpClientHandler.ServerCertificateCustomValidationCallback](https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.servercertificatecustomvalidationcallback) and [Transport Layer Security (TLS) best practices with .NET](https://learn.microsoft.com/en-us/dotnet/core/extensions/ssl-troubleshooting).

### Go

Use the default `http.Client` transport. Set `MinVersion` to TLS 1.2 or higher and load custom roots instead of skipping verification.

```go
import (
    "crypto/tls"
    "crypto/x509"
    "net/http"
    "os"
)

pool, _ := x509.SystemCertPool()
if extra, err := os.ReadFile("/etc/ssl/certs/corp-root.pem"); err == nil {
    pool.AppendCertsFromPEM(extra)
}
tr := &http.Transport{
    TLSClientConfig: &tls.Config{
        RootCAs:    pool,
        MinVersion: tls.VersionTLS12,
    },
}
client := &http.Client{Transport: tr}
```

**Important:** `InsecureSkipVerify` disables both chain and hostname checks. Prefer `RootCAs` and, when connecting by IP or custom name, set `ServerName` explicitly.

See [Go crypto/tls package](https://pkg.go.dev/crypto/tls) and [Go net/http Transport TLSClientConfig](https://pkg.go.dev/net/http#Transport).

## Verify During Review

- Minimum TLS version is **1.2 or 1.3**; SSLv2, SSLv3, TLS 1.0, and TLS 1.1 are disabled.
- Cipher policy follows an approved baseline; no NULL, EXPORT, RC4, or 3DES in production.
- Clients use **default or explicit** chain validation to a trusted anchor; no trust-all callbacks in release code.
- **Hostname verification** is enabled and matches the intended host or configured `ServerName`.
- Server configs present a **complete certificate chain** with valid expiry and appropriate SANs.
- Corporate or private CAs are loaded via **trust stores**, not by turning off verification.
- Test-only TLS relaxations are excluded from production builds and deployment manifests.

## Reference

- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2](https://www.rfc-editor.org/rfc/rfc5246)
- [RFC 8996: Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996)
- [RFC 6125: Representation and Verification of Domain-Based Application Service Identity](https://www.rfc-editor.org/rfc/rfc6125)
- [NIST SP 800-52 Rev. 2: Guidelines for TLS Implementations](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [OWASP Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Mozilla Wiki — Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [Python ssl module](https://docs.python.org/3/library/ssl.html)
- [Python httpx — SSL](https://www.python-httpx.org/advanced/ssl/)
- [Java JSSE Reference Guide](https://docs.oracle.com/en/java/javase/21/security/java-secure-socket-extension-jsse-reference-guide.html)
- [Microsoft — TLS best practices with .NET](https://learn.microsoft.com/en-us/dotnet/core/extensions/ssl-troubleshooting)
- [Go crypto/tls](https://pkg.go.dev/crypto/tls)
- [Node.js TLS/SSL documentation](https://nodejs.org/api/tls.html)
