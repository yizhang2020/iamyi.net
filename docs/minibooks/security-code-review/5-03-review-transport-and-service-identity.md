---
title: Review Transport and Service Identity
keywords:
  - tls
  - mtls
  - certificates
  - service identity
description: Review TLS/SSL protocol settings and mTLS service identity as one transport family.
---

## 5.3 - Review Transport and Service Identity

### Overview

Transport and service-identity failures let an attacker sit on the wire or impersonate a peer. Review protocol versions, cipher and certificate validation, hostname checks, and—when mutual TLS is claimed—whether both sides present and verify the expected identity.

The points below are the ideas this family chapter uses again and again.

1. Transport failures let an attacker sit on the wire or impersonate a peer.
2. Review protocol versions, ciphers, certificate validation, and hostname checks.
3. When mutual TLS is claimed, both sides must present and verify expected identity.
4. TLS protocol settings and mTLS service identity share that handshake trust problem.
5. Evidence names the handshake decision, missing control, impact, and a proving test.

After reading this chapter, we should be able to review TLS and mTLS configurations for protocol strength and peer identity verification.

## Shared Review Model

Across every variant below, keep the same evidence habit: name the **protocol step or credential**, the **trust decision**, the **missing control**, the **impact**, and a **test** that would prove a fix.

## Variants in This Family

### TLS and SSL protocol {: #tls }

TLS misconfiguration weakens confidentiality and authenticity even when URLs use `https://`. Common failures include enabling obsolete protocols, accepting weak ciphers, skipping certificate chain validation, or not checking that the certificate matches the intended host name.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Server termination** | Nginx, Apache, HAProxy, cloud load balancers, Kubernetes Ingress, embedded Tomcat/Jetty/uvicorn listeners |
| **Client libraries** | `requests`, `httpx`, `HttpClient`, `RestTemplate`, `fetch`, gRPC channels, database and message-broker drivers |
| **Protocol policy** | Explicit `ssl.PROTOCOL_*`, `MinProtocol`/`MaxProtocol`, cipher list overrides, “compatibility mode” flags |
| **Trust stores** | Custom CA bundles, corporate root injection, `verify=False`, trust-all callbacks, empty trust managers |
| **Hostname checks** | Disabled `check_hostname`, custom `SSLContext` without server name indication (SNI), IP literals without SAN coverage |
| **Certificate lifecycle** | Expired or self-signed certs in prod, missing intermediate chain, wildcard certs on unrelated services |

**Appendix detail:** [TLS and SSL protocol reference](appendix/secure-implementations-reference/5-03-review-transport-and-service-identity.md#tls).

### mTLS and service identity {: #mtls }

mTLS fails when servers request but do not validate client certificates, when any certificate signed by a broad internal CA is accepted without binding to an expected service identity, or when mesh sidecars terminate mTLS but application code trusts unauthenticated localhost traffic.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Service-to-service APIs** | Internal gRPC/HTTPS gateways, admin APIs, payment or identity backends reachable from the cluster network |
| **Server TLS config** | `SSLVerifyClient`, `clientAuth`, `NeedClientCert`, Envoy `require_client_certificate`, Istio `PeerAuthentication` |
| **Client cert loading** | PKCS#12 files in images, mounted secrets, cert-manager `Certificate` resources, SPIRE agent sockets |
| **Identity mapping** | CN/SAN parsing, SPIFFE ID (`spiffe://`) extraction, custom headers set by proxies without verification |
| **Mesh bypass paths** | Plain HTTP ports, `NetworkPolicy` gaps, debug ports, legacy jobs hitting services directly by pod IP |
| **Rotation and revocation** | Long-lived client certs, shared cert across environments, no reissue on compromise, missing CRL/OCSP where required |

**Appendix detail:** [mTLS and service identity reference](appendix/secure-implementations-reference/5-03-review-transport-and-service-identity.md#mtls).

## Worked Example (TLS and SSL protocol)

We walk **TLS and SSL protocol** in depth. Apply the same tracing steps to the other variants, adjusting protocol steps and sinks from the tables above.

### Sample vulnerable code (Python)

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

### Step-by-step review walkthrough

1. **Inventory TLS endpoints.** List every server listener and outbound HTTPS client in the change. Include sidecars, webhooks, health checks, and batch jobs—not only user-facing APIs.
2. **Confirm minimum protocol version.** Require TLS 1.2 or TLS 1.3 per [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) and [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final). Reject SSLv2, SSLv3, TLS 1.0, and TLS 1.1 ([RFC 8996](https://www.rfc-editor.org/rfc/rfc8996)).
3. **Review cipher suites.** On TLS 1.3, prefer AEAD suites from the standard set. On TLS 1.2, prefer ECDHE with AES-GCM or ChaCha20-Poly1305; avoid NULL, EXPORT, RC4, and 3DES. Align with [Mozilla Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS) or your platform baseline.
4. **Trace certificate validation.** Follow trust store loading: system store, custom CA file, or mTLS bundle. Flag `verify=False`, `CERT_NONE`, and callbacks that return true for all certificates.
5. **Verify hostname matching.** Confirm the client checks the peer name against Subject Alternative Name (SAN) or legacy Common Name per [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125). Disabled `check_hostname` is a finding even when `verify_mode` is `CERT_REQUIRED`.
6. **Inspect server certificate chains.** Server configs must present leaf plus intermediates. Clients must build a chain to a trusted anchor—not only trust the leaf if it is self-signed in non-dev environments.
7. **Check environment parity.** Staging must not relax TLS for convenience while production is strict, unless the relaxation is isolated and documented. Test harnesses must not ship trust-all clients in release builds.

## Risk Impact (Family)

**Man-in-the-middle interception.** Skipping verification or hostname checks lets attackers present arbitrary certificates and read or modify HTTPS traffic, including OAuth tokens and API secrets.

**Downgrade and weak-crypto exposure.** Permitting old protocols or weak ciphers enables decryption or session manipulation against clients and servers that negotiate insecure parameters.

**Service impersonation.** Missing hostname validation allows connections to a valid certificate for a different domain, breaking the intended trust boundary between services.

**Compliance and audit findings.** Regulated environments expect documented TLS baselines aligned with [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final) and industry transport guidance such as [OWASP Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html).

**Silent failure in automation.** Batch jobs and internal microservice clients often disable verification “temporarily,” then remain in production for years.

## Fix Principles

Primary safer patterns for the worked example follow. For other languages and variant-specific fixes, use the [family appendix](appendix/secure-implementations-reference/5-03-review-transport-and-service-identity.md).

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

Use the checklist below as a family-level pass over the variants above. Each item should map to evidence in the change under review.

- Minimum TLS version is **1.2 or 1.3**; SSLv2, SSLv3, TLS 1.0, and TLS 1.1 are disabled.
- Cipher policy follows an approved baseline; no NULL, EXPORT, RC4, or 3DES in production.
- Clients use **default or explicit** chain validation to a trusted anchor; no trust-all callbacks in release code.
- **Hostname verification** is enabled and matches the intended host or configured `ServerName`.
- Server configs present a **complete certificate chain** with valid expiry and appropriate SANs.
- Corporate or private CAs are loaded via **trust stores**, not by turning off verification.
- Test-only TLS relaxations are excluded from production builds and deployment manifests.
- Internal privileged APIs **require** client certificates; optional client auth is flagged unless explicitly justified.
- Server validates client cert **chain** against the expected CA or SPIFFE trust domain.
- Authorization uses **verified** cert fields (SPIFFE ID, SAN), not unauthenticated headers or CN alone.
- Clients verify **server** cert and hostname per [5.3 § TLS](5-03-review-transport-and-service-identity.md#tls) while presenting their own cert.
- Mesh mode is **STRICT** (or equivalent) for production namespaces; permissive mode has an expiry plan.
- No plaintext **bypass ports** expose the same handlers without equivalent authentication.
- Client certs **rotate** automatically; shared long-lived certs across services are documented exceptions only.

## Implementation Reference (Appendix)

Library sinks, multi-language examples, and full fix catalogs for every variant live in **[5.3 reference — Review Transport and Service Identity](appendix/secure-implementations-reference/5-03-review-transport-and-service-identity.md)**.

## Reference

- Appendix — [5.3 reference](appendix/secure-implementations-reference/5-03-review-transport-and-service-identity.md)

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
- [RFC 8446: TLS 1.3 — Client Authentication](https://www.rfc-editor.org/rfc/rfc8446#section-2.2)
- [RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://www.rfc-editor.org/rfc/rfc8705)
- [SPIFFE Specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md)
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [Istio — PeerAuthentication](https://istio.io/latest/docs/reference/config/security/peer_authentication/)
- [Istio — Mutual TLS Migration](https://istio.io/latest/docs/ops/configuration/traffic-management/tls-configuration/)
- [Envoy — Downstream TLS transport socket](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/tls.proto)
- [gRPC — Authentication guide](https://grpc.io/docs/guides/auth/)
- [Go crypto/tls — ClientAuth](https://pkg.go.dev/crypto/tls#ClientAuthType)
- [ASP.NET Core certificate authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/certauth)
