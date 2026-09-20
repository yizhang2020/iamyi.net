---
title: Review mTLS and Service Identity
keywords:
  - security code review
  - mutual TLS
  - mTLS
  - client certificates
  - service mesh
  - workload identity
description: How to review mutual TLS and service identity—client certificate validation, SPIFFE-style workload IDs, and mesh-sidecar trust boundaries.
---

## 10.6 - Review mTLS and Service Identity

Mutual TLS (mTLS) adds client authentication to TLS: both peers present certificates and validate each other. Review server-side client-cert requirements, client cert loading and rotation, and how service meshes or workload identity systems map certificates to authorized services. Treat identity as a authorization input, not only as transport encryption.

## What This Vulnerability Is

mTLS fails when servers request but do not validate client certificates, when any certificate signed by a broad internal CA is accepted without binding to an expected service identity, or when mesh sidecars terminate mTLS but application code trusts unauthenticated localhost traffic.

The unsafe assumption is that TLS encryption alone proves which service is calling. Attackers with network access may connect without a valid client cert, present a cert for a different workload, or bypass sidecar enforcement if the app listens on plain HTTP behind the mesh. This relates to [CWE-295](https://cwe.mitre.org/data/definitions/295.html) (Improper Certificate Validation) and [CWE-287](https://cwe.mitre.org/data/definitions/287.html) (Improper Authentication).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Service-to-service APIs** | Internal gRPC/HTTPS gateways, admin APIs, payment or identity backends reachable from the cluster network |
| **Server TLS config** | `SSLVerifyClient`, `clientAuth`, `NeedClientCert`, Envoy `require_client_certificate`, Istio `PeerAuthentication` |
| **Client cert loading** | PKCS#12 files in images, mounted secrets, cert-manager `Certificate` resources, SPIRE agent sockets |
| **Identity mapping** | CN/SAN parsing, SPIFFE ID (`spiffe://`) extraction, custom headers set by proxies without verification |
| **Mesh bypass paths** | Plain HTTP ports, `NetworkPolicy` gaps, debug ports, legacy jobs hitting services directly by pod IP |
| **Rotation and revocation** | Long-lived client certs, shared cert across environments, no reissue on compromise, missing CRL/OCSP where required |

## Abuse Scenarios

Use these when reviewing service-to-service authentication and mesh-enforced mTLS.

### Scenario 1: Optional client certificate (`VerifyClientCertIfGiven`)

The server requests client certs but accepts connections without them. An attacker on the pod network connects without a cert and invokes internal admin APIs that operators assumed were mTLS-protected.

### Scenario 2: Client cert present but not validated

Node.js sets `requestCert: true` with `rejectUnauthorized: false`. A client presents an expired, self-signed, or wrong-CA certificate; the server reads CN and grants access anyway.

### Scenario 3: Trust any internal CA

Server trusts a broad enterprise root and accepts any client cert signed by that CA without checking SPIFFE ID or SAN against an allowlist. Compromise of any internal workload cert allows impersonation of any service.

### Scenario 4: Header-based identity without verification

Ingress sets `X-Forwarded-Client-Cert` or custom `X-Service-Identity` headers. Application trusts the header on plaintext localhost while sidecar mTLS is bypassed via direct port access.

### Scenario 5: Mesh permissive mode left in production

Istio `PeerAuthentication` is `PERMISSIVE` indefinitely. Plaintext and mTLS clients both reach the same handlers; attackers choose plaintext from compromised pods.

### Scenario 6: Shared long-lived client cert in images

One PKCS#12 client cert is baked into all microservice images. Leak from any container reveals identity usable against every internal API until manual revocation.

## Language-Specific Libraries and Dangerous Patterns

### Python

```python
# Dangerous: TLS without required client cert
ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
# verify_mode defaults — client cert not required

# Safer
ctx.verify_mode = ssl.CERT_REQUIRED
ctx.load_verify_locations(cafile="mesh-ca.pem")
spiffe_id = peer_spiffe_id(conn.getpeercert())
if spiffe_id not in ALLOWED_CALLERS: conn.close()
```

Also review: `uvicorn`/`gunicorn` SSL settings, `requests` client cert without server verify ([10.5](10-05-review-tls-ssl-protocol.md)).

### Java

```java
// Dangerous: gRPC server TLS without client auth
GrpcSslContexts.forServer(serverCert, serverKey).build();

// Safer
GrpcSslContexts.forServer(serverCert, serverKey)
    .trustManager(clientCaBundle)
    .clientAuth(ClientAuth.REQUIRE)
    .build();
```

Also review: Netty `SslContextBuilder`, Spring Boot `server.ssl.client-auth=need`, Istio Java agent headers.

See [gRPC Java TLS guide](https://grpc.io/docs/guides/auth/#with-server-authentication-ssltls).

### C#

```csharp
// Dangerous: default ClientCertificateMode
listen.UseHttps(https => { https.ServerCertificate = serverCert; });

// Safer
https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
https.ClientCertificateValidation = (cert, chain, errors) =>
    errors == SslPolicyErrors.None && AllowedSpiffeIds.Contains(ExtractSpiffeId(cert));
```

See [ASP.NET Core certificate authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/certauth).

### Go

```go
// Dangerous
tls.Config{ClientAuth: tls.VerifyClientCertIfGiven}

// Safer
tls.Config{
    ClientAuth: tls.RequireAndVerifyClientCert,
    ClientCAs:  clientCAPool,
    MinVersion: tls.VersionTLS12,
}
// Authorize: r.TLS.PeerCertificates[0] SPIFFE SAN
```

Also review: SPIRE [go-spiffe](https://pkg.go.dev/github.com/spiffe/go-spiffe/v2/workloadapi), cert-manager mounted certs, Envoy SDS config.

### JavaScript / infrastructure

```yaml
# Istio — permissive left in prod
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
spec:
  mtls:
    mode: PERMISSIVE
```

See [Python ssl verify_mode](https://docs.python.org/3/library/ssl.html#ssl.SSLContext.verify_mode), [Go tls ClientAuth](https://pkg.go.dev/crypto/tls#ClientAuthType), [SPIFFE](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/), and [Istio PeerAuthentication](https://istio.io/latest/docs/reference/config/security/peer_authentication/).

## Sample Vulnerable Code in Python

```python
import ssl
import socket

def handle_internal_request(conn: ssl.SSLSocket) -> None:
    # Server negotiates TLS but never requires or validates a client certificate
    peer = conn.getpeercert()  # may be empty dict when client cert not sent
    # Unsafe: any TLS client on the network is treated as trusted internal caller
    service_name = peer.get("subject", ((("CN", "unknown"),),))[0][0][1]
    authorize_admin_action(service_name)
```

## Step-by-Step Review Walkthrough

1. **Map trust boundaries.** Identify which services require mTLS and which callers are allowed. Draw paths through ingress, sidecars, and direct cluster DNS names.
2. **Confirm server requires client auth.** On TLS terminators and app listeners, verify `CERT_REQUIRED` (or equivalent) and rejection when no client cert is presented.
3. **Validate client certificate chains.** Trace trust anchors for client certs—mesh CA, SPIRE bundle, or enterprise PKI. Reject self-signed or wrong-CA client certs.
4. **Bind cert identity to authorization.** Parse SPIFFE ID or approved SAN/CN patterns; compare against an allowlist of services for the endpoint. Do not trust unverified `X-Forwarded-Client-Cert` headers from outside the mesh.
5. **Review client implementation.** Outbound callers must load current cert and key, present them during handshake, and verify the server cert and hostname as in [10.5 Review TLS](10-05-review-tls-ssl-protocol.md).
6. **Inspect mesh policy.** For Istio, Linkerd, or Envoy, read `PeerAuthentication`, destination rules, and whether `PERMISSIVE` mode is temporary. Confirm applications do not expose plaintext ports that bypass sidecar capture.
7. **Check rotation and blast radius.** Shared certs across services, multi-year validity, and certs baked into images complicate revocation. Confirm automated rotation and distinct identities per workload where feasible.

## Risk Impact Analysis

**Lateral movement inside the network.** Without enforced client authentication, any compromised pod or insider with network reach can call privileged internal APIs.

**Service impersonation.** Accepting client certs without identity binding lets one service masquerade as another if it obtains any valid internal certificate.

**Mesh false confidence.** Operators may believe mTLS is enabled while permissive mode or plaintext fallback leaves critical paths unauthenticated.

**Broken zero-trust claims.** Auditors expect demonstrable workload identity; optional or misconfigured mTLS undermines “never trust the network” designs.

**Long-lived credential risk.** Client certificates without rotation remain valid after key compromise until manually revoked.

## Vulnerable Examples in Other Languages

### Java

```java
// gRPC server: TLS enabled but client certs not required
Server server = NettyServerBuilder.forPort(8443)
    .sslContext(GrpcSslContexts.forServer(serverCert, serverKey).build())
    // Missing: clientAuth(ClientAuth.REQUIRE)
    .addService(new AdminServiceImpl())
    .build();
```

### C#

```csharp
// Kestrel listens with HTTPS but ClientCertificateMode defaults to NoCertificate
builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Any, 8443, listen =>
    {
        listen.UseHttps(https =>
        {
            https.ServerCertificate = serverCert;
            // Missing: ClientCertificateMode.RequireCertificate + validation callback
        });
    });
});
```

### JavaScript

```javascript
// Node HTTPS server: requestCert without rejectUnauthorized on client cert
const https = require("https");
https.createServer(
  { key, cert, requestCert: true, rejectUnauthorized: false },
  (req, res) => {
    // Client cert may be present but invalid — still accepted
    const cn = req.socket.getPeerCertificate()?.subject?.CN;
    grantAccess(cn);
  }
).listen(8443);
```

### Go

```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientAuth:   tls.VerifyClientCertIfGiven, // optional client cert — not mTLS
    ClientCAs:    clientCAPool,
}
srv := &http.Server{Addr: ":8443", TLSConfig: tlsConfig}
```

## Fix: Safer Patterns and Libraries to Use

### Python (mTLS with SPIRE workload API)

```python
from spiffe.workloadapi import WorkloadApiClient
import ssl

client = WorkloadApiClient()
svid = client.fetch_x509_svid()
ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
ctx.load_cert_chain(certfile=svid.cert_path, keyfile=svid.key_path)
ctx.load_verify_locations(cafile=client.fetch_x509_bundles().path)
ctx.verify_mode = ssl.CERT_REQUIRED
```

**Important:** `CERT_OPTIONAL` and `VerifyClientCertIfGiven` are not mTLS for high-value endpoints. Pair mTLS with server cert verification on clients.

See [Python ssl — SSLContext.verify_mode](https://docs.python.org/3/library/ssl.html#ssl.SSLContext.verify_mode).

### Java

Require client authentication on gRPC or HTTPS and validate the peer chain against the mesh or SPIRE trust bundle.

```java
import io.grpc.netty.GrpcSslContexts;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;

SslContext sslContext = GrpcSslContexts.forServer(serverCert, serverKey)
    .trustManager(clientCaBundle)
    .clientAuth(ClientAuth.REQUIRE)
    .build();

Server server = NettyServerBuilder.forPort(8443)
    .sslContext(sslContext)
    .intercept(new SpiffeAuthorizationServerInterceptor(ALLOWED_SPIFFE_IDS))
    .addService(new InternalApiImpl())
    .build();
```

**Important:** Extract SPIFFE ID or service SAN from verified peer credentials in an interceptor—do not trust client-supplied HTTP headers for identity.

See [gRPC Java — TLS](https://grpc.io/docs/guides/auth/#with-server-authentication-ssltls) and [Java JSSE Reference Guide](https://docs.oracle.com/en/java/javase/21/security/java-secure-socket-extension-jsse-reference-guide.html).

### C#

Configure Kestrel to require and validate client certificates against your CA policy.

```csharp
builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Any, 8443, listen =>
    {
        listen.UseHttps(https =>
        {
            https.ServerCertificate = serverCert;
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            https.ClientCertificateValidation = (cert, chain, errors) =>
            {
                if (errors != SslPolicyErrors.None) return false;
                return AllowedSpiffeIds.Contains(ExtractSpiffeId(cert));
            };
        });
    });
});
```

**Important:** Forwarded client cert headers from ingress must be stripped or validated at the edge; only trusted proxies should set them.

See [Configure certificate authentication in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/certauth).

### Go

Set `ClientAuth: tls.RequireAndVerifyClientCert` and authorize using verified certificate fields.

```go
clientCAPool := x509.NewCertPool()
clientCAPool.AppendCertsFromPEM(clientCAPEM)
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    clientCAPool,
    MinVersion:   tls.VersionTLS12,
}
mux := http.NewServeMux()
mux.HandleFunc("/internal/", func(w http.ResponseWriter, r *http.Request) {
    certs := r.TLS.PeerCertificates
    if len(certs) == 0 || !allowedCaller(certs[0]) {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    handle(w, r)
})
http.Server{Addr: ":8443", TLSConfig: tlsConfig, Handler: mux}.ListenAndServeTLS("", "")
```

**Important:** SPIFFE workload API or cert-manager should supply rotated cert material; avoid embedding long-lived client keys in container layers.

See [Go crypto/tls — ClientAuth](https://pkg.go.dev/crypto/tls#ClientAuthType), [SPIFFE Specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md), and [Istio PeerAuthentication](https://istio.io/latest/docs/reference/config/security/peer_authentication/).

## Verify During Review

- Internal privileged APIs **require** client certificates; optional client auth is flagged unless explicitly justified.
- Server validates client cert **chain** against the expected CA or SPIFFE trust domain.
- Authorization uses **verified** cert fields (SPIFFE ID, SAN), not unauthenticated headers or CN alone.
- Clients verify **server** cert and hostname per [10.5](10-05-review-tls-ssl-protocol.md) while presenting their own cert.
- Mesh mode is **STRICT** (or equivalent) for production namespaces; permissive mode has an expiry plan.
- No plaintext **bypass ports** expose the same handlers without equivalent authentication.
- Client certs **rotate** automatically; shared long-lived certs across services are documented exceptions only.

## Reference

- [RFC 8446: TLS 1.3 — Client Authentication](https://www.rfc-editor.org/rfc/rfc8446#section-2.2)
- [RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://www.rfc-editor.org/rfc/rfc8705)
- [SPIFFE Specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md)
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [Istio — PeerAuthentication](https://istio.io/latest/docs/reference/config/security/peer_authentication/)
- [Istio — Mutual TLS Migration](https://istio.io/latest/docs/ops/configuration/traffic-management/tls-configuration/)
- [Envoy — Downstream TLS transport socket](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/tls.proto)
- [gRPC — Authentication guide](https://grpc.io/docs/guides/auth/)
- [Python ssl module](https://docs.python.org/3/library/ssl.html)
- [Go crypto/tls — ClientAuth](https://pkg.go.dev/crypto/tls#ClientAuthType)
- [ASP.NET Core certificate authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/certauth)
- [Java JSSE Reference Guide](https://docs.oracle.com/en/java/javase/21/security/java-secure-socket-extension-jsse-reference-guide.html)
