---
title: Review SSRF
keywords:
  - security code review
  - ssrf
  - server-side request forgery
  - url validation
  - allowlist
description: How to read code for server-side request forgery—trace attacker-controlled URLs into HTTP clients and verify allowlists block internal targets.
---

## 4.14 - Review SSRF

Server-side request forgery (SSRF) appears when the application fetches or calls a URL, host, or path supplied by a user and reaches networks or services that were never meant to be client-facing. Review webhooks, import-from-URL features, PDF generators, image proxies, and health checks. Trace user input into HTTP clients, socket code, and cloud metadata endpoints.

## What This Vulnerability Is

SSRF makes the server send requests on behalf of an attacker. The attacker may reach loopback addresses, cloud instance metadata (`169.254.169.254`), internal admin panels, or file URLs that expose local content. Impact can include credential theft, lateral movement, and bypass of network perimeter controls.

The unsafe assumption is that restricting the UI is enough and that "internal" hostnames are unreachable from application code. This pattern maps to [CWE-918](https://cwe.mitre.org/data/definitions/918.html) (Server-Side Request Forgery).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | URL preview, webhook registration, PDF/HTML import, image proxy, RSS fetcher, OAuth callback URL fetch |
| **Attacker control** | Full URL, host, port, path, query, or redirect target from request body or query string |
| **HTTP clients** | `requests.get`, `HttpClient`, `HttpURLConnection`, `http.Get`, FTP/gRPC gateways |
| **Weak validation** | Regex denylists for `localhost` that miss encoded IPs, IPv6, or RFC1918 ranges |
| **Redirect handling** | `follow_redirects=True` without re-validation after each hop |
| **Async replay** | Webhooks stored in the database and fetched later by background workers |

## Attack Payloads

Use these in authorized tests when a parameter supplies a URL, host, or path segment to an outbound HTTP client. Replace `TARGET` with the vulnerable field.

### Pattern 1: Cloud metadata (link-local)

```text
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://metadata.google.internal/computeMetadata/v1/
http://100.100.100.200/latest/meta-data/   # Alibaba
```

### Pattern 2: Loopback and internal services

```text
http://127.0.0.1:6379/
http://localhost:8080/admin
http://127.0.0.1:9200/_cat/indices
```

### Pattern 3: Private RFC1918 ranges

```text
http://10.0.0.15/internal/users
http://192.168.1.1/
http://172.16.0.5:8500/v1/agent/self
```

### Pattern 4: Encoded and alternate IP forms (bypass denylists)

```text
http://2130706433/          # decimal 127.0.0.1
http://0x7f000001/
http://127.1/
http://[::1]/
http://0177.0.0.1/
```

### Pattern 5: Non-HTTP schemes and redirects

```text
file:///etc/passwd
gopher://127.0.0.1:6379/_...
# Register https://evil.example → 302 to http://169.254.169.254/
```

## Language-Specific Sinks and Dangerous APIs

Any outbound request built from user input needs allowlisting, DNS rebinding awareness, and post-redirect re-validation.

### Python

```python
import httpx, urllib.request
httpx.Client(follow_redirects=True).get(user_link)
urllib.request.urlopen(preview_target)
requests.post(webhook_url, json={"ping": True})  # when URL is user-supplied
```

Also: `aiohttp` session fetches, `selenium`/`playwright` navigation to user URLs, PDF renderers fetching remote HTML.

### Java

```java
new URL(userUrl).openConnection();
HttpClient.newHttpClient().send(HttpRequest.newBuilder().uri(URI.create(url)).build(), ...);
RestTemplate.getForObject(endpoint, String.class);
```

Apache HttpClient, `URLConnection`, image/PDF libraries that fetch remote resources.

### C#

```csharp
await httpClient.GetAsync(userUrl);
new WebClient().DownloadString(url);
```

`HttpWebRequest`, WCF clients, headless browser automation with user-supplied start URL.

### JavaScript (Node.js)

```javascript
const axios = require('axios');
await axios.get(req.query.url);
await fetch(userUrl);
```

`node-fetch`, `got`, `request`, server-side `puppeteer.goto(url)`.

### Go

```go
http.Get(r.URL.Query().Get("link"))
client.Do(req) // req built from ?link= query param
```

`net/http`, custom TCP dialers, gRPC gateways that proxy to user hostnames.

### Ruby

```ruby
URI.open(params[:url])
Net::HTTP.get(URI(user_url))
```

## Sample Vulnerable Code in Python

```python
import httpx
from flask import Flask, request, Response

app = Flask(__name__)

@app.route("/images/thumbnail")
def thumbnail():
    # Attacker supplies src=http://169.254.169.254/... or http://127.0.0.1:6379/
    image_url = request.args.get("src")
    with httpx.Client(follow_redirects=True, timeout=5.0) as client:
        resp = client.get(image_url)
    return Response(resp.content, mimetype=resp.headers.get("content-type", "image/jpeg"))
```

## Step-by-Step Review Walkthrough

1. **Find outbound request builders.** Search for `HttpURLConnection`, `requests.get`, `HttpClient`, `fetch`, FTP, and gRPC gateways driven by user input.
2. **Identify which URL parts are attacker-controlled.** Full URL, host, port, path, query, or redirect target each need separate review.
3. **Check redirect handling.** Libraries that follow 302 responses to `file://` or internal IPs expand the attack surface.
4. **Review allowlists and denylists.** Prefer fixed endpoint maps over partial hostname blocks.
5. **Inspect URL parsing.** Encoded IPs (`127.0.0.1`, `2130706433`, `0x7f000001`), IPv6, and DNS rebinding risks bypass naive checks.
6. **Follow secondary flows.** Webhooks stored at registration time and replayed by workers must apply the same validation.
7. **Confirm egress controls.** Network policies, proxy requirements, and metadata service hardening complement code checks.

## Risk Impact Analysis

**Cloud credential theft.** Access to link-local metadata endpoints may expose IAM tokens and instance credentials.

**Internal service access.** Attackers reach admin panels, Redis, databases, or message brokers bound to localhost or private subnets.

**Data exfiltration.** Server responses from internal APIs may be reflected to the attacker through preview or proxy features.

**Lateral movement.** SSRF often bridges the public web tier into networks assumed unreachable from the internet.

**Compliance impact.** Unauthorized access to internal systems through application bugs may trigger incident response and regulatory review.

## Vulnerable Examples in Other Languages

### Java

```java
@GetMapping("/images/thumbnail")
public ResponseEntity<byte[]> thumbnail(@RequestParam String src) throws Exception {
    URL url = new URL(src);
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    conn.setRequestMethod("GET");
    byte[] body;
    try (InputStream in = conn.getInputStream()) {
        body = in.readAllBytes();
    }
    return ResponseEntity.ok()
        .contentType(MediaType.parseMediaType(conn.getContentType()))
        .body(body);
}
```

### C#

```csharp
[HttpGet("images/thumbnail")]
public async Task<IActionResult> Thumbnail([FromQuery] string src)
{
    using var client = new HttpClient();
    var bytes = await client.GetByteArrayAsync(src);
    return File(bytes, "image/jpeg");
}
```

### Go

```go
func fetchThumbnail(w http.ResponseWriter, r *http.Request) {
    src := r.URL.Query().Get("src")
    resp, err := http.Get(src)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    defer resp.Body.Close()
    w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
    io.Copy(w, resp.Body)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Allowlist hosts and block private ranges after DNS resolution. Disable redirects or validate each hop.

```python
import ipaddress
import socket
from urllib.parse import urlparse
import requests

ALLOWED_IMAGE_HOSTS = {"images.example.com", "cdn.partner.com"}

def is_public_ip(hostname: str) -> bool:
    addr = socket.gethostbyname(hostname)
    ip = ipaddress.ip_address(addr)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)

def safe_fetch_image(url: str) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("scheme not allowed")
    if parsed.hostname not in ALLOWED_IMAGE_HOSTS:
        raise ValueError("host not allowlisted")
    if not is_public_ip(parsed.hostname):
        raise ValueError("destination not public")
    resp = requests.get(url, timeout=5, allow_redirects=False)
    resp.raise_for_status()
    return resp.content

@app.route("/images/thumbnail")
def thumbnail():
    return Response(safe_fetch_image(request.args["src"]), mimetype="image/jpeg")
```

**Important:** Wrap fetches in a separate network segment with no internal access when possible. Use IMDSv2 on AWS to reduce metadata abuse.

### Java

Map user choices to predefined base URLs. Resolve DNS and verify the resulting IP is public before connecting.

```java
private static final Map<String, String> ALLOWED = Map.of(
    "logo", "https://cdn.partner.com/assets/logo.png",
    "banner", "https://cdn.partner.com/assets/banner.png");

public byte[] fetchThumbnail(String assetKey) throws Exception {
    String url = ALLOWED.get(assetKey);
    if (url == null) {
        throw new SecurityException("unknown asset");
    }
    URI uri = URI.create(url);
    InetAddress addr = InetAddress.getByName(uri.getHost());
    if (addr.isLoopbackAddress() || addr.isSiteLocalAddress() || addr.isLinkLocalAddress()) {
        throw new SecurityException("blocked destination");
    }
    HttpClient client = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
    HttpRequest req = HttpRequest.newBuilder(uri).GET().build();
    return client.send(req, HttpResponse.BodyHandlers.ofByteArray()).body();
}
```

**Important:** Force outbound traffic through a controlled forward proxy when policy allows. Disable redirects or validate each hop.

### C#

Use a custom `DelegatingHandler` that rejects non-public destinations after DNS resolve.

```csharp
public async Task<byte[]> FetchApprovedAsset(string assetId)
{
    var url = _assetCatalog.GetApprovedUrl(assetId);
    if (url is null) throw new SecurityException("unknown asset");

    var host = new Uri(url).Host;
    var addresses = await Dns.GetHostAddressesAsync(host);
    foreach (var addr in addresses)
    {
        if (IPAddress.IsLoopback(addr) || IsPrivate(addr))
            throw new SecurityException("blocked destination");
    }

    using var client = new HttpClient(new SsrSafeHandler()) { Timeout = TimeSpan.FromSeconds(5) };
    return await client.GetByteArrayAsync(url);
}

private static bool IsPrivate(IPAddress ip) =>
    ip.ToString().StartsWith("10.") || ip.ToString().StartsWith("192.168.");
```

**Important:** Store resource IDs and fetch from trusted internal catalogs instead of raw user URLs in production.

### Go

Custom `Transport.DialContext` refuses private IPs. Allowlist permitted webhook hosts.

```go
var allowedImageHosts = map[string]bool{"images.example.com": true, "cdn.partner.com": true}

func safeFetchThumbnail(raw string) ([]byte, error) {
    u, err := url.Parse(raw)
    if err != nil || u.Scheme != "https" || !allowedImageHosts[u.Hostname()] {
        return nil, fmt.Errorf("url not allowed")
    }
    addrs, err := net.LookupHost(u.Hostname())
    if err != nil {
        return nil, err
    }
    for _, a := range addrs {
        ip := net.ParseIP(a)
        if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
            return nil, fmt.Errorf("blocked destination")
        }
    }
    client := &http.Client{
        Timeout: 5 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }
    resp, err := client.Get(u.String())
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
```

**Important:** Cap response body size to reduce blind data exfiltration. Route outbound HTTP through policy-enforcing sidecars.

## Verify During Review

- User-supplied URLs cannot target loopback, link-local, or RFC1918 addresses without explicit approval.
- Allowlists define permitted hosts, paths, and schemes; denylists are not the only control.
- HTTP clients disable or strictly validate redirects and non-HTTP schemes.
- Webhooks and async jobs apply the same validation as synchronous preview features.
- Cloud and container metadata endpoints are unreachable from application fetch code.
- Defense in depth includes network segmentation, not only application-layer parsing.

## Reference

- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [AWS — Instance Metadata Service (IMDSv2)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [Python requests — redirects](https://requests.readthedocs.io/en/latest/user/quickstart/#redirection-and-history)
- [Java HttpClient — Redirect policy](https://docs.oracle.com/en/java/javase/21/docs/api/java.net.http/java/net/http/HttpClient.Redirect.html)
- [ASP.NET Core — HttpClient usage](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/http-requests)
- [Go net/http — Transport](https://pkg.go.dev/net/http#Transport)
