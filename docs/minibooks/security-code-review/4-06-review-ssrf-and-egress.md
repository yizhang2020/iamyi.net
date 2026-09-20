---
title: Review SSRF and Egress
keywords:
  - SSRF
  - egress
  - exfiltration
  - URL fetch
description: Review server-side request forgery and internal/egress exfiltration as outbound trust.
---

## 4.6 - Review SSRF and Egress

### Overview

When user input influences where the server connects or what it sends outward, the server becomes a proxy into internal networks or partner systems. Review URL allowlists, scheme/host constraints, and whether responses or outbound channels can leak secrets.

The points below are the ideas this family chapter uses again and again.

1. SSRF and egress bugs let the server fetch or send on the attacker's behalf.
2. Validate destination after DNS resolution; disable or re-check redirects.
3. Internal and egress exfiltration share the same outbound trust problem.
4. Allowlists beat denylists for host and scheme policy.
5. Evidence names source, outbound sink, missing control, impact, and a proving test.

After reading this chapter, we should be able to review outbound request builders for private-range access and uncontrolled egress.

## Shared Review Model

Across every variant below, keep the same evidence habit: name the **source**, the **sink**, the **missing control**, the **impact**, and a **test** that would prove a fix.

## Variants in This Family

### SSRF {: #ssrf }

SSRF makes the server send requests on behalf of an attacker. The attacker may reach loopback addresses, cloud instance metadata (`169.254.169.254`), internal admin panels, or file URLs that expose local content. Impact can include credential theft, lateral movement, and bypass of network perimeter controls.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | URL preview, webhook registration, PDF/HTML import, image proxy, RSS fetcher, OAuth callback URL fetch |
| **Attacker control** | Full URL, host, port, path, query, or redirect target from request body or query string |
| **HTTP clients** | `requests.get`, `HttpClient`, `HttpURLConnection`, `http.Get`, FTP/gRPC gateways |
| **Weak validation** | Regex denylists for `localhost` that miss encoded IPs, IPv6, or RFC1918 ranges |
| **Redirect handling** | `follow_redirects=True` without re-validation after each hop |
| **Async replay** | Webhooks stored in the database and fetched later by background workers |

**Appendix detail:** [SSRF code reference](appendix/code-level-reference/4-06-review-ssrf-and-egress.md#ssrf).

### Internal and egress exfiltration {: #egress }

Internal and egress exfiltration covers cases where the application acts as an HTTP client on behalf of users or jobs. An attacker supplies a URL or hostname; the server fetches it from a privileged network position. That may expose admin panels on localhost, cloud instance metadata, or files on internal file servers.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Image proxies, avatar importers, OG preview fetchers, webhook validators, PDF-from-URL, health checks on user URLs |
| **Input entry** | Query params, JSON body URL fields, path segments appended to internal base URLs |
| **HTTP client sinks** | `requests.get`, `HttpURLConnection`, `HttpClient`, `fetch`, `http.Get` with user-influenced targets |
| **Weak controls** | `"http://127.0.0.1" + path`, substring denylists for `localhost`, automatic redirect following |
| **High-value targets** | Cloud metadata (`169.254.169.254`), internal admin panels, file servers on RFC1918 ranges |
| **Blast radius** | Workers, serverless functions, and containers with broad VPC egress |

**Appendix detail:** [Internal and egress exfiltration code reference](appendix/code-level-reference/4-06-review-ssrf-and-egress.md#egress).

## Worked Example (SSRF)

We walk **SSRF** in depth. Apply the same tracing steps to the other variants, adjusting sources and sinks from the tables above.

### Sample vulnerable code (Python)

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

### Step-by-step review walkthrough

1. **Find outbound request builders.** Search for `HttpURLConnection`, `requests.get`, `HttpClient`, `fetch`, FTP, and gRPC gateways driven by user input.
2. **Identify which URL parts are attacker-controlled.** Full URL, host, port, path, query, or redirect target each need separate review.
3. **Check redirect handling.** Libraries that follow 302 responses to `file://` or internal IPs expand the attack surface.
4. **Review allowlists and denylists.** Prefer fixed endpoint maps over partial hostname blocks.
5. **Inspect URL parsing.** Encoded IPs (`127.0.0.1`, `2130706433`, `0x7f000001`), IPv6, and DNS rebinding risks bypass naive checks.
6. **Follow secondary flows.** Webhooks stored at registration time and replayed by workers must apply the same validation.
7. **Confirm egress controls.** Network policies, proxy requirements, and metadata service hardening complement code checks.

## Risk Impact (Family)

**Cloud credential theft.** Access to link-local metadata endpoints may expose IAM tokens and instance credentials.

**Internal service access.** Attackers reach admin panels, Redis, databases, or message brokers bound to localhost or private subnets.

**Data exfiltration.** Server responses from internal APIs may be reflected to the attacker through preview or proxy features.

**Lateral movement.** SSRF often bridges the public web tier into networks assumed unreachable from the internet.

**Compliance impact.** Unauthorized access to internal systems through application bugs may trigger incident response and regulatory review.

## Fix Principles

Primary safer patterns for the worked example follow. For other languages and variant-specific fixes, use the [family appendix](appendix/code-level-reference/4-06-review-ssrf-and-egress.md).

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

## Verify During Review

Use the checklist below as a family-level pass over the variants above. Each item should map to evidence in the change under review.

- User-supplied URLs cannot target loopback, link-local, or RFC1918 addresses without explicit approval.
- Allowlists define permitted hosts, paths, and schemes; denylists are not the only control.
- HTTP clients disable or strictly validate redirects and non-HTTP schemes.
- Webhooks and async jobs apply the same validation as synchronous preview features.
- Cloud and container metadata endpoints are unreachable from application fetch code.
- Defense in depth includes network segmentation, not only application-layer parsing.
- User input cannot choose arbitrary protocol, host, port, or path for server-side HTTP without an allowlist.
- Redirects, DNS rebinding, and alternate IP encodings are considered in the threat model.
- Features that must fetch remote content use a dedicated, hardened client with size and time limits.
- Cloud metadata and loopback addresses are unreachable from request-building code paths.
- Denylists of string substrings are not the primary control.
- Logging captures blocked SSRF attempts without storing full attacker payloads unsafely.

## Code Reference (Appendix)

Payloads, language-specific sinks, multi-language examples, and full fix catalogs for every variant live in **[4.6 code reference — Review SSRF and Egress](appendix/code-level-reference/4-06-review-ssrf-and-egress.md)**.

## Reference

- Appendix — [4.6 code reference](appendix/code-level-reference/4-06-review-ssrf-and-egress.md)

- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [AWS — Instance Metadata Service (IMDSv2)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [Python requests — redirects](https://requests.readthedocs.io/en/latest/user/quickstart/#redirection-and-history)
- [Java HttpClient — Redirect policy](https://docs.oracle.com/en/java/javase/21/docs/api/java.net.http/java/net/http/HttpClient.Redirect.html)
- [ASP.NET Core — HttpClient usage](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/http-requests)
- [Go net/http — Transport](https://pkg.go.dev/net/http#Transport)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP — Server Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Python ipaddress module](https://docs.python.org/3/library/ipaddress.html)
- [Python requests — Redirect control](https://requests.readthedocs.io/en/latest/user/quickstart/#redirection-and-history)
- [Java HttpClient — Redirect policy](https://docs.oracle.com/en/java/javase/21/docs/api/java.net.http/java/net/http/HttpClient.Builder.html#followRedirects(java.net.http.HttpClient.Redirect))
- [ASP.NET Core — IHttpClientFactory](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/http-requests)
- [Go net/http — Client](https://pkg.go.dev/net/http#Client)
