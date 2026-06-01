---
title: Review Path Traversal
keywords:
  - security code review
  - path traversal
  - directory traversal
  - file access
  - lfi
description: How to read code for path traversal—trace attacker-controlled filenames to filesystem APIs and verify resolved paths stay within an allowlisted root.
---

## 4.10 - Review Path Traversal

Path traversal appears when user input influences file paths without canonicalization and base-directory checks. Start from download endpoints, avatar servers, log viewers, import/export features, and archive extractors. Trace each filename from request to filesystem API.

## What This Vulnerability Is

Path traversal (directory traversal) is a filesystem access flaw. Functions that open, read, write, or delete files concatenate attacker-controlled names with a base directory. Sequences like `../` or absolute paths escape the intended folder and reach sensitive files elsewhere on the server.

The unsafe assumption is that users only request files they own. This maps to [CWE-22](https://cwe.mitre.org/data/definitions/22.html) (Improper Limitation of a Pathname to a Restricted Directory).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | File download, avatar serve, log tail, attachment read, ZIP/tar extract, backup restore |
| **Input entry** | Filename parameters, path segments, attachment IDs mapped to paths, archive entry names |
| **Path construction** | `base + filename`, f-strings, `Path.join`, `send_file`, `http.ServeFile` |
| **Weak controls** | Denylist of `..` only, no canonical prefix check, URL-encoded traversal variants |
| **Write/delete paths** | Upload overwrite, extract-all without per-entry validation (zip slip) |
| **Indirect paths** | Database-stored filenames, object storage keys, cache keys resolved to filesystem paths |

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

## Sample Vulnerable Code in Python

```python
from flask import Flask, request, send_file

app = Flask(__name__)

@app.route("/avatar")
def serve_avatar():
    # Attacker-controlled avatar filename — may contain ../ sequences
    avatar = request.args.get("name")
    user_id = request.args.get("uid")
    # Sink: path built without canonicalization or root check
    return send_file(f"/var/www/avatars/{user_id}/{avatar}")
```

## Step-by-Step Review Walkthrough

1. **Find file I/O endpoints.** Search for download, upload, delete, and archive extract handlers that accept names or paths.
2. **Trace the Python (or equivalent) input path.** In the sample, `avatar` is concatenated into a user-specific path. Ask whether `../../etc/passwd` resolves outside `/var/www/avatars/{user_id}`.
3. **Inspect normalization.** Check for `resolve()`, `getCanonicalPath()`, `filepath.Clean()`, and whether results are compared to a trusted root prefix.
4. **Review weak filters.** Blocking only `..` substring may miss `....//`, URL encoding, Unicode separators, or absolute paths.
5. **Follow indirect paths.** Database-stored filenames and attachment IDs mapped to paths need the same root check.
6. **Inspect write and extract operations.** Traversal on upload or `extractall` can overwrite binaries or drop web shells.
7. **Check symlink behavior.** Resolved paths that follow symlinks may escape the intended directory.

## Risk Impact Analysis

**Sensitive file read.** Attackers retrieve application secrets, source code, credentials, and system files such as `/etc/passwd`.

**Arbitrary file write.** Traversal combined with upload or extract may overwrite configuration or plant executable content in web-served directories.

**Service disruption.** Deleting or corrupting files outside the intended directory can break the application or host.

**Compliance exposure.** Unauthorized access to customer data files may trigger breach notification and audit findings.

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

## Verify During Review

- Resolved filesystem paths are verified to stay within the intended base directory before I/O.
- User input never supplies absolute paths; directory separators and `..` sequences are rejected or stripped safely.
- Archive extraction validates every member path against the destination root (zip slip prevention).
- Download endpoints use framework helpers (`send_from_directory`, rooted file providers) where available.
- Stored filenames on disk are opaque identifiers, not raw client-provided names with path components.
- Suspicious traversal attempts are logged and covered by automated security tests.

## Reference

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Python pathlib.Path.resolve](https://docs.python.org/3/library/pathlib.html#pathlib.Path.resolve)
- [Flask send_from_directory](https://flask.palletsprojects.com/en/stable/api/#flask.send_from_directory)
- [Werkzeug safe_join](https://werkzeug.palletsprojects.com/en/stable/utils/#werkzeug.security.safe_join)
- [Java Path.normalize](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/nio/file/Path.html#normalize())
- [Apache Commons IO FilenameUtils](https://commons.apache.org/proper/commons-io/apidocs/org/apache/commons/io/FilenameUtils.html)
- [ASP.NET Core PhysicalFileResult](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.physicalfileresult)
- [Go filepath.Clean](https://pkg.go.dev/path/filepath#Clean)
- [Go http.Dir](https://pkg.go.dev/net/http#Dir)
