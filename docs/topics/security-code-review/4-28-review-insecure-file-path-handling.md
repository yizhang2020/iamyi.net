---
title: Review Insecure File Path Handling
keywords:
  - security code review
  - path traversal
  - directory traversal
  - file download
  - canonical path
description: How to read code for path traversal where user input reaches file open, read, or write operations outside intended directories.
---

## 4.28 - Review Insecure File Path Handling

Path traversal lets attackers read or write files outside the intended directory by supplying `../` segments or absolute paths. Review download endpoints, avatar servers, backup restore, and attachment storage. Trace user-controlled filenames from parameter to `open`, `FileInputStream`, or path joins.

## What This Vulnerability Is

Path (directory) traversal occurs when the application uses attacker-controlled strings as file paths without confining access to an allowed base directory. Functions that serve files by name are the most common location. Concatenation and `Paths.get(base, userInput)` without a canonical path check can reach `/etc/passwd` or application configuration.

The unsafe assumption is that users will only request legitimate filenames. URL encoding, Unicode normalization, and `..` sequences bypass naive filters. This maps to [CWE-22](https://cwe.mitre.org/data/definitions/22.html) (Improper Limitation of a Pathname to a Restricted Directory).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | File download, avatar serve, backup restore, attachment storage, static file handlers |
| **Input entry** | Params named `file`, `filename`, `path`, `document`, or IDs resolved to paths |
| **Path sinks** | `open()`, `FileInputStream`, `Paths.get(base, input)`, `sendFile`, cloud key builders |
| **Weak controls** | Denylist only (`contains("..")`), missing URL decode before validation |
| **Write paths** | Upload save, log rotation, export directories with crafted names |
| **Symlink risk** | Resolved paths escape via symlinks under the base directory |

## Sample Vulnerable Code in Python

```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/get_file")
def get_file():
    filename = request.args.get("file")
    # Sink: user input concatenated into path without containment check
    return open(f"/var/www/uploads/{filename}", "r").read()
```

## Step-by-Step Review Walkthrough

1. **Find user-influenced path parameters.** Search for `file`, `filename`, `path`, and similar names before file API calls.
2. **Trace the Python download handler.** In the sample, `../../../etc/passwd` escapes the upload folder. Canonical containment is required.
3. **Inspect path joins.** `Paths.get(base, userInput)` without resolve check is a common pattern in Java and Python.
4. **Check denylist-only validation.** `if ".." in name` without comparing canonical paths fails on encoded dots and absolute paths.
5. **Review write paths.** Upload and export handlers must confine writes the same way as reads.
6. **Confirm opaque ID indirection.** Public APIs should map server-side storage keys, not raw path strings.
7. **Log rejected attempts server-side.** Do not echo full attacker paths in client error messages.

## Risk Impact Analysis

**Arbitrary file read.** Attackers retrieve application secrets, keys, and system files such as `/etc/passwd`.

**Arbitrary file write.** Combined with upload or export features, traversal may overwrite configuration or web roots.

**Multi-tenant data breach.** Escaping one tenant's directory may expose another user's attachments.

**Cloud storage equivalents.** The same logic applies when user input builds S3 or blob object keys.

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

from flask import Flask, abort, request, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = Path("/var/www/uploads").resolve()

@app.route("/get_file")
def get_file():
    name = secure_filename(request.args.get("file", ""))
    if not name:
        abort(400)
    target = (UPLOAD_FOLDER / name).resolve()
    if not target.is_relative_to(UPLOAD_FOLDER):
        abort(403)
    if not target.is_file():
        abort(404)
    return send_from_directory(UPLOAD_FOLDER, name, as_attachment=True)
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

## Verify During Review

- Every user-influenced path is resolved and verified to stay under an explicit base directory.
- Denylist checks for `..` are supplemented by canonical path containment, not replaced by them.
- Download and upload handlers do not accept absolute paths or drive letters from clients.
- Opaque identifiers replace direct filesystem paths in public APIs where possible.
- Suspicious access attempts are logged server-side without returning internal paths in errors.
- Cloud and local storage use the same containment rules.

## Reference

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP — Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Flask — send_from_directory](https://flask.palletsprojects.com/en/stable/api/#flask.send_from_directory)
- [Werkzeug — secure_filename](https://werkzeug.palletsprojects.com/en/stable/utils/#werkzeug.utils.secure_filename)
- [Python pathlib — Path.resolve](https://docs.python.org/3/library/pathlib.html#pathlib.Path.resolve)
- [Java Path.normalize](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/nio/file/Path.html#normalize())
- [Microsoft — Path.GetFullPath](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.getfullpath)
- [Go filepath — Clean and Rel](https://pkg.go.dev/path/filepath)
