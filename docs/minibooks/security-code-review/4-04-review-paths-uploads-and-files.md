---
title: Review Paths, Uploads, and Files
keywords:
  - path traversal
  - file upload
  - temporary files
  - file parsing
description: Review path traversal, uploads, temp files, and unsafe file parsing together.
---

## 4.4 - Review Paths, Uploads, and Files

### Overview

File and path bugs share one question: can a name or payload escape the intended directory or content type? Resolve and constrain paths, validate uploads by content and policy, and treat parsers of user files as hostile input.

The points below are the ideas this family chapter uses again and again.

1. File and path bugs ask whether a name or payload can escape the intended directory or content type.
2. Resolve and constrain paths; validate uploads by content and policy.
3. Treat parsers of user files as hostile input.
4. Traversal, upload, temp files, and unsafe parsing share that escape question.
5. Evidence still names source, sink, missing control, impact, and a proving test.

After reading this chapter, we should be able to constrain paths and uploads and verify every user-influenced file name against a safe root.

## Shared Review Model

Across every variant below, keep the same evidence habit: name the **source**, the **sink**, the **missing control**, the **impact**, and a **test** that would prove a fix.

## Variants in This Family

### Path traversal {: #path-traversal }

Path traversal (directory traversal) is a filesystem access flaw. Functions that open, read, write, or delete files concatenate attacker-controlled names with a base directory. Sequences like `../` or absolute paths escape the intended folder and reach sensitive files elsewhere on the server.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | File download, avatar serve, log tail, attachment read, ZIP/tar extract, backup restore |
| **Input entry** | Filename parameters, path segments, attachment IDs mapped to paths, archive entry names |
| **Path construction** | `base + filename`, f-strings, `Path.join`, `send_file`, `http.ServeFile` |
| **Weak controls** | Denylist of `..` only, no canonical prefix check, URL-encoded traversal variants |
| **Write/delete paths** | Upload overwrite, extract-all without per-entry validation (zip slip) |
| **Indirect paths** | Database-stored filenames, object storage keys, cache keys resolved to filesystem paths |

**Appendix detail:** [Path traversal code reference](appendix/code-level-reference/4-04-review-paths-uploads-and-files.md#path-traversal).

### Insecure file path handling {: #file-path }

Path (directory) traversal occurs when the application uses attacker-controlled strings as file paths without confining access to an allowed base directory. Functions that serve files by name are the most common location. Concatenation and `Paths.get(base, userInput)` without a canonical path check can reach `/etc/passwd` or application configuration.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | File download, avatar serve, backup restore, attachment storage, static file handlers |
| **Input entry** | Params named `file`, `filename`, `path`, `document`, or IDs resolved to paths |
| **Path sinks** | `open()`, `FileInputStream`, `Paths.get(base, input)`, `sendFile`, cloud key builders |
| **Weak controls** | Denylist only (`contains("..")`), missing URL decode before validation |
| **Write paths** | Upload save, log rotation, export directories with crafted names |
| **Symlink risk** | Resolved paths escape via symlinks under the base directory |

**Appendix detail:** [Insecure file path handling code reference](appendix/code-level-reference/4-04-review-paths-uploads-and-files.md#file-path).

### Insecure file upload {: #upload }

Insecure file upload handling allows attackers to place unexpected content on server storage. Risks include uploading web shells when files land under a web root, cross-site content when browsers interpret uploads as HTML or SVG, virus propagation, quota exhaustion, and metadata tricks that bypass extension checks.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Avatar, attachment, import, CMS media, presigned object uploads |
| **Storage location** | Web-accessible `public/`, servlet context roots, shared buckets with public ACL |
| **Validation order** | Extension-only checks, client `Content-Type` trusted, size limits after full buffer |
| **Naming** | Preserving `originalFilename` from client as on-disk path component |
| **Active content** | SVG/HTML allowed as inline "images", user MIME echoed on download |
| **AuthZ gaps** | Upload without matching download permission for other users' objects |

**Appendix detail:** [Insecure file upload code reference](appendix/code-level-reference/4-04-review-paths-uploads-and-files.md#upload).

### Insecure temporary files {: #temp-files }

Insecure temporary file handling exposes application, system, or user data on shared hosts. Attackers scan `/tmp`, guess filenames from PID patterns, or win time-of-check-time-of-use races by creating a symlink before the application writes.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Export pipelines, upload staging, report generation, crypto scratch buffers, PDF temp output |
| **Path patterns** | `/tmp/app.log`, `temporary.txt`, `tempfile_<pid>.txt`, tick-only suffixes |
| **Race windows** | `if file.exists()` followed by separate open or write |
| **Permission gaps** | World-readable exports, missing `0600`, `chmod 777` on temp dirs |
| **Cleanup gaps** | Delete only on happy path; `deleteOnExit` without guaranteed removal |
| **Shared hosts** | Multi-tenant VMs, containers with shared `/tmp`, predictable PID-based names |

**Appendix detail:** [Insecure temporary files code reference](appendix/code-level-reference/4-04-review-paths-uploads-and-files.md#temp-files).

### Insecure file parsing {: #file-parsing }

Insecure file parsing treats attacker-supplied files as trustworthy input to complex format libraries. ZIP bombs, XML external entities (XXE), malicious Office macros, pickle payloads, and malformed images can exhaust memory, read local files, or execute code inside the parser or downstream handlers.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Config import, archive upload, XML/YAML ingestion, image conversion, document preview |
| **Parser types** | ZIP, TAR, XML, YAML, pickle, Java serialization, PDF, image decoders |
| **Unsafe loaders** | `yaml.load`, `pickle.load`, `ObjectInputStream`, `BinaryFormatter` |
| **Archive sinks** | `ZipEntry.getName()` joined to output path without canonical check |
| **Resource limits** | Missing caps on entry count, uncompressed size, recursion depth |
| **Post-parse use** | Parsed objects fed into reflection, scripting, or dynamic SQL |

**Appendix detail:** [Insecure file parsing code reference](appendix/code-level-reference/4-04-review-paths-uploads-and-files.md#file-parsing).

## Worked Example (Path traversal)

We walk **Path traversal** in depth. Apply the same tracing steps to the other variants, adjusting sources and sinks from the tables above.

### Sample vulnerable code (Python)

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

### Step-by-step review walkthrough

1. **Find file I/O endpoints.** Search for download, upload, delete, and archive extract handlers that accept names or paths.
2. **Trace the Python (or equivalent) input path.** In the sample, `avatar` is concatenated into a user-specific path. Ask whether `../../etc/passwd` resolves outside `/var/www/avatars/{user_id}`.
3. **Inspect normalization.** Check for `resolve()`, `getCanonicalPath()`, `filepath.Clean()`, and whether results are compared to a trusted root prefix.
4. **Review weak filters.** Blocking only `..` substring may miss `....//`, URL encoding, Unicode separators, or absolute paths.
5. **Follow indirect paths.** Database-stored filenames and attachment IDs mapped to paths need the same root check.
6. **Inspect write and extract operations.** Traversal on upload or `extractall` can overwrite binaries or drop web shells.
7. **Check symlink behavior.** Resolved paths that follow symlinks may escape the intended directory.

## Risk Impact (Family)

**Sensitive file read.** Attackers retrieve application secrets, source code, credentials, and system files such as `/etc/passwd`.

**Arbitrary file write.** Traversal combined with upload or extract may overwrite configuration or plant executable content in web-served directories.

**Service disruption.** Deleting or corrupting files outside the intended directory can break the application or host.

**Compliance exposure.** Unauthorized access to customer data files may trigger breach notification and audit findings.

## Fix Principles

Primary safer patterns for the worked example follow. For other languages and variant-specific fixes, use the [family appendix](appendix/code-level-reference/4-04-review-paths-uploads-and-files.md).

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

## Verify During Review

Use the checklist below as a family-level pass over the variants above. Each item should map to evidence in the change under review.

- Resolved filesystem paths are verified to stay within the intended base directory before I/O.
- User input never supplies absolute paths; directory separators and `..` sequences are rejected or stripped safely.
- Archive extraction validates every member path against the destination root (zip slip prevention).
- Download endpoints use framework helpers (`send_from_directory`, rooted file providers) where available.
- Stored filenames on disk are opaque identifiers, not raw client-provided names with path components.
- Suspicious traversal attempts are logged and covered by automated security tests.
- Every user-influenced path is resolved and verified to stay under an explicit base directory.
- Denylist checks for `..` are supplemented by canonical path containment, not replaced by them.
- Download and upload handlers do not accept absolute paths or drive letters from clients.
- Opaque identifiers replace direct filesystem paths in public APIs where possible.
- Suspicious access attempts are logged server-side without returning internal paths in errors.
- Cloud and local storage use the same containment rules.
- Uploads are stored outside executable web roots or served through controlled endpoints with safe headers.
- Filenames on disk are server-generated; client-supplied names are not used as path components.
- Type validation uses content inspection and allowlists appropriate to the business need.
- Size, rate, and per-user quotas limit abuse and DoS via large files.
- Authorization covers upload, list, download, and delete for multi-tenant data.
- Uploaded content is scanned or transformed where policy requires before other users can access it.
- Temporary files use framework APIs that generate unpredictable names and safe default permissions.
- No check-then-act sequence opens a race on shared temp directories.
- Files are deleted as soon as processing finishes, including on error paths.
- Predictable paths under `/tmp` with PIDs or timestamps alone are replaced.
- Sensitive exports are not world-readable and not served statically without access control.
- Container and multi-user deployments use isolated temp locations where policy requires it.
- No unsafe deserialization or YAML/XML loaders on attacker-controlled file bytes.
- Archive extraction validates every member path against a fixed base directory.
- Parser limits cap compressed size, entry count, and recursion depth.
- Parsed output is validated as data, not executed or reflected into code paths.
- Dangerous format features (macros, DTD, external entities) are disabled or rejected.
- High-risk parsing runs with minimal privileges and monitoring for anomalies.

## Code Reference (Appendix)

Payloads, language-specific sinks, multi-language examples, and full fix catalogs for every variant live in **[4.4 code reference — Review Paths, Uploads, and Files](appendix/code-level-reference/4-04-review-paths-uploads-and-files.md)**.

## Reference

- Appendix — [4.4 code reference](appendix/code-level-reference/4-04-review-paths-uploads-and-files.md)

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
- [OWASP — Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Flask — send_from_directory](https://flask.palletsprojects.com/en/stable/api/#flask.send_from_directory)
- [Werkzeug — secure_filename](https://werkzeug.palletsprojects.com/en/stable/utils/#werkzeug.utils.secure_filename)
- [Python pathlib — Path.resolve](https://docs.python.org/3/library/pathlib.html#pathlib.Path.resolve)
- [Microsoft — Path.GetFullPath](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.getfullpath)
- [Go filepath — Clean and Rel](https://pkg.go.dev/path/filepath)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [OWASP — File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [Flask — Uploading files](https://flask.palletsprojects.com/en/stable/patterns/fileuploads/)
- [Pillow — Image.verify](https://pillow.readthedocs.io/en/stable/reference/Image.html#PIL.Image.Image.verify)
- [Java Servlet Part API](https://jakarta.ee/specifications/servlet/6.0/apidocs/jakarta.servlet/jakarta/servlet/http/part)
- [ASP.NET Core — IFormFile](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.http.iformfile)
- [Go http.MaxBytesReader](https://pkg.go.dev/net/http#MaxBytesReader)
- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)
- [CWE-367: Time-of-check Time-of-use Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [Python tempfile module](https://docs.python.org/3/library/tempfile.html)
- [Java Files.createTempFile](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/nio/file/Files.html#createTempFile(java.lang.String,java.lang.String,java.nio.file.attribute.FileAttribute...))
- [Microsoft — Path.GetTempFileName](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.gettempfilename)
- [Go os.CreateTemp](https://pkg.go.dev/os#CreateTemp)
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [OWASP — Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [PyYAML — safe_load](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [Python defusedxml](https://pypi.org/project/defusedxml/)
- [Java DocumentBuilderFactory security features](https://docs.oracle.com/en/java/javase/21/docs/api/java.xml/module-summary.html)
- [Microsoft — BinaryFormatter obsolete](https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide)
- [Go archive/zip package](https://pkg.go.dev/archive/zip)
