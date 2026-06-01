---
title: Review Insecure Temporary Files
keywords:
  - security code review
  - temporary files
  - tempfile
  - race condition
  - toctou
description: How to read code for insecure temporary file creation that exposes data through predictable paths, weak permissions, or TOCTOU races.
---

## 4.26 - Review Insecure Temporary Files

Temporary files can leak sensitive data when names are predictable, permissions are weak, or deletion is delayed. Review export pipelines, upload staging, report generation, and crypto scratch buffers. Confirm the code uses secure APIs, unique names, restrictive permissions, and prompt cleanup.

## What This Vulnerability Is

Insecure temporary file handling exposes application, system, or user data on shared hosts. Attackers scan `/tmp`, guess filenames from PID patterns, or win time-of-check-time-of-use races by creating a symlink before the application writes.

The unsafe assumption is that short-lived files are private because they are deleted later. Without unique unpredictable names, owner-only permissions, and secure open semantics, another local user or process can read or redirect file content. This maps to [CWE-377](https://cwe.mitre.org/data/definitions/377.html) (Insecure Temporary File) and [CWE-367](https://cwe.mitre.org/data/definitions/367.html) (Time-of-check Time-of-use Race Condition).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Export pipelines, upload staging, report generation, crypto scratch buffers, PDF temp output |
| **Path patterns** | `/tmp/app.log`, `temporary.txt`, `tempfile_<pid>.txt`, tick-only suffixes |
| **Race windows** | `if file.exists()` followed by separate open or write |
| **Permission gaps** | World-readable exports, missing `0600`, `chmod 777` on temp dirs |
| **Cleanup gaps** | Delete only on happy path; `deleteOnExit` without guaranteed removal |
| **Shared hosts** | Multi-tenant VMs, containers with shared `/tmp`, predictable PID-based names |

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

## Sample Vulnerable Code in Python

```python
import os
import uuid

def write_payout_export(rows: list[str]) -> str:
    # Predictable name under shared /tmp — readable by other local users
    export_name = f"payout_{uuid.uuid4().hex[:6]}.csv"
    temp_file = os.path.join("/tmp", export_name)
    with open(temp_file, "w", encoding="utf-8") as f:
        f.write("\n".join(rows))
    return temp_file
```

## Step-by-Step Review Walkthrough

1. **Search for hardcoded temp paths.** Look for `/tmp/`, `temporary.txt`, and PID-only filename patterns.
2. **Trace the payout export writer.** In the sample, short UUID prefixes under shared `/tmp` remain guessable on multi-tenant hosts.
3. **Compare create APIs.** Prefer `tempfile.mkstemp` or `NamedTemporaryFile` over manual path construction.
4. **Check for TOCTOU.** Existence checks followed by separate opens create a race on shared directories.
5. **Review permissions after create.** Set owner-read/write only on Unix when defaults are loose.
6. **Trace cleanup in error paths.** `finally` blocks must delete even when exceptions occur.
7. **Confirm container isolation.** Shared temp roots on multi-tenant hosts need app-owned volumes.

## Risk Impact Analysis

**Local information disclosure.** Other users or containers on the same host may read world-readable temp exports.

**TOCTOU symlink attacks.** An attacker creates a symlink at the expected path; the application writes secrets to an attacker-chosen destination.

**Stale sensitive files.** Crashes before delete leave credentials or PII on disk beyond the intended window.

**Compliance exposure.** Uncontrolled temp storage of regulated data may violate retention and access controls.

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

## Verify During Review

- Temporary files use framework APIs that generate unpredictable names and safe default permissions.
- No check-then-act sequence opens a race on shared temp directories.
- Files are deleted as soon as processing finishes, including on error paths.
- Predictable paths under `/tmp` with PIDs or timestamps alone are replaced.
- Sensitive exports are not world-readable and not served statically without access control.
- Container and multi-user deployments use isolated temp locations where policy requires it.

## Reference

- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)
- [CWE-367: Time-of-check Time-of-use Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [Python tempfile module](https://docs.python.org/3/library/tempfile.html)
- [Java Files.createTempFile](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/nio/file/Files.html#createTempFile(java.lang.String,java.lang.String,java.nio.file.attribute.FileAttribute...))
- [Microsoft — Path.GetTempFileName](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.gettempfilename)
- [Go os.CreateTemp](https://pkg.go.dev/os#CreateTemp)
