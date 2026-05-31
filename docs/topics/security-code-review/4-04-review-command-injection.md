---
title: Review Command Injection
keywords:
  - security code review
  - command injection
  - os command injection
  - shell injection
  - CWE-78
description: How to read code for command injection—trace attacker-controlled input into process-spawning APIs and verify arguments are allowlisted or passed without a shell.
---

## 4.4 - Review Command Injection

Command injection appears when attacker-controlled input is passed to an operating system command or shell. Start from ping tools, file converters, backup scripts, and DevOps automation. Trace each parameter to `subprocess`, `Runtime.exec`, or equivalent APIs.

## What This Vulnerability Is

Command injection vulnerabilities arise when a developer executes an external command with a parameter that the user controls. The application already invokes system utilities—ping, ImageMagick, git, tar—and attacker input extends or replaces intended arguments. Shell metacharacters such as `;`, `|`, `&&`, `` ` ``, and `$()` let the attacker run arbitrary commands with the application's OS privileges.

The unsafe assumption is that user input is a harmless hostname, filename, or flag value. Unlike code injection, the application intentionally calls the OS; the attacker hijacks that existing capability. This maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html) (Improper Neutralization of Special Elements used in an OS Command).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Network diagnostics, PDF/image conversion, git hooks, backup restore, CI triggers, admin shell tools |
| **Input entry** | HTTP parameters, uploaded filenames, webhook payloads, config values |
| **Process APIs** | `subprocess`, `Runtime.exec`, `ProcessBuilder`, `Process.Start`, `exec.Command` |
| **Shell usage** | `shell=True`, `/bin/sh -c`, `cmd.exe /c`, single command-line strings with user data |
| **Weak controls** | Regex denylist of metacharacters, `shlex.quote` as the only defense |
| **High impact context** | Processes running as root, container escape paths, shared hosting environments |

## Sample Vulnerable Code in Python

```python
import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/tools/ping")
def ping():
    # Attacker-controlled hostname from query string
    host = request.args.get("host", "")
    # Sink: user input embedded in shell command string
    output = subprocess.check_output(f"ping -c 3 {host}", shell=True)
    return output
```

## Step-by-Step Review Walkthrough

1. **Search for process-spawning APIs.** Find `subprocess`, `os.system`, `Runtime.exec`, `Process.Start`, and `exec.Command`.
2. **Trace the Python (or equivalent) input path.** In the sample, `host` flows into an f-string passed to a shell. Ask whether `shell=True` is required; here it enables metacharacter injection.
3. **Identify shell vs argv invocation.** Shell wrappers (`sh -c`, `cmd /c`) concatenate user data into one string. Prefer fixed binary plus separate arguments.
4. **Review argument sources.** Trace each argument to HTTP parameters, filenames, and webhook fields.
5. **Check wrappers around diagnostics and media tools.** Ping, traceroute, ffmpeg, and ImageMagick endpoints are common targets.
6. **Ask whether the external command is necessary.** Native libraries or service APIs often replace shelling out.
7. **Note the OS user.** Container isolation limits but does not eliminate impact when subprocesses run with broad privileges.

## Risk Impact Analysis

**Arbitrary command execution.** Attackers run shell commands as the application OS user, enabling file read, modification, and lateral movement.

**Credential and secret theft.** Process environment, config files, and cloud metadata endpoints may be reachable from injected commands.

**Service disruption.** Injected commands can delete data, fork resource-heavy processes, or kill application services.

**Supply-chain pivot.** Compromised app servers may be used to scan internal networks or deploy malware when outbound access exists.

## Vulnerable Examples in Other Languages

### Java

```java
public void pingHost(String hostname) throws IOException {
    String[] cmd = { "/bin/sh", "-c", "ping -c 3 " + hostname };
    Process p = Runtime.getRuntime().exec(cmd);
    p.waitFor();
}
```

### C#

```csharp
public string RunTraceroute(string target)
{
    var psi = new ProcessStartInfo("cmd.exe", $"/c tracert {target}")
    {
        RedirectStandardOutput = true,
        UseShellExecute = false
    };
    using var proc = Process.Start(psi);
    return proc.StandardOutput.ReadToEnd();
}
```

### Shell

```bash
#!/bin/bash
# CGI or cron wrapper: host comes from query string / env
host="$QUERY_HOST"
ping -c 3 "$host"   # host=127.0.0.1; id
```

```sh
# One-liner invoked from app code: nslookup example.com; cat /etc/passwd
nslookup $1
```

### Go

```go
func pingHandler(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    cmd := exec.Command("sh", "-c", "ping -c 3 "+host)
    out, _ := cmd.CombinedOutput()
    w.Write(out)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Invoke binaries with an argument list. Never pass user input through a shell.

```python
import re
import subprocess

HOST_PATTERN = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")

@app.route("/tools/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST_PATTERN.fullmatch(host):
        return "Invalid host", 400
    output = subprocess.run(
        ["ping", "-c", "3", host],
        check=True,
        capture_output=True,
        timeout=10,
    )
    return output.stdout
```

**Important:** `shlex.quote` is a secondary defense only. Prefer argv lists and strict allowlists over quoting into shell strings.

```python
# Prefer native libraries when possible:
import socket
socket.gethostbyname(host)  # DNS lookup without shell ping
```

### Java

Use `ProcessBuilder` with a fixed binary path and separate arguments.

```java
public void pingHost(String hostname) throws IOException, InterruptedException {
    if (!hostname.matches("[a-zA-Z0-9.-]{1,253}")) {
        throw new IllegalArgumentException("Invalid host");
    }
    ProcessBuilder pb = new ProcessBuilder("ping", "-c", "3", hostname);
    pb.redirectErrorStream(true);
    Process p = pb.start();
    p.waitFor();
}
```

**Important:** Never embed user input in `-c` command strings. Each argument must be a separate list element.

### C#

Use `ProcessStartInfo.ArgumentList` instead of `/c` command strings.

```csharp
public string RunPing(string target)
{
    if (!Regex.IsMatch(target, @"^[a-zA-Z0-9.-]{1,253}$"))
        throw new ArgumentException("Invalid host");

    var psi = new ProcessStartInfo
    {
        FileName = "ping",
        RedirectStandardOutput = true,
        UseShellExecute = false
    };
    psi.ArgumentList.Add("-c");
    psi.ArgumentList.Add("3");
    psi.ArgumentList.Add(target);
    using var proc = Process.Start(psi);
    return proc!.StandardOutput.ReadToEnd();
}
```

**Important:** Avoid `UseShellExecute = true` when user-influenced arguments are involved.

### Go

Pass arguments separately. Never use `sh -c` with concatenated user input.

```go
var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9.-]{1,253}$`)

func pingHandler(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    if !hostPattern.MatchString(host) {
        http.Error(w, "invalid host", http.StatusBadRequest)
        return
    }
    cmd := exec.Command("ping", "-c", "3", host)
    out, err := cmd.CombinedOutput()
    if err != nil {
        http.Error(w, "ping failed", http.StatusInternalServerError)
        return
    }
    w.Write(out)
}
```

**Important:** Set context timeouts on subprocess calls to limit abuse windows.

## Verify During Review

- User input never appears in shell command strings (`sh -c`, `cmd /c`, `shell=True`).
- Process APIs use argument arrays with allowlisted or strictly validated values per argument.
- External commands are removed or replaced with in-process libraries where feasible.
- Filenames and paths passed to CLI tools are canonicalized and restricted to expected directories.
- The OS account running subprocesses has minimal permissions.
- Security tests include metacharacter payloads (`; id`, `| whoami`, `` `id` ``) in relevant parameters.

## Reference

- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Python subprocess — security considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [Java ProcessBuilder](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/ProcessBuilder.html)
- [Apache Commons Exec](https://commons.apache.org/proper/commons-exec/)
- [C# ProcessStartInfo.ArgumentList](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist)
- [Go os/exec package](https://pkg.go.dev/os/exec)
