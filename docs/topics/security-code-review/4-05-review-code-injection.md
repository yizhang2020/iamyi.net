---
title: Review Code Injection
keywords:
  - security code review
  - code injection
  - expression injection
  - script engine
  - eval
description: How to read code for code injection—trace attacker-controlled input into evaluators and verify user data is never executed as application code.
---

## 4.5 - Review Code Injection

Code injection appears when attacker-controlled input is passed to an evaluator that executes it as code. Start from rule engines, formula fields, admin consoles, and plugin systems. Trace each user-supplied string to `eval`, script engines, or dynamic template compilation.

## What This Vulnerability Is

Code injection is similar to command injection, but the attacker injects source code in a language the application executes—JavaScript, Python, Groovy, SpEL, OGNL—not OS shell commands. The application exposes an evaluation primitive for business rules, math expressions, or user-defined logic. Attacker input becomes part of that program and runs with the interpreter's privileges.

In command injection, the attacker extends existing OS command execution. In code injection, the attacker supplies program text the runtime compiles or interprets. This relates to [CWE-94](https://cwe.mitre.org/data/definitions/94.html) (Improper Control of Generation of Code) and [CWE-95](https://cwe.mitre.org/data/definitions/95.html) (Improper Neutralization of Directives in Dynamically Evaluated Code).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Formula fields, workflow rules, admin script consoles, plugin hooks, webhook transformers |
| **Input entry** | HTTP parameters, JSON rule bodies, uploaded config, admin-only text areas |
| **Evaluation APIs** | `eval`, `exec`, `ScriptEngine.eval`, SpEL, OGNL, `Function()`, pickle/yaml unsafe loaders |
| **Concatenation patterns** | Expression strings built with `+` or f-strings before evaluation |
| **Weak controls** | Sandbox claims without verified restrictions on imports, reflection, file I/O |
| **Overlap with SSTI** | Template engines that compile user-supplied source at runtime |

## Sample Vulnerable Code in Python

```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/calc")
def calc():
    # Attacker-controlled expression from query string
    expr = request.args.get("expr", "0")
    # Sink: arbitrary Python expression evaluated with full interpreter power
    result = eval(expr)
    return str(result)
```

## Step-by-Step Review Walkthrough

1. **Search for dynamic evaluation.** Find `eval`, `exec`, `ScriptEngine.eval`, `ExpressionParser`, and unsafe deserialization loaders.
2. **Trace the Python (or equivalent) input path.** In the sample, `expr` comes directly from the query string into `eval`. Ask whether any grammar restriction exists; there is none.
3. **Inspect concatenation before eval.** Patterns like `"Math.pow(" + x + ",2)"` assemble executable text from user fragments.
4. **Review admin-only features.** Formula editors and webhook transformers may be reachable through privilege escalation.
5. **Check framework expression languages.** SpEL, OGNL, EL, and rule engine APIs parse user text as code.
6. **Follow sandbox claims.** Verify restrictions on imports, reflection, and network access. Do not assume sandboxes are sufficient.
7. **Ask whether evaluation is required.** Prefer declarative configuration, safe DSLs, or precompiled static rules.

## Risk Impact Analysis

**Arbitrary code execution.** Full language evaluators run attacker code inside the application process with its credentials and network access.

**Credential and data theft.** Injected code can read environment variables, config files, database connections, and in-memory secrets.

**Authorization bypass.** Rules embedded in scripts may gate access; attacker-controlled expressions can force true conditions.

**Persistence and lateral movement.** Evaluated code may write files, spawn subprocesses, or call internal services reachable from the app tier.

## Vulnerable Examples in Other Languages

### Java

```java
public double evaluateFormula(String x, String y) throws ScriptException {
    ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
    String expression = "Math.pow(" + x + ",2) + " + y;
    return ((Number) engine.eval(expression)).doubleValue();
}
```

### C#

```csharp
public object EvaluateRule(string userRule, Dictionary<string, object> context)
{
    var engine = new Microsoft.ClearScript.V8.V8ScriptEngine();
    foreach (var kv in context)
        engine.AddHostObject(kv.Key, kv.Value);
    return engine.Evaluate(userRule);
}
```

### JavaScript

```javascript
const express = require("express");
const app = express();

app.get("/calc", (req, res) => {
  const expr = req.query.expr || "0";
  res.send(String(eval(expr))); // attacker-controlled expression
});
```

### Go

```go
func runUserScript(w http.ResponseWriter, r *http.Request) {
    script := r.FormValue("script")
    vm := goja.New()
    val, err := vm.RunString(script)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    fmt.Fprint(w, val)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Avoid `eval` and `exec` on untrusted strings. Use restricted evaluators or fixed server-side logic.

```python
from simpleeval import simple_eval

@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    try:
        result = simple_eval(expr, names={})  # no builtins, no imports
    except Exception:
        return "Invalid expression", 400
    return str(result)
```

```python
# ast.literal_eval — literals only, not expressions:
import ast
data = ast.literal_eval('{"key": "value"}')  # safe for literal structures
```

**Important:** `simpleeval` limits semantics but is not a full sandbox for hostile admin input. Prefer fixed formulas implemented in Python for untrusted users.

### Java

Replace `ScriptEngine.eval` on user input with arithmetic-only libraries or fixed Java code.

```java
import net.objecthunter.exp4j.Expression;
import net.objecthunter.exp4j.ExpressionBuilder;

public double evaluateFormula(double x, double y) {
    Expression expr = new ExpressionBuilder("pow(x,2) + y")
        .variables("x", "y")
        .build();
    return expr.setVariable("x", x).setVariable("y", y).evaluate();
}
```

**Important:** Bind variables through a sandboxed API. Never concatenate user strings into expression text.

### C#

Use expression parsers limited to math and boolean logic instead of full script engines.

```csharp
using NCalc;

public object EvaluateFormula(string expression, Dictionary<string, object> parameters)
{
    var expr = new Expression(expression);
    foreach (var kv in parameters)
        expr.Parameters[kv.Key] = kv.Value;
    return expr.Evaluate();
}
```

**Important:** Avoid ClearScript or Roslyn on user text unless heavily sandboxed, authorized, and audited.

### Go

Use a typed expression language with limited builtins instead of full JavaScript runtimes.

```go
import "github.com/expr-lang/expr"

func evaluateFormula(input string, env map[string]interface{}) (interface{}, error) {
    program, err := expr.Compile(input, expr.Env(env))
    if err != nil {
        return nil, err
    }
    return expr.Run(program, env)
}
```

**Important:** Avoid `RunString` on user input in goja, Otto, or yaegi unless in a hardened sandbox with no host bindings.

## Verify During Review

- No `eval`, `exec`, `ScriptEngine.eval`, or equivalent processes HTTP-derived strings.
- User "formulas" use a vetted arithmetic or rules DSL with a fixed grammar, not a general-purpose language.
- Expression languages have restricted contexts: no arbitrary type loading, reflection, or file I/O.
- Admin rule editors require strong authentication, authorization, and audit trails.
- Template engines do not compile user-supplied template source at runtime.
- Alternatives were considered: static code, configuration tables, or server-side business logic replace dynamic evaluation.

## Reference

- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code](https://cwe.mitre.org/data/definitions/95.html)
- [Python ast.literal_eval](https://docs.python.org/3/library/ast.html#ast.literal_eval)
- [simpleeval on PyPI](https://pypi.org/project/simpleeval/)
- [exp4j](https://www.objecthunter.net/exp4j/)
- [NCalc](https://github.com/ncalc/ncalc)
- [expr-lang/expr](https://pkg.go.dev/github.com/expr-lang/expr)
- [Java ScriptEngineManager](https://docs.oracle.com/en/java/javase/21/docs/api/java.scripting/javax/script/ScriptEngineManager.html)
