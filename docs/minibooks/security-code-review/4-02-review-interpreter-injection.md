---
title: Review Interpreter Injection
keywords:
  - sql injection
  - command injection
  - SSTI
  - code injection
description: Review SQL, command, code, JSON, and template injection as interpreter-boundary failures.
---

## 4.2 - Review Interpreter Injection

### Overview

Interpreter injection happens when attacker-controlled data is concatenated into a language the runtime will parse—SQL, shell, eval, templates, or crafted JSON structures. The shared review move is to separate **structure from data** (parameters, argv arrays, safe template APIs) and refuse user influence over identifiers that must stay allowlisted.

The points below are the ideas this family chapter uses again and again.

1. Interpreter injection concatenates attacker data into a language the runtime will parse.
2. Separate structure from data with parameters, argv arrays, or safe template APIs.
3. SQL, command, code, JSON, and SSTI share that boundary failure with different interpreters.
4. Refuse user influence over identifiers that must stay allowlisted.
5. Record source, sink, missing control, impact, and a proving test.

After reading this chapter, we should be able to spot interpreter-boundary failures across SQL, shell, eval, JSON, and templates with shared evidence habits.

## Shared Review Model

Across every variant below, keep the same evidence habit: name the **source**, the **sink**, the **missing control**, the **impact**, and a **test** that would prove a fix.

## Variants in This Family

### SQL injection {: #sql }

SQL injection occurs when data from a user or external system is included in a SQL statement without proper parameterization. The attacker supplies metacharacters such as quotes, comment markers, or boolean operators that alter the query structure. Impact may include authentication bypass, unauthorized reads, data modification, or—in some configurations—execution of database server commands.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login, search, filters, reporting, admin dashboards, bulk export, audit queries |
| **Input entry** | HTTP parameters, JSON fields, headers, cookies, upstream service responses |
| **Query construction** | String concatenation, f-strings, `format()`, ORM `.raw()` / `FromSqlRaw` / `$queryRaw` |
| **Dynamic fragments** | `ORDER BY`, column names, table names, `IN (...)` clauses built from user strings |
| **Weak controls** | Escaping quotes only, denylist of `'`, `;`, `--`, `#` without parameter binding |
| **Second-order paths** | Values stored earlier and later embedded in queries without parameterization |

**Appendix detail:** [SQL injection code reference](appendix/code-level-reference/4-02-review-interpreter-injection.md#sql).

### Command injection {: #command }

Command injection vulnerabilities arise when a developer executes an external command with a parameter that the user controls. The application already invokes system utilities—ping, ImageMagick, git, tar—and attacker input extends or replaces intended arguments. Shell metacharacters such as `;`, `|`, `&&`, `` ` ``, and `$()` let the attacker run arbitrary commands with the application's OS privileges.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Network diagnostics, PDF/image conversion, git hooks, backup restore, CI triggers, admin shell tools |
| **Input entry** | HTTP parameters, uploaded filenames, webhook payloads, config values |
| **Process APIs** | `subprocess`, `Runtime.exec`, `ProcessBuilder`, `Process.Start`, `exec.Command` |
| **Shell usage** | `shell=True`, `/bin/sh -c`, `cmd.exe /c`, single command-line strings with user data |
| **Weak controls** | Regex denylist of metacharacters, `shlex.quote` as the only defense |
| **High impact context** | Processes running as root, container escape paths, shared hosting environments |

**Appendix detail:** [Command injection code reference](appendix/code-level-reference/4-02-review-interpreter-injection.md#command).

### Code injection {: #code }

Code injection is similar to command injection, but the attacker injects source code in a language the application executes—JavaScript, Python, Groovy, SpEL, OGNL—not OS shell commands. The application exposes an evaluation primitive for business rules, math expressions, or user-defined logic. Attacker input becomes part of that program and runs with the interpreter's privileges.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Formula fields, workflow rules, admin script consoles, plugin hooks, webhook transformers |
| **Input entry** | HTTP parameters, JSON rule bodies, uploaded config, admin-only text areas |
| **Evaluation APIs** | `eval`, `exec`, `ScriptEngine.eval`, SpEL, OGNL, `Function()`, pickle/yaml unsafe loaders |
| **Concatenation patterns** | Expression strings built with `+` or f-strings before evaluation |
| **Weak controls** | Sandbox claims without verified restrictions on imports, reflection, file I/O |
| **Overlap with SSTI** | Template engines that compile user-supplied source at runtime |

**Appendix detail:** [Code injection code reference](appendix/code-level-reference/4-02-review-interpreter-injection.md#code).

### JSON injection {: #json }

JSON injection is a server-side injection flaw. The application treats JSON as plain text or merges untrusted key-value pairs into objects that drive authorization, pricing, or workflow state. Attackers add fields, close strings early, or inject nested objects the developer did not intend.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Profile updates, checkout, order APIs, settings save, webhook relay, OAuth token handling |
| **Input entry** | JSON bodies, form fields embedded in JSON, query parameters serialized to JSON |
| **String-built JSON** | f-strings, concatenation of `{`, `}`, `"`, `:` from HTTP input without a serializer |
| **Mass assignment** | `dict.update`, spread operators, reflection that copies all client keys into models |
| **Weak controls** | Untyped `Map<String,Object>`, missing schema validation, trusting client price or role fields |
| **Downstream trust** | Microservices or batch jobs that accept JSON from a prior tier without re-validation |

**Appendix detail:** [JSON injection code reference](appendix/code-level-reference/4-02-review-interpreter-injection.md#json).

### Server-side template injection {: #ssti }

SSTI is a server-side code injection flaw in templating engines. Templates mix static markup with expression placeholders. When attacker-controlled text becomes part of the template itself—or is interpreted as an expression—the engine may execute code with server privileges.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Email preview, notification customization, PDF/HTML generators, admin theme editors |
| **Input entry** | Form fields, query parameters, stored user templates re-rendered at runtime |
| **Compile-from-string** | `Template(userInput)`, `from_string`, `process(String)`, `Parse(userText)`, Razor string compilation |
| **Expression contexts** | `${}`, `{{}}`, `#{}`, SpEL in views, inline template directives |
| **Weak controls** | `|safe`, `th:utext`, `@Html.Raw`, `autoescape=False` on user-influenced template source |
| **Distinction from XSS** | SSTI executes on the server during render; XSS executes in the victim browser |

**Appendix detail:** [Server-side template injection code reference](appendix/code-level-reference/4-02-review-interpreter-injection.md#ssti).

## Worked Example (SQL injection)

We walk **SQL injection** in depth. Apply the same tracing steps to the other variants, adjusting sources and sinks from the tables above.

### Sample vulnerable code (Python)

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/reports/export")
def export_report():
    # Attacker-controlled region filter and sort column from query string
    region = request.args.get("region", "")
    sort_col = request.args.get("sort", "created_at")
    cursor = db.cursor()
    # Sink: user input concatenated into SQL — changes query structure
    cursor.execute(
        f"SELECT id, total, region FROM orders "
        f"WHERE region = '{region}' ORDER BY {sort_col}"
    )
    return jsonify(cursor.fetchall())
```

### Step-by-step review walkthrough

1. **Find every database call.** Search for ORM raw queries, DB-API cursors, and stored procedure invocations built from strings.
2. **Trace the Python (or equivalent) input path.** In the sample, `region` and `sort_col` flow into an f-string. Ask whether any placeholder binding exists; there is none.
3. **Inspect concatenation patterns.** Flag `+`, `%`, f-string, and `format()` that include request data in SQL text.
4. **Review dynamic identifiers.** Column names, table names, and `ORDER BY` clauses from user input need allowlists, not quoting alone.
5. **Follow ORM escape hatches.** Audit `.raw()`, `.extra()`, `text()` with string interpolation, and similar APIs.
6. **Check second-order SQLi.** Values read from the database and later embedded in queries must use the same binding rules as direct input.
7. **Confirm error handling.** Ask whether failed queries expose full SQL or stack traces to untrusted clients.

## Risk Impact (Family)

**Authentication bypass.** Login queries with string-built credentials may return rows when attackers inject `' OR '1'='1`.

**Data exposure.** `UNION SELECT` and blind boolean or timing techniques can read tables the application role can access.

**Data integrity.** Injected `UPDATE` or `DELETE` statements may modify or destroy records when write access exists.

**Server compromise.** Some database configurations allow stacked queries or extension loading that escalates to OS-level impact.

## Fix Principles

Primary safer patterns for the worked example follow. For other languages and variant-specific fixes, use the [family appendix](appendix/code-level-reference/4-02-review-interpreter-injection.md).

### Python

Use DB-API parameterized queries or ORM filters. Never interpolate user strings into SQL text.

```python
@app.route("/reports/export")
def export_report():
    region = request.args.get("region", "")
    sort = request.args.get("sort", "created_at")
    cursor = db.cursor()
    cursor.execute(
        "SELECT id, total, region FROM orders WHERE region = ? ORDER BY created_at",
        (region,),
    )
    return jsonify(cursor.fetchall())
```

```python
# SQLAlchemy — prefer ORM filters or bound text():
from sqlalchemy import text

session.execute(
    text("SELECT id, total FROM orders WHERE region = :region ORDER BY created_at"),
    {"region": region},
)
```

**Important:** Dynamic column or table names cannot use `?` placeholders. Map user choices to a fixed allowlist before query assembly.

```python
ALLOWED_SORT = {"created_at", "total", "region"}
sort = request.args.get("sort", "created_at")
if sort not in ALLOWED_SORT:
    sort = "created_at"
cursor.execute(f"SELECT id, total, region FROM orders ORDER BY {sort}")  # sort is allowlisted only
```

## Verify During Review

Use the checklist below as a family-level pass over the variants above. Each item should map to evidence in the change under review.

- All user-derived values use bound parameters; no string concatenation into SQL text.
- Dynamic `ORDER BY`, column, and table names use allowlists, not user strings wrapped in quotes.
- ORM raw-query escape hatches are audited and rare; each instance has a documented safe pattern.
- Second-order queries parameterize values read from the database the same way as direct input.
- Database accounts follow least privilege; the application role cannot run admin commands unnecessarily.
- Error responses do not return full SQL statements or stack traces to untrusted clients.
- User input never appears in shell command strings (`sh -c`, `cmd /c`, `shell=True`).
- Process APIs use argument arrays with allowlisted or strictly validated values per argument.
- External commands are removed or replaced with in-process libraries where feasible.
- Filenames and paths passed to CLI tools are canonicalized and restricted to expected directories.
- The OS account running subprocesses has minimal permissions.
- Security tests include metacharacter payloads (`; id`, `| whoami`, `` `id` ``) in relevant parameters.
- No `eval`, `exec`, `ScriptEngine.eval`, or equivalent processes HTTP-derived strings.
- User "formulas" use a vetted arithmetic or rules DSL with a fixed grammar, not a general-purpose language.
- Expression languages have restricted contexts: no arbitrary type loading, reflection, or file I/O.
- Admin rule editors require strong authentication, authorization, and audit trails.
- Template engines do not compile user-supplied template source at runtime.
- Alternatives were considered: static code, configuration tables, or server-side business logic replace dynamic evaluation.
- No hand-built JSON strings include HTTP parameters without proper escaping through a serializer.
- Request bodies bind to typed DTOs with unknown fields rejected or ignored by policy.
- Price, role, ownership, and status fields are set server-side, not copied from client JSON.
- Schema validation runs at the API boundary and in tests for extra-key and type-confusion cases.
- JSON stored in databases or queues is produced by libraries, not string templates.
- Downstream consumers re-validate or treat upstream JSON as untrusted when crossing trust boundaries.
- User input is passed as template data variables, never concatenated into template source.
- No runtime `from_string`, `process(String)`, `Parse(userText)`, or Razor string compilation on HTTP input.
- Rich text features use sanitization libraries, not full template engines on user-authored markup.
- Preview and customization features require strong authorization and audit logging.
- Auto-escape defaults remain enabled; unsafe unescaped sinks are absent on untrusted fields.
- Engine-specific SSTI probes are covered in security tests for each dynamic render path.

## Code Reference (Appendix)

Payloads, language-specific sinks, multi-language examples, and full fix catalogs for every variant live in **[4.2 code reference — Review Interpreter Injection](appendix/code-level-reference/4-02-review-interpreter-injection.md)**.

## Reference

- Appendix — [4.2 code reference](appendix/code-level-reference/4-02-review-interpreter-injection.md)

- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Python sqlite3 — execute parameters](https://docs.python.org/3/library/sqlite3.html#sqlite3.Cursor.execute)
- [SQLAlchemy — Sending Parameters](https://docs.sqlalchemy.org/en/latest/core/sqlelement.html#sqlalchemy.sql.expression.text)
- [JDBC PreparedStatement](https://docs.oracle.com/en/java/javase/21/docs/api/java.sql/java/sql/PreparedStatement.html)
- [Spring JdbcTemplate](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/jdbc/core/JdbcTemplate.html)
- [MyBatis — `#{}` vs `${}`](https://mybatis.org/mybatis-3/sqlmap-xml.html)
- [ADO.NET SqlCommand.Parameters](https://learn.microsoft.com/en-us/dotnet/api/system.data.sqlclient.sqlcommand.parameters)
- [Entity Framework Core — Raw SQL queries](https://learn.microsoft.com/en-us/ef/core/querying/sql-queries)
- [Go database/sql package](https://pkg.go.dev/database/sql)
- [GORM — Raw SQL](https://gorm.io/docs/sql_builder.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Python subprocess — security considerations](https://docs.python.org/3/library/subprocess.html#security-considerations)
- [Java ProcessBuilder](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/ProcessBuilder.html)
- [Apache Commons Exec](https://commons.apache.org/proper/commons-exec/)
- [C# ProcessStartInfo.ArgumentList](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist)
- [Go os/exec package](https://pkg.go.dev/os/exec)
- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code](https://cwe.mitre.org/data/definitions/95.html)
- [Python ast.literal_eval](https://docs.python.org/3/library/ast.html#ast.literal_eval)
- [simpleeval on PyPI](https://pypi.org/project/simpleeval/)
- [exp4j](https://www.objecthunter.net/exp4j/)
- [NCalc](https://github.com/ncalc/ncalc)
- [expr-lang/expr](https://pkg.go.dev/github.com/expr-lang/expr)
- [Java ScriptEngineManager](https://docs.oracle.com/en/java/javase/21/docs/api/java.scripting/javax/script/ScriptEngineManager.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Variable Indexes](https://cwe.mitre.org/data/definitions/915.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [Python json module](https://docs.python.org/3/library/json.html)
- [Pydantic v2 — model configuration](https://docs.pydantic.dev/latest/api/config/)
- [jsonschema on PyPI](https://pypi.org/project/jsonschema/)
- [Jackson ObjectMapper](https://javadoc.io/doc/com.fasterxml.jackson.core/jackson-databind/latest/com/fasterxml/jackson/databind/ObjectMapper.html)
- [Jakarta Bean Validation](https://jakarta.ee/specifications/bean-validation/3.0/)
- [System.Text.Json — unmapped members](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/missing-members)
- [Go encoding/json — Decoder.DisallowUnknownFields](https://pkg.go.dev/encoding/json#Decoder.DisallowUnknownFields)
- [JSON Schema specification](https://json-schema.org/)
- [OWASP Server-Side Template Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)
- [Jinja2 — Template Designer Documentation](https://jinja.palletsprojects.com/en/stable/templates/)
- [Jinja2 SandboxedEnvironment](https://jinja.palletsprojects.com/en/stable/sandbox/)
- [Thymeleaf — th:text vs th:utext](https://www.thymeleaf.org/doc/tutorials/3.1/usingthymeleaf.html#text-inlining)
- [ASP.NET Core Razor views](https://learn.microsoft.com/en-us/aspnet/core/mvc/views/overview)
- [Go html/template package](https://pkg.go.dev/html/template)
- [bleach documentation](https://bleach.readthedocs.io/en/latest/)
