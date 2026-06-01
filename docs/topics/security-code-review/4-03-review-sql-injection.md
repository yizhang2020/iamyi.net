---
title: Review SQL Injection
keywords:
  - security code review
  - sql injection
  - prepared statements
  - parameterized queries
  - CWE-89
description: How to read code for SQL injection—trace attacker-controlled input into database calls and verify values are bound as data, not appended as syntax.
---

## 4.3 - Review SQL Injection

SQL injection appears when attacker-controlled input is concatenated into SQL and changes query meaning. Start from login flows, search filters, sort columns, and reporting queries. Trace each user-supplied value to the database call and confirm it is bound as data.

## What This Vulnerability Is

SQL injection occurs when data from a user or external system is included in a SQL statement without proper parameterization. The attacker supplies metacharacters such as quotes, comment markers, or boolean operators that alter the query structure. Impact may include authentication bypass, unauthorized reads, data modification, or—in some configurations—execution of database server commands.

The unsafe assumption is that user input is always benign data. Denylisting characters is fragile; attackers routinely bypass naive filters. Prepared statements separate query structure from user data. This maps to [CWE-89](https://cwe.mitre.org/data/definitions/89.html) (Improper Neutralization of Special Elements used in an SQL Command).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Login, search, filters, reporting, admin dashboards, bulk export, audit queries |
| **Input entry** | HTTP parameters, JSON fields, headers, cookies, upstream service responses |
| **Query construction** | String concatenation, f-strings, `format()`, ORM `.raw()` / `FromSqlRaw` / `$queryRaw` |
| **Dynamic fragments** | `ORDER BY`, column names, table names, `IN (...)` clauses built from user strings |
| **Weak controls** | Escaping quotes only, denylist of `'`, `;`, `--`, `#` without parameter binding |
| **Second-order paths** | Values stored earlier and later embedded in queries without parameterization |

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

## Sample Vulnerable Code in Python

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

## Step-by-Step Review Walkthrough

1. **Find every database call.** Search for ORM raw queries, DB-API cursors, and stored procedure invocations built from strings.
2. **Trace the Python (or equivalent) input path.** In the sample, `region` and `sort_col` flow into an f-string. Ask whether any placeholder binding exists; there is none.
3. **Inspect concatenation patterns.** Flag `+`, `%`, f-string, and `format()` that include request data in SQL text.
4. **Review dynamic identifiers.** Column names, table names, and `ORDER BY` clauses from user input need allowlists, not quoting alone.
5. **Follow ORM escape hatches.** Audit `.raw()`, `.extra()`, `text()` with string interpolation, and similar APIs.
6. **Check second-order SQLi.** Values read from the database and later embedded in queries must use the same binding rules as direct input.
7. **Confirm error handling.** Ask whether failed queries expose full SQL or stack traces to untrusted clients.

## Risk Impact Analysis

**Authentication bypass.** Login queries with string-built credentials may return rows when attackers inject `' OR '1'='1`.

**Data exposure.** `UNION SELECT` and blind boolean or timing techniques can read tables the application role can access.

**Data integrity.** Injected `UPDATE` or `DELETE` statements may modify or destroy records when write access exists.

**Server compromise.** Some database configurations allow stacked queries or extension loading that escalates to OS-level impact.

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

## Verify During Review

- All user-derived values use bound parameters; no string concatenation into SQL text.
- Dynamic `ORDER BY`, column, and table names use allowlists, not user strings wrapped in quotes.
- ORM raw-query escape hatches are audited and rare; each instance has a documented safe pattern.
- Second-order queries parameterize values read from the database the same way as direct input.
- Database accounts follow least privilege; the application role cannot run admin commands unnecessarily.
- Error responses do not return full SQL statements or stack traces to untrusted clients.

## Reference

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
