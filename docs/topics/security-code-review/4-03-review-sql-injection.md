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

## Sample Vulnerable Code in Python

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/users")
def find_user():
    # Attacker-controlled username from query string
    name = request.args.get("name", "")
    cursor = db.cursor()
    # Sink: user input concatenated into SQL — changes query structure
    cursor.execute(f"SELECT * FROM users WHERE username = '{name}'")
    return jsonify(cursor.fetchall())
```

## Step-by-Step Review Walkthrough

1. **Find every database call.** Search for ORM raw queries, DB-API cursors, and stored procedure invocations built from strings.
2. **Trace the Python (or equivalent) input path.** In the sample, `request.args.get("name")` flows into an f-string. Ask whether any placeholder binding exists; there is none.
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
public User authenticate(String username, String password) throws SQLException {
    String sql = "SELECT * FROM users WHERE username = '" + username
               + "' AND password = '" + password + "'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(sql);
    return rs.next() ? mapUser(rs) : null;
}
```

### C#

```csharp
public User GetUser(string username)
{
    var sql = $"SELECT * FROM Users WHERE Username = '{username}'";
    using var cmd = new SqlCommand(sql, _connection);
    using var reader = cmd.ExecuteReader();
    return reader.Read() ? MapUser(reader) : null;
}
```

### SQL

```sql
-- Dynamic SQL built inside the database (concatenated parameter)
CREATE PROCEDURE dbo.GetUser @name NVARCHAR(128)
AS
BEGIN
    DECLARE @sql NVARCHAR(MAX) =
        N'SELECT * FROM Users WHERE Username = ''' + @name + N'''';
    EXEC(@sql);
END;
```

```sql
-- Second-order: stored value breaks a later batch query
SELECT * FROM audit_log
WHERE message LIKE '%' + (SELECT bio FROM users WHERE id = @id) + '%';
```

### Go

```go
func getUser(db *sql.DB, username string) (*User, error) {
    query := fmt.Sprintf("SELECT id, username FROM users WHERE username = '%s'", username)
    row := db.QueryRow(query)
    var u User
    err := row.Scan(&u.ID, &u.Username)
    return &u, err
}
```

## Fix: Safer Patterns and Libraries to Use

### Python

Use DB-API parameterized queries or ORM filters. Never interpolate user strings into SQL text.

```python
@app.route("/users")
def find_user():
    name = request.args.get("name", "")
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (name,))
    return jsonify(cursor.fetchall())
```

```python
# SQLAlchemy — prefer ORM filters or bound text():
from sqlalchemy import text

session.execute(
    text("SELECT * FROM users WHERE username = :name"),
    {"name": name},
)
```

**Important:** Dynamic column or table names cannot use `?` placeholders. Map user choices to a fixed allowlist before query assembly.

```python
ALLOWED_SORT = {"name", "created_at"}
sort = request.args.get("sort", "name")
if sort not in ALLOWED_SORT:
    sort = "name"
cursor.execute(f"SELECT * FROM users ORDER BY {sort}")  # sort is allowlisted only
```

### Java

Bind user values with `PreparedStatement` setters.

```java
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement ps = connection.prepareStatement(sql);
ps.setString(1, username);
ps.setString(2, passwordHash);
ResultSet rs = ps.executeQuery();
```

```java
// Spring JdbcTemplate
jdbcTemplate.query(
    "SELECT * FROM users WHERE id = ?",
    rs -> mapUser(rs),
    userId
);
```

**Important:** In MyBatis, `#{}` binds safely; `${}` performs string substitution and is unsafe for user input.

### C#

Use ADO.NET parameters with `@param` placeholders.

```csharp
var sql = "SELECT * FROM Users WHERE Username = @username";
using var cmd = new SqlCommand(sql, _connection);
cmd.Parameters.AddWithValue("@username", username);
using var reader = cmd.ExecuteReader();
```

```csharp
// Entity Framework Core — prefer LINQ:
var user = _db.Users.FirstOrDefault(u => u.Username == username);
```

**Important:** `FromSqlRaw` with string interpolation is unsafe. Use `FromSqlRaw` with explicit `SqlParameter` objects or LINQ.

### Go

Use `database/sql` placeholders. Never build query strings with user input.

```go
row := db.QueryRow("SELECT id, username FROM users WHERE username = ?", username)
```

```go
// sqlx named query
query := `SELECT id, username FROM users WHERE username = :username`
rows, err := db.NamedQuery(query, map[string]interface{}{"username": username})
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
