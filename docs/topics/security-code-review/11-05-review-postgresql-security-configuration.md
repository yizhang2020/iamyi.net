---
title: Review PostgreSQL Security Configuration
keywords:
  - security code review
  - PostgreSQL
  - SSL
  - row level security
  - role separation
  - connection limits
description: How to review PostgreSQL server and role configuration—SSL, row-level security, role separation, and connection limits—for least privilege data access.
---

## 11.5 - Review PostgreSQL Security Configuration

PostgreSQL security spans server configuration (`postgresql.conf`, `pg_hba.conf`), role grants, row-level security policies, and how applications open connections. Review SQL migration scripts, Helm charts, and ORM datasource settings together. TLS disabled on the wire, a superuser application role, or missing RLS on a multi-tenant table are findings even when application queries use parameterization.

## What This Misconfiguration Is

PostgreSQL misconfiguration exposes the database to network eavesdropping, privilege escalation, or cross-tenant reads. Common failures include `host` entries in `pg_hba.conf` that trust entire subnets without SCRAM authentication, application roles granted `SUPERUSER` or `BYPASSRLS`, and connections that set `sslmode=disable` in production.

The unsafe assumption is that private VPC routing replaces encryption and authorization at the database layer. Anyone who reaches the port—including a compromised sibling service—may read or mutate data the role permits. Row-level security must be enabled on the table and forced for table owners when owners should not bypass policies. This aligns with [CWE-319](https://cwe.mitre.org/data/definitions/319.html) (Cleartext Transmission of Sensitive Information) and [CWE-284](https://cwe.mitre.org/data/definitions/284.html) (Improper Access Control).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Cleartext transport** | `ssl=off`, JDBC URLs with `sslmode=disable`, missing `hostssl` in `pg_hba.conf` |
| **Superuser app role** | Migration or Helm creating `app_user` with `SUPERUSER` or `CREATEDB` |
| **RLS gaps** | Multi-tenant tables without `ENABLE ROW LEVEL SECURITY` and policies |
| **Policy bypass** | Table owner matches application role; `FORCE ROW LEVEL SECURITY` not set |
| **Role sprawl** | `GRANT ALL ON SCHEMA public TO PUBLIC`; shared role across microservices |
| **Connection exhaustion** | No `CONNECTION LIMIT` on app roles; pool size × replicas exceeds `max_connections` |
| **Weak auth** | `trust` or `md5` in `pg_hba.conf` for non-local connections |
| **Logging gaps** | `log_connections` off in production; no audit extension for sensitive tables |

## Sample Vulnerable Configuration in Python

Validate connection settings and migration SQL in CI before deploy.

```python
import re
import sys
from pathlib import Path

def review_jdbc_url(url: str, path: str) -> list[str]:
    findings: list[str] = []
    if "sslmode=disable" in url.lower() or "ssl=false" in url.lower():
        findings.append(f"{path}: PostgreSQL connection disables SSL")
    if re.search(r"password=[^&\s]+", url, re.I):
        findings.append(f"{path}: password embedded in connection URL")
    return findings

def review_sql_migration(text: str, path: str) -> list[str]:
    findings: list[str] = []
    upper = text.upper()
    if "SUPERUSER" in upper and "CREATE ROLE" in upper:
        findings.append(f"{path}: role created with SUPERUSER")
    if "BYPASSRLS" in upper:
        findings.append(f"{path}: BYPASSRLS granted")
    if "CREATE TABLE" in upper and "TENANT" in upper:
        if "ENABLE ROW LEVEL SECURITY" not in upper:
            findings.append(f"{path}: tenant table without RLS enablement")
    if "GRANT ALL" in upper and "PUBLIC" in upper:
        findings.append(f"{path}: GRANT ALL to PUBLIC")
    return findings

if __name__ == "__main__":
    for arg in sys.argv[1:]:
        p = Path(arg)
        text = p.read_text(encoding="utf-8", errors="ignore")
        findings = []
        if "postgresql://" in text or "jdbc:postgresql" in text:
            for line in text.splitlines():
                findings.extend(review_jdbc_url(line, str(p)))
        if p.suffix == ".sql":
            findings.extend(review_sql_migration(text, str(p)))
        for f in findings:
            print(f)
    sys.exit(1 if findings else 0)
```

## Step-by-Step Review Walkthrough

1. **Read `pg_hba.conf` and SSL settings.** Confirm remote clients use `hostssl` with `scram-sha-256` (or stronger) and that `ssl=on` with valid certificates in `postgresql.conf`.
2. **Inventory roles.** List roles with `\du` or `pg_roles`; flag superusers, `BYPASSRLS`, and roles shared by unrelated services.
3. **Trace grants on sensitive schemas.** Follow `GRANT` on tables, sequences, and functions; prefer schema-scoped roles with minimal DML rights.
4. **Verify RLS on tenant data.** For each table with `tenant_id`, confirm `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`, policy predicates, and `FORCE ROW LEVEL SECURITY` when the app role owns the table.
5. **Check connection limits.** Compare application pool `max_size` × replica count to role `CONNECTION LIMIT` and server `max_connections`.
6. **Review application datasource config.** Python, Java, and C# connection strings should require TLS and load passwords from vaults, not git.
7. **Confirm auditability.** Enable connection logging; use `pgaudit` or equivalent for regulated tables when policy requires statement-level audit.

## Risk Impact Analysis

**Credential and data sniffing.** Cleartext PostgreSQL protocols expose passwords and result sets to anyone on the network path.

**Cross-tenant reads.** Missing or bypassable RLS lets one customer's API key read every row in a shared table.

**Denial of service.** Unlimited connections from a runaway pool may exhaust `max_connections` and take down the database for all clients.

**Privilege escalation.** Superuser application roles enable file access via `COPY PROGRAM`, extension install, and role property changes.

**Compliance failure.** Auditors expect encryption in transit, separation of duties between admin and app roles, and evidence of access control on PII tables.

## Vulnerable Examples in Other Formats

### PostgreSQL SQL (roles and RLS)

```sql
-- Application role with excessive privileges
CREATE ROLE app_user LOGIN PASSWORD 'PlainTextInMigration' SUPERUSER CREATEDB;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO PUBLIC;

CREATE TABLE orders (
  id bigserial PRIMARY KEY,
  tenant_id uuid NOT NULL,
  total numeric NOT NULL
);
-- No RLS; any app_user session reads all tenants
```

### pg_hba.conf (weak authentication)

```
# TYPE  DATABASE  USER  ADDRESS        METHOD
host    all       all   10.0.0.0/8     scram-sha-256
host    all       all   0.0.0.0/0      trust
```

Mixed strong and trust rules; trust on wide range allows unauthenticated remote login if reachable.

### Java (application integration)

```java
// application.yml committed to git
// spring.datasource.url=jdbc:postgresql://db.internal:5432/app?sslmode=disable
// spring.datasource.username=app_user
// spring.datasource.password=PlainTextInMigration

@Bean
DataSource dataSource() {
    HikariConfig cfg = new HikariConfig();
    cfg.setJdbcUrl(env.getProperty("spring.datasource.url"));
    cfg.setMaximumPoolSize(200); // no alignment with CONNECTION LIMIT
    return new HikariDataSource(cfg);
}
```

### C# (application integration)

```csharp
// Npgsql connection string without SSL
var connStr = "Host=db.internal;Database=app;Username=app_user;Password=PlainText;SSL Mode=Disable";
await using var conn = new NpgsqlConnection(connStr);
await conn.OpenAsync();
// SET app.tenant_id never called — relies on app WHERE clause only
var cmd = new NpgsqlCommand("SELECT * FROM orders WHERE tenant_id = @t", conn);
```

## Fix: Safer Patterns and Libraries to Use

### PostgreSQL SQL

Separate admin and application roles; enable RLS; set connection limits; require SSL at the server per [PostgreSQL SSL documentation](https://www.postgresql.org/docs/current/ssl-tcp.html) and [row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

```sql
CREATE ROLE app_migrator NOLOGIN;
CREATE ROLE app_user LOGIN PASSWORD NULL CONNECTION LIMIT 50;
GRANT USAGE ON SCHEMA app TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO app_user;

CREATE TABLE app.orders (
  id bigserial PRIMARY KEY,
  tenant_id uuid NOT NULL,
  total numeric NOT NULL
);

ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.orders FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON app.orders
  USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- postgresql.conf: ssl=on; pg_hba.conf uses hostssl + scram-sha-256 only
```

**Important:** Application must `SET app.tenant_id` (or use `SET LOCAL` in a transaction) on each request before queries. RLS is the authoritative gate—not only ORM filters.

### Python

Use `sslmode=verify-full` (or `require` minimum); load credentials from vault; set tenant context per connection.

```python
import psycopg
from pathlib import Path

def connect(cfg: dict):
    return psycopg.connect(
        host=cfg["host"],
        dbname=cfg["dbname"],
        user=cfg["user"],
        password=cfg["password"],
        sslmode="verify-full",
        sslrootcert=Path(cfg["ca_path"]),
    )

def fetch_orders(conn, tenant_id: str):
    with conn.cursor() as cur:
        cur.execute("SET LOCAL app.tenant_id = %s", (tenant_id,))
        cur.execute("SELECT id, total FROM app.orders")
        return cur.fetchall()
```

### Java

Configure HikariCP with SSL properties; run `SET LOCAL` via connection init or transaction callback.

```java
HikariConfig cfg = new HikariConfig();
cfg.setJdbcUrl("jdbc:postgresql://db.internal:5432/app?sslmode=verify-full");
cfg.setUsername(vault.get("pg-user"));
cfg.setPassword(vault.get("pg-password"));
cfg.setMaximumPoolSize(20); // aligned with role CONNECTION LIMIT

@Bean
PlatformTransactionManager txManager(DataSource ds) {
    return new DataSourceTransactionManager(ds);
}

// In @Transactional service method:
jdbcTemplate.execute("SET LOCAL app.tenant_id = '" + tenantId + "'");
```

Prefer parameterized `SET` via `PreparedStatement` rather than string concat for tenant IDs.

### C#

Use Npgsql with `SSL Mode=VerifyFull` and tenant context at transaction start.

```csharp
var dataSourceBuilder = new NpgsqlDataSourceBuilder(
    $"Host=db.internal;Database=app;Username={user};Password={pass};SSL Mode=VerifyFull");
await using var dataSource = dataSourceBuilder.Build();
await using var conn = await dataSource.OpenConnectionAsync();
await using var tx = await conn.BeginTransactionAsync();
await using (var set = new NpgsqlCommand("SET LOCAL app.tenant_id = @t", conn, tx)) {
    set.Parameters.AddWithValue("t", tenantId);
    await set.ExecuteNonQueryAsync();
}
```

## Verify During Review

- Remote connections use **SSL/TLS**; production clients set `sslmode=verify-full` or equivalent.
- **`pg_hba.conf`** has no `trust` or `password` (md5) for network-facing entries; use **`hostssl`** with **SCRAM**.
- Application role is **not SUPERUSER** and does **not** have **BYPASSRLS**.
- Multi-tenant tables have **RLS enabled**, correct **policies**, and **FORCE ROW LEVEL SECURITY** when owners query through the app role.
- **Role separation** exists between migrator, app, and read-only analytics roles.
- **Connection limits** align with pool sizing and `max_connections` headroom.
- Passwords come from **vaults**, not migration files or git-tracked config.
- Application sets **`app.tenant_id`** (or equivalent) each request or transaction before DML.

## Reference

- [PostgreSQL — SSL support](https://www.postgresql.org/docs/current/ssl-tcp.html)
- [PostgreSQL — Row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL — Roles and privileges](https://www.postgresql.org/docs/current/user-manag.html)
- [PostgreSQL — Client authentication (pg_hba.conf)](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html)
- [PostgreSQL — Connection settings](https://www.postgresql.org/docs/current/runtime-config-connection.html)
- [pgAudit extension](https://github.com/pgaudit/pgaudit)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [NIST SP 800-53 — System and Communications Protection (SC)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
