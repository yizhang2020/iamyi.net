---
title: Review Snowflake Security Configuration
keywords:
  - security code review
  - Snowflake
  - network policy
  - RBAC
  - row access policy
  - data sharing
description: How to review Snowflake account configuration—network policies, RBAC grants, row access policies, secrets, MFA, and data sharing—for least privilege and auditability.
---

## 11.1 - Review Snowflake Security Configuration

Snowflake security depends on account-level controls as much as application SQL. Start from who can connect (network policy, MFA), what each role can read or write (RBAC and row access policies), how secrets are stored, and whether data leaves the account through shares. Review Terraform, SQL migration scripts, and Snowflake UI change tickets with the same evidence standard as application code.

## What This Misconfiguration Is

Snowflake misconfiguration happens when network paths, role grants, or sharing rules allow broader access than the data owner intended. A service role with `ACCOUNTADMIN`, a network policy that allows `0.0.0.0/0`, or a share that exposes PII tables are platform-level authorization failures—not bugs in a single query.

The unsafe assumption is that warehouse isolation and object naming replace explicit grants. Snowflake evaluates effective privileges from role hierarchy, future grants, and optional row access policies. Missing any layer may expose rows another team thought were private. This aligns with [CWE-284](https://cwe.mitre.org/data/definitions/284.html) (Improper Access Control) and [CWE-732](https://cwe.mitre.org/data/definitions/732.html) (Incorrect Permission Assignment for Critical Resource).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Network exposure** | `CREATE NETWORK POLICY` with wide IP lists, missing policies on service users, PrivateLink bypass |
| **RBAC sprawl** | `GRANT ROLE ACCOUNTADMIN`, `SECURITYADMIN`, or `SYSADMIN` to humans or apps; `OWNERSHIP` on `PUBLIC` schema |
| **Future grants** | `GRANT SELECT ON FUTURE TABLES IN SCHEMA` to overly broad roles |
| **Row-level gaps** | Sensitive tables without row access policies when multiple tenants share a database |
| **Secrets handling** | Passwords in connection strings in git, unrotated service users, keys in notebook cells |
| **MFA gaps** | Human users without MFA, bypass for "break-glass" accounts without monitoring |
| **Data sharing** | Outbound shares to consumer accounts without column masking or secure views |
| **Audit blind spots** | `ACCESS_HISTORY` not retained, login without client IP logging, no alert on privilege escalation |

## Misconfiguration Examples

Use these as review checklists when reading SQL migrations, Terraform, and account settings—not as instructions to apply in production.

### Example 1: Open network policy

```sql
CREATE NETWORK POLICY open_policy
  ALLOWED_IP_LIST = ('0.0.0.0/0');
ALTER ACCOUNT SET NETWORK_POLICY = open_policy;
```

Any IPv4 address may attempt login—credential stuffing and brute force from the public internet.

### Example 2: Service user with ACCOUNTADMIN

```sql
CREATE USER etl_service PASSWORD = 'S3rv1ceP@ssw0rd';
GRANT ROLE ACCOUNTADMIN TO USER etl_service;
```

Compromise of one JDBC password yields full account control including shares and external stages.

### Example 3: Future grant to broad role

```sql
GRANT SELECT ON FUTURE TABLES IN SCHEMA prod.public TO ROLE analyst_role;
GRANT SELECT ON FUTURE TABLES IN SCHEMA prod.public TO ROLE PUBLIC;
```

Every new table inherits wide read access without per-table review.

### Example 4: Outbound share of base PII table

```sql
CREATE SHARE customer_pii_share;
GRANT SELECT ON TABLE prod.public.customers TO SHARE customer_pii_share;
-- No secure view; SSN and email columns exposed to consumer account
```

### Example 5: Missing row access policy on multi-tenant table

```sql
CREATE TABLE prod.app.events (tenant_id VARCHAR, payload VARIANT);
-- No CREATE ROW ACCESS POLICY; app role SELECT sees all tenants
```

## SDK/IaC Sinks and Dangerous Patterns

Search Terraform, SQL migrations, and application code for these grant and connection patterns.

### Snowflake SQL (GRANT / DDL sinks)

```sql
GRANT ROLE ACCOUNTADMIN TO USER app_svc;
GRANT ALL PRIVILEGES ON DATABASE prod TO ROLE app_role;
GRANT SELECT ON ALL TABLES IN SCHEMA prod.public TO ROLE PUBLIC;
CREATE USER svc PASSWORD = 'literal-in-migration';
ALTER USER svc SET RSA_PUBLIC_KEY = NULL;  -- password-only service user
CREATE SHARE external_share;
GRANT SELECT ON TABLE prod.public.users TO SHARE external_share;
```

Also review: `GRANT OWNERSHIP`, `GRANT ROLE ... TO ROLE` (role hierarchy sprawl), `CREATE INTEGRATION` with broad storage URLs.

### Python (snowflake-connector-python)

```python
snowflake.connector.connect(
    user="app_svc", password="PlainTextInSource", role="ACCOUNTADMIN",
    account="xy12345", warehouse="COMPUTE_WH",
)
cursor.execute(f"SELECT * FROM customers WHERE region = '{region}'")
# Dynamic SQL bypasses row access policy session context
```

Also review: `write_pandas` with elevated role, `snowflake-sqlalchemy` connection strings in git.

### Java (JDBC)

```java
String url = "jdbc:snowflake://xy12345.snowflakecomputing.com/?role=SYSADMIN&password=...";
DriverManager.getConnection(url);
stmt.executeQuery("SELECT * FROM " + userTable);  // identifier injection
```

Also review: Spring `application.yml` snowflake datasource, Flyway/Liquibase SQL with privileged grants.

### Terraform (snowflake provider)

```hcl
resource "snowflake_user" "etl" {
  password = "S3rv1ceP@ssw0rd"  # in state and git
}
resource "snowflake_role_grants" "bad" {
  role_name = "ACCOUNTADMIN"
  users     = [snowflake_user.etl.name]
}
resource "snowflake_share" "pii" {
  accounts = ["CONSUMER.ACCOUNT"]
}
```

Also review: `snowflake_grant`, `snowflake_network_policy` CIDR lists, provider `preview` features without review.

### C# (Snowflake.Data)

```csharp
var connStr = "account=xy12345;user=app_svc;password=PlainText;role=SYSADMIN";
new SnowflakeDbConnection(connStr);
cmd.CommandText = $"SELECT * FROM orders WHERE id = {orderId}";
```

See [Snowflake connector for Python](https://docs.snowflake.com/en/developer-guide/python-connector/python-connector), [Snowflake JDBC](https://docs.snowflake.com/en/developer-guide/jdbc/jdbc), and [Terraform Snowflake provider](https://registry.terraform.io/providers/Snowflake-Labs/snowflake/latest/docs).

## Sample Vulnerable Configuration in Python

Review IaC and CI scripts that apply Snowflake DDL. This policy-as-code check flags common grant anti-patterns before merge.

```python
import re
import sys
from pathlib import Path

PRIVILEGED_ROLES = {"ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN", "ORGADMIN"}
RISKY_GRANTS = re.compile(
    r"GRANT\s+(?:ROLE\s+\w+\s+TO|ALL\s+PRIVILEGES\s+ON)\s+.*",
    re.IGNORECASE,
)

def review_sql_file(path: Path) -> list[str]:
    findings: list[str] = []
    text = path.read_text(encoding="utf-8")
    for line_no, line in enumerate(text.splitlines(), start=1):
        upper = line.upper()
        if "CREATE NETWORK POLICY" in upper and "0.0.0.0/0" in line:
            findings.append(f"{path}:{line_no} network policy allows all IPv4")
        for role in PRIVILEGED_ROLES:
            if f"GRANT ROLE {role}" in upper and "TO USER" in upper:
                findings.append(f"{path}:{line_no} privileged role granted to user")
        if "GRANT SELECT ON FUTURE TABLES" in upper and "PUBLIC" in upper:
            findings.append(f"{path}:{line_no} future grant to PUBLIC role")
        if "CREATE SHARE" in upper and "SECURE VIEW" not in text.upper():
            findings.append(f"{path}:{line_no} share may expose base tables without secure views")
    return findings

if __name__ == "__main__":
    paths = [Path(p) for p in sys.argv[1:]]
    all_findings = [f for p in paths for f in review_sql_file(p)]
    for item in all_findings:
        print(item)
    sys.exit(1 if all_findings else 0)
```

## Step-by-Step Review Walkthrough

1. **Inventory identities.** List human users, service users, and OAuth integrations. Map each to roles; flag any with `ACCOUNTADMIN` or unused dormant accounts.
2. **Read network policies.** Confirm every non-PrivateLink path uses a policy that lists known egress IPs or CIDR blocks. Service accounts should not inherit a human user's permissive policy by default.
3. **Trace RBAC for sensitive objects.** For each PII or financial table, follow `SHOW GRANTS` from table → schema → database → role → user. Check inherited roles and `OWNERSHIP` that allows grant propagation.
4. **Verify row access policies.** When one database serves multiple business units, confirm `CREATE ROW ACCESS POLICY` exists and applies to the table, not only to a reporting view.
5. **Inspect shares and replication.** Read `SHOW SHARES` outbound grants. Consumer accounts, included databases, and whether base tables (not secure views) are shared.
6. **Review secrets and auth.** Service users should use key-pair or OAuth where possible; passwords must rotate and live in a vault. Confirm MFA is enforced for interactive users per [Snowflake MFA guidance](https://docs.snowflake.com/en/user-guide/security-mfa).
7. **Confirm audit coverage.** Ensure `ACCESS_HISTORY`, `LOGIN_HISTORY`, and `QUERY_HISTORY` retention meets compliance needs and that privilege changes trigger alerts.

## Risk Impact Analysis

**Cross-tenant data exposure.** Missing row access policies or excessive `SELECT` grants may let one analyst read another customer's rows in a shared warehouse.

**Account takeover paths.** `ACCOUNTADMIN` on a compromised service user enables share creation, user provisioning, and stage exfiltration to external locations.

**Unauthenticated network reachability.** A permissive network policy exposes the login endpoint to credential stuffing and brute force from the public internet.

**Regulatory and contractual breach.** Outbound shares without masking may move regulated data to a consumer account outside your control boundary.

**Forensic gaps.** Without login and access history, teams cannot reconstruct who exported a table during an incident.

## Vulnerable Examples in Other Formats

### Snowflake SQL (network and RBAC)

```sql
-- Network policy allows any IPv4 address
CREATE NETWORK POLICY open_policy
  ALLOWED_IP_LIST = ('0.0.0.0/0');

CREATE USER etl_service PASSWORD = 'S3rv1ceP@ssw0rd'
  DEFAULT_ROLE = ACCOUNTADMIN;

GRANT ROLE ACCOUNTADMIN TO USER etl_service;

-- Future grant gives every new table to a broad analytics role
GRANT SELECT ON FUTURE TABLES IN SCHEMA prod.public TO ROLE analyst_role;

CREATE SHARE customer_pii_share;
GRANT USAGE ON DATABASE prod TO SHARE customer_pii_share;
GRANT SELECT ON TABLE prod.public.customers TO SHARE customer_pii_share;
-- Base table shared; emails and SSN columns not masked
```

### Java (application integration)

```java
// JDBC URL embeds password; role hardcoded to elevated privilege
String url = "jdbc:snowflake://xy12345.snowflakecomputing.com/"
    + "?db=PROD&schema=PUBLIC&role=ACCOUNTADMIN&user=app_svc&password=PlainTextSecret";

try (Connection conn = DriverManager.getConnection(url);
     Statement stmt = conn.createStatement()) {
    // Dynamic SQL built from request parameter — bypasses intended row policy context
    String region = request.getParameter("region");
    stmt.execute("SELECT * FROM customers WHERE region = '" + region + "'");
}
```

### C# (application integration)

```csharp
// Connection string in appsettings.json with long-lived password
var connStr = Configuration["Snowflake:ConnectionString"];
// "account=xy12345;user=app_svc;password=PlainTextSecret;role=SYSADMIN;db=PROD";

using var conn = new SnowflakeDbConnection(connStr);
await conn.OpenAsync();
var sql = $"SELECT * FROM orders WHERE customer_id = {customerId}"; // no parameterization
using var cmd = new SnowflakeDbCommand(conn) { CommandText = sql };
```

### Terraform (IaC)

```hcl
resource "snowflake_user" "etl" {
  name     = "ETL_SERVICE"
  password = "S3rv1ceP@ssw0rd" # secret in state and git history
}

resource "snowflake_role_grants" "etl_admin" {
  role_name = "ACCOUNTADMIN"
  users     = [snowflake_user.etl.name]
}
```

## Fix: Safer Patterns and Libraries to Use

### Snowflake SQL

Use least-privilege roles, narrow network policies, row access policies for multi-tenant data, and secure views for shares.

```sql
CREATE NETWORK POLICY corp_egress_only
  ALLOWED_IP_LIST = ('203.0.113.0/24', '198.51.100.10');

CREATE ROLE app_read_role;
GRANT USAGE ON WAREHOUSE app_wh TO ROLE app_read_role;
GRANT USAGE ON DATABASE prod TO ROLE app_read_role;
GRANT USAGE ON SCHEMA prod.app TO ROLE app_read_role;
GRANT SELECT ON ALL TABLES IN SCHEMA prod.app TO ROLE app_read_role;

CREATE ROW ACCESS POLICY tenant_isolation AS (tenant_id VARCHAR)
  RETURNS BOOLEAN ->
  CURRENT_ROLE() = 'ACCOUNTADMIN'
  OR tenant_id = CURRENT_SESSION()->>'tenant_id';

ALTER TABLE prod.app.events ADD ROW ACCESS POLICY tenant_isolation ON (tenant_id);

CREATE SECURE VIEW prod.app.customers_shared AS
  SELECT id, region, hashed_email FROM prod.app.customers;

CREATE SHARE partner_share;
GRANT USAGE ON DATABASE prod TO SHARE partner_share;
GRANT SELECT ON VIEW prod.app.customers_shared TO SHARE partner_share;
```

**Important:** `ACCOUNTADMIN` is for break-glass only. Service users should use dedicated roles scoped to one schema or task.

### Python

Load credentials from a vault; use key-pair auth for service accounts; parameterize queries.

```python
import snowflake.connector
from cryptography.hazmat.primitives import serialization

def connect_from_vault(secret: dict):
    private_key = serialization.load_pem_private_key(
        secret["private_key_pem"].encode(), password=None
    )
    return snowflake.connector.connect(
        account=secret["account"],
        user=secret["user"],
        private_key=private_key,
        role="APP_READ_ROLE",
        warehouse="APP_WH",
        database="PROD",
        schema="APP",
    )

def fetch_orders(conn, customer_id: str):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id, total FROM orders WHERE customer_id = %s",
            (customer_id,),
        )
        return cur.fetchall()
```

Pair runtime checks with SQL lint in CI (the sample reviewer above) and tools such as [Snowflake access control documentation](https://docs.snowflake.com/en/user-guide/security-access-control-overview) as the authoritative grant model.

### Java

Use Snowflake JDBC with external credentials and parameterized queries. Never embed passwords in source.

```java
Properties props = vault.loadSnowflakeProps("app/snowflake/prod");
props.setProperty("role", "APP_READ_ROLE");
try (Connection conn = DriverManager.getConnection(props.getProperty("jdbcUrl"), props);
     PreparedStatement ps = conn.prepareStatement(
         "SELECT id, total FROM orders WHERE customer_id = ?")) {
    ps.setString(1, customerId);
    try (ResultSet rs = ps.executeQuery()) { /* ... */ }
}
```

### C#

Use `Snowflake.Data` with Azure Key Vault or AWS Secrets Manager and least-privilege role in configuration—not `SYSADMIN`.

```csharp
var secret = await secretClient.GetSecretAsync("snowflake-app-prod");
var builder = new SnowflakeDbConnectionStringBuilder(secret.Value.Value);
builder["role"] = "APP_READ_ROLE";
await using var conn = new SnowflakeDbConnection(builder.ConnectionString);
await using var cmd = new SnowflakeDbCommand(conn);
cmd.CommandText = "SELECT id, total FROM orders WHERE customer_id = ?";
cmd.Parameters.Add(new SnowflakeDbParameter { Value = customerId });
```

## Verify During Review

- Every human user has **MFA**; service users use **key-pair or OAuth**, not static passwords in git.
- **Network policies** restrict login to known corporate or cloud egress IPs; no `0.0.0.0/0` on production accounts.
- **Roles follow least privilege**; no application user holds `ACCOUNTADMIN`, `SECURITYADMIN`, or `SYSADMIN`.
- Multi-tenant tables have **row access policies** or equivalent isolation, not only naming conventions.
- **Outbound shares** expose secure views with masked columns, not raw PII tables.
- **Future grants** target narrow roles, never `PUBLIC`, unless explicitly justified and documented.
- **Audit logs** (`ACCESS_HISTORY`, `LOGIN_HISTORY`) retention and alerting cover privilege changes and bulk exports.
- Application code uses **parameterized SQL** and vault-backed credentials aligned with the Snowflake role model.

## Reference

- [Snowflake — Network policies](https://docs.snowflake.com/en/user-guide/network-policies)
- [Snowflake — Access control overview](https://docs.snowflake.com/en/user-guide/security-access-control-overview)
- [Snowflake — Row access policies](https://docs.snowflake.com/en/user-guide/security-row-intro)
- [Snowflake — Multi-factor authentication](https://docs.snowflake.com/en/user-guide/security-mfa)
- [Snowflake — Secure data sharing](https://docs.snowflake.com/en/user-guide/data-sharing-intro)
- [Snowflake — Key-pair authentication](https://docs.snowflake.com/en/user-guide/key-pair-auth)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [NIST SP 800-53 — Access Control (AC)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
