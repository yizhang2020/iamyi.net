---
title: Review Databricks Clean Room Configuration
keywords:
  - security code review
  - Databricks
  - clean room
  - data collaboration
  - output restrictions
  - participant isolation
description: How to review Databricks clean room rules, output restrictions, audit settings, and participant isolation so collaborative analytics does not leak raw data.
---

## 11.2 - Review Databricks Clean Room Configuration

Databricks clean rooms let multiple parties run joint analytics without sharing raw datasets directly. Security review must read clean room rules, output restrictions, and participant permissions—not only notebook code. Start from who can join the room, what SQL or Python each party can run, what leaves the room as output, and whether audit logs prove every run.

## What This Misconfiguration Is

Clean room misconfiguration happens when collaboration rules allow a participant to read another party's raw table, export unrestricted aggregates, or run arbitrary code that bypasses output filters. The platform enforces isolation through clean room rules, allowed functions, and output inspection; weak rules turn the room into a shared workspace with full data access.

The unsafe assumption is that joining organizations trust each other enough to skip output caps and column restrictions. A malicious or compromised participant may exfiltrate row-level detail through carefully chosen joins or statistical queries unless output restrictions block it. This maps to [CWE-284](https://cwe.mitre.org/data/definitions/284.html) (Improper Access Control) and [CWE-359](https://cwe.mitre.org/data/definitions/359.html) (Exposure of Private Personal Information to an Unauthorized Actor).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Rule scope** | Clean room rules that `SELECT *` from contributor tables without column allowlists |
| **Output restrictions** | Missing minimum aggregation thresholds, no row caps, arbitrary file download enabled |
| **Participant roles** | Admin-equivalent rights for all collaborators; ability to edit rules without dual control |
| **Code execution** | Unrestricted Python/Scala in rooms meant for SQL-only collaboration |
| **Audit gaps** | Run history not exported to SIEM; no alert on failed output validation |
| **Cross-room leakage** | Shared service principals across clean rooms with different data classifications |
| **External locations** | Unapproved cloud storage mounts writable from inside the room |
| **Notebook exports** | Results copied to personal workspace or DBFS paths outside the room boundary |

## Sample Vulnerable Configuration in Python

Use SDK or REST review scripts in CI to catch clean room definitions that omit output restrictions before deployment.

```python
import json
import sys
from pathlib import Path

def review_clean_room_spec(spec: dict) -> list[str]:
    findings: list[str] = []
    name = spec.get("name", "<unnamed>")

    rules = spec.get("clean_room_rules", [])
    if not rules:
        findings.append(f"{name}: no clean_room_rules defined")

    for rule in rules:
        sql = (rule.get("query_template") or rule.get("sql") or "").upper()
        if "SELECT *" in sql:
            findings.append(f"{name}: rule '{rule.get('name')}' selects all columns")
        if "JOIN" in sql and "OUTPUT" not in spec:
            findings.append(f"{name}: join rule without output restriction block")

    output = spec.get("output_restrictions") or spec.get("output_policy")
    if not output:
        findings.append(f"{name}: missing output_restrictions")
    else:
        min_group = output.get("minimum_group_size") or output.get("min_rows")
        if min_group is None or min_group < 10:
            findings.append(f"{name}: aggregation threshold too low or absent")

    participants = spec.get("participants", [])
    for p in participants:
        if p.get("role") in ("admin", "owner") and len(participants) > 2:
            findings.append(f"{name}: participant {p.get('name')} has admin in multi-party room")

    return findings

if __name__ == "__main__":
    for path in sys.argv[1:]:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        rooms = data if isinstance(data, list) else [data]
        for room in rooms:
            for finding in review_clean_room_spec(room):
                print(f"{path}: {finding}")
    sys.exit(0)
```

## Step-by-Step Review Walkthrough

1. **Identify room purpose and data classes.** Document each contributor dataset, regulatory label, and whether SQL-only or notebook execution is required.
2. **Read clean room rules line by line.** Each rule should reference approved views or column projections, not base tables with sensitive fields.
3. **Verify output restrictions.** Confirm minimum group size, maximum row count, banned column types in output, and whether differential privacy or noise is applied where required.
4. **Check participant isolation.** Each party should see only their assets plus rule-mediated results. Flag shared personal access tokens or service principals across rooms.
5. **Review audit and retention.** [Databricks audit logs](https://docs.databricks.com/en/administration-guide/account-settings/audit-logs.html) should capture clean room runs, rule changes, and membership updates with export to your SIEM.
6. **Inspect application integration.** APIs that trigger clean room jobs must authenticate per participant and must not merge results across tenants in application memory.
7. **Test negative cases.** Attempt a query that returns fewer rows than the threshold or a join that reconstructs identifiers; output validation should block or redact.

## Risk Impact Analysis

**Raw data exfiltration.** Without column allowlists and output caps, one participant may download another party's underlying records.

**Re-identification from aggregates.** Small group sizes in output allow linkage attacks that recover individual rows from "anonymous" statistics.

**Rule tampering.** If any collaborator can edit clean room rules without approval, they can widen access mid-collaboration.

**Compliance failure.** Healthcare, financial, and advertising use cases often require provable isolation; weak rooms fail third-party audits.

**Cross-tenant application bugs.** Backend services that cache clean room results for one customer and serve them to another amplify configuration mistakes into application-level breaches.

## Vulnerable Examples in Other Formats

### Databricks clean room rule (JSON)

```json
{
  "name": "partner_overlap_analysis",
  "clean_room_rules": [
    {
      "name": "full_customer_join",
      "query_template": "SELECT a.*, b.* FROM {{provider.customers}} a JOIN {{consumer.purchases}} b ON a.id = b.customer_id"
    }
  ],
  "participants": [
    { "name": "retailer", "role": "admin" },
    { "name": "brand", "role": "admin" }
  ]
}
```

No `output_restrictions` block; both parties are admins; query selects all columns from both sides.

### SQL inside an under-restricted room

```sql
-- Permitted by a loose rule; exports identifiable rows
SELECT user_id, email, SUM(revenue) AS total
FROM shared_catalog.clean_room.events
GROUP BY user_id, email
HAVING COUNT(*) >= 1;
```

### Java (application integration)

```java
// Single shared PAT for all clean room jobs — no per-participant scoping
String token = System.getenv("DATABRICKS_ADMIN_PAT");
WorkspaceClient client = WorkspaceClient.builder()
    .host("https://adb-123.azuredatabricks.net")
    .token(token)
    .build();

// Results from brand A job returned to brand B API caller — missing tenant check
CleanRoomRun run = client.cleanRooms().runs().submit(roomId, jobSpec);
return run.output().download(); // no output validation in app layer
```

### C# (application integration)

```csharp
// Hardcoded workspace host and long-lived token in configuration
var client = new DatabricksClient(
    "https://adb-123.azuredatabricks.net",
    Configuration["Databricks:AdminToken"]);

var result = await client.Sql.StatementExecution.ExecuteAsync(
    warehouseId, "SELECT * FROM clean_room.shared_events");

// Writes full result set to shared blob — outside room audit boundary
await blobClient.UploadAsync(resultBytes);
```

## Fix: Safer Patterns and Libraries to Use

### Databricks clean room configuration

Define narrow rules, enforce output restrictions, and separate admin from analyst roles per [Databricks clean room rules](https://docs.databricks.com/en/clean-rooms/clean-room-rules.html).

```json
{
  "name": "partner_overlap_analysis",
  "clean_room_rules": [
    {
      "name": "overlap_counts_only",
      "query_template": "SELECT region, COUNT(DISTINCT hashed_user_id) AS overlap_count FROM {{provider.hashed_events}} a INNER JOIN {{consumer.hashed_purchases}} b ON a.hashed_user_id = b.hashed_user_id GROUP BY region"
    }
  ],
  "output_restrictions": {
    "minimum_group_size": 100,
    "maximum_rows": 500,
    "allowed_column_types": ["string", "long"],
    "block_download": true
  },
  "participants": [
    { "name": "retailer", "role": "contributor" },
    { "name": "brand", "role": "contributor" },
    { "name": "platform_ops", "role": "admin" }
  ]
}
```

**Important:** Hash or tokenize identifiers before they enter the room. Output restrictions complement—but do not replace—column minimization in rules.

### Python

Use the Databricks SDK with participant-scoped credentials; validate output row counts in the application before returning data.

```python
from databricks.sdk import WorkspaceClient
from databricks.sdk.service.cleanrooms import CleanRoomRun

def run_collaboration(participant_secret: dict, room_id: str, rule_name: str) -> dict:
    client = WorkspaceClient(
        host=participant_secret["host"],
        client_id=participant_secret["client_id"],
        client_secret=participant_secret["client_secret"],
    )
    run: CleanRoomRun = client.clean_rooms.run_now(room_id=room_id, rule_name=rule_name)
    rows = run.result().as_dict()["rows"]
    if len(rows) > 500:
        raise ValueError("output exceeds maximum row cap")
    for row in rows:
        if row.get("overlap_count", 0) < 100:
            raise ValueError("output violates minimum group size")
    return rows
```

### Java

Use OAuth service principals per participant; enforce tenant routing in the API layer.

```java
WorkspaceClient client = WorkspaceClient.builder()
    .host(cfg.host())
    .clientId(cfg.clientId())
    .clientSecret(cfg.clientSecret())
    .build();

CleanRoomRun run = client.cleanRooms().runs().submit(roomId, ruleName);
List<Row> rows = run.output().rows();
outputValidator.assertMeetsCleanRoomPolicy(rows); // min group size, max rows
return tenantScopedResponse(currentTenant, rows);
```

### C#

Store tokens in a vault; never reuse an admin PAT for participant-facing APIs.

```csharp
var credential = await vault.GetDatabricksOAuthAsync(tenantId);
var client = new WorkspaceClient(cfg.Host, credential);
var run = await client.CleanRooms.RunNowAsync(roomId, ruleName);
await _outputValidator.EnsureCompliantAsync(run.Rows, minGroupSize: 100, maxRows: 500);
return Results.Ok(run.Rows);
```

## Verify During Review

- Clean room **rules use column projections or pre-approved views**, not `SELECT *` on contributor base tables.
- **Output restrictions** define minimum group size, maximum rows, and blocked download paths.
- **Participant roles** follow least privilege; only platform ops holds admin where dual control exists.
- **Audit logs** capture runs, rule edits, and membership changes with SIEM export.
- Identifiers are **hashed or tokenized** before collaboration; reversible joins across parties are impossible by design.
- Application services use **per-participant credentials** and validate output before cross-tenant API responses.
- **Negative tests** confirm sub-threshold aggregates and wide joins are rejected by the room or app validator.

## Reference

- [Databricks — Clean rooms overview](https://docs.databricks.com/en/clean-rooms/index.html)
- [Databricks — Clean room rules](https://docs.databricks.com/en/clean-rooms/clean-room-rules.html)
- [Databricks — Audit logs](https://docs.databricks.com/en/administration-guide/account-settings/audit-logs.html)
- [Databricks SDK for Python](https://databricks-sdk-py.readthedocs.io/en/latest/)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-359: Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)
- [NIST SP 800-122 — Guide to Protecting the Confidentiality of PII](https://csrc.nist.gov/publications/detail/sp/800-122/final)
