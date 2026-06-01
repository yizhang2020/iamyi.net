---
title: Review AWS IAM and Secrets Configuration
keywords:
  - security code review
  - AWS IAM
  - Secrets Manager
  - least privilege
  - long-lived credentials
description: How to review AWS IAM policies, Secrets Manager usage, and application credential patterns for least privilege and no long-lived keys in code.
---

## 11.3 - Review AWS IAM and Secrets Configuration

AWS access control lives in IAM policy JSON, trust relationships, and how applications retrieve secrets at runtime. Review Terraform, CloudFormation, CDK output, and application bootstrap code together. A permissive `s3:*` on `*` in IaC plus hardcoded access keys in a service repo is a full-chain finding—not two low-severity notes.

## What This Misconfiguration Is

IAM misconfiguration grants principals more actions or resources than a workload needs. Common failures include administrator policies on task roles, `Resource: "*"` on destructive actions, trust policies that allow any account to assume a role, and long-lived access keys embedded in source instead of [AWS Secrets Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html) or IAM Roles for Service Accounts.

The unsafe assumption is that network perimeter or private subnets compensate for broad IAM. An SSRF flaw, dependency compromise, or stolen key from a log file still invokes APIs the role permits. This aligns with [CWE-732](https://cwe.mitre.org/data/definitions/732.html) (Incorrect Permission Assignment for Critical Resource) and [CWE-798](https://cwe.mitre.org/data/definitions/798.html) (Use of Hard-coded Credentials).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Overbroad actions** | `Action: "*"` or `s3:*`, `dynamodb:*`, `iam:*` on production roles |
| **Wildcard resources** | `Resource: "*"` paired with write or PassRole permissions |
| **Trust policy sprawl** | `Principal: "*"` or foreign account IDs without external ID condition |
| **Long-lived keys** | `AKIA*` strings in git, Docker layers, mobile apps, CI logs |
| **Secrets in env defaults** | `os.environ.get("AWS_SECRET", "wJalr...")` fallback literals |
| **Missing rotation** | Secrets Manager secrets without rotation Lambda or manual cadence |
| **Cross-account** | Roles assumable from vendor accounts without `aws:SourceArn` condition |
| **Human identities on workloads** | EC2 or ECS tasks using IAM user keys instead of instance/task roles |

## Misconfiguration Examples

Use these when reviewing IAM policy JSON, trust policies, and application bootstrap—not as policies to deploy.

### Example 1: Star action on star resource

```json
{
  "Effect": "Allow",
  "Action": ["s3:*", "secretsmanager:GetSecretValue", "iam:PassRole"],
  "Resource": "*"
}
```

One compromised workload may read all buckets, fetch all secrets, and pass admin roles to new resources.

### Example 2: Open trust policy

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "*" },
  "Action": "sts:AssumeRole"
}
```

Any principal that can satisfy optional conditions—or none—may assume the role.

### Example 3: Long-lived access key in source

```python
boto3.client("s3",
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
)
```

Keys in git history remain valid until rotated; scanners harvest them continuously.

### Example 4: Secrets Manager without rotation

Secret `prod/db/password` has rotation disabled; same password for years. `GetSecretValue` granted to `*` resource from web tier role.

### Example 5: PassRole to admin instance profile

```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::123456789012:role/AdminInstanceRole"
}
```

Attacker with `iam:PassRole` launches EC2 with admin profile—common privilege escalation chain.

## SDK/IaC Sinks and Dangerous Patterns

### IAM JSON (policy and trust sinks)

```json
"Action": "*", "Resource": "*"
"Action": "s3:*", "Resource": "arn:aws:s3:::*"
"Action": "sts:AssumeRole", "Principal": { "AWS": "*" }
"Action": "iam:CreateUser", "Action": "iam:AttachUserPolicy"
```

Also review: `kms:Decrypt` on `*`, `lambda:InvokeFunction` on `*`, overly broad `Condition` omissions.

### Python (boto3 / botocore)

```python
boto3.client("s3", aws_access_key_id=KEY, aws_secret_access_key=SECRET)
os.environ.get("AWS_SECRET_ACCESS_KEY", "fallback-literal")
boto3.client("secretsmanager").get_secret_value(SecretId="prod/db")
s3.list_objects_v2(Bucket="prod-customer-data")  # role not prefix-scoped
session = boto3.Session(profile_name="admin")  # on production worker
```

Also review: `aioboto3`, `moto` test creds shipped to prod, `urllib3` logging of auth headers.

### Java (AWS SDK v2)

```java
StaticCredentialsProvider.create(
    AwsBasicCredentials.create("AKIA...", "secret..."));
S3Client.builder().credentialsProvider(staticProvider).build();
secretsManager.getSecretValue(r -> r.secretId("prod/db"));
```

Also review: `DefaultCredentialsProvider` fallback to env vars with literals, Spring Cloud AWS `spring.cloud.aws.credentials`.

### Terraform / CloudFormation

```hcl
resource "aws_iam_user" "app" {
  name = "app-user"
}
resource "aws_iam_access_key" "app" { user = aws_iam_user.app.name }

resource "aws_iam_role_policy" "wide" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
```

Also review: CDK `PolicyStatement` with `resources: ['*']`, ECS task role vs execution role confusion.

### C# (AWSSDK)

```csharp
new AmazonS3Client(new BasicAWSCredentials(
    Configuration["AWS:AccessKey"], Configuration["AWS:SecretKey"]));
await sm.GetSecretValueAsync(new GetSecretValueRequest { SecretId = "prod/db" });
_logger.LogError("Secret: {S}", resp.SecretString);
```

See [boto3 documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html), [AWS IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html), and [AWS SDK for Java 2.x](https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/home.html).

## Sample Vulnerable Configuration in Python

Automate IAM JSON review in CI with boto3 or static analysis before `terraform apply`.

```python
import json
import sys
from pathlib import Path

RISKY_ACTIONS = {"*", "iam:*", "s3:*", "secretsmanager:*"}
RISKY_COMBOS = [
    ({"s3:GetObject", "s3:PutObject", "s3:DeleteObject"}, "*"),
    ({"secretsmanager:GetSecretValue"}, "*"),
]

def review_policy_doc(doc: dict, path: str) -> list[str]:
    findings: list[str] = []
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        for action in actions:
            if action in RISKY_ACTIONS and "*" in resources:
                findings.append(f"{path}: Allow {action} on Resource *")
        action_set = set(actions)
        for combo_actions, res in RISKY_COMBOS:
            if combo_actions.issubset(action_set) and "*" in resources:
                findings.append(f"{path}: broad data plane access {combo_actions} on *")
        if "PassRole" in action_set and "*" in resources:
            findings.append(f"{path}: iam:PassRole allowed on *")
    return findings

def review_app_config(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    findings: list[str] = []
    if "AKIA" in text:
        findings.append(f"{path}: possible access key id in source")
    if "aws_secret_access_key" in text.lower() and "=" in text:
        findings.append(f"{path}: possible secret access key assignment")
    return findings

if __name__ == "__main__":
    for arg in sys.argv[1:]:
        p = Path(arg)
        if p.suffix == ".json" and "policy" in p.name.lower():
            doc = json.loads(p.read_text())
            for f in review_policy_doc(doc, str(p)):
                print(f)
        elif p.suffix == ".py":
            for f in review_app_config(p):
                print(f)
```

## Step-by-Step Review Walkthrough

1. **Map each workload to one role.** EC2 instance profile, ECS task role, Lambda execution role, or EKS IRSA—one principal per service, not shared admin users.
2. **Read policy JSON statement by statement.** Split allow and deny; flag wildcards on actions and resources; confirm `Condition` keys scope by bucket prefix, secret ARN, or source VPC.
3. **Inspect trust policies.** Who can `sts:AssumeRole`? Require `aws:SourceAccount`, `aws:SourceArn`, or external ID for third-party assumers.
4. **Search code and IaC for access keys.** Grep for `AKIA`, `aws_access_key_id`, and Secrets Manager calls that fall back to literals.
5. **Review Secrets Manager configuration.** Encryption with CMK, rotation enabled, least-privilege `GetSecretValue` on specific ARNs, no secrets in CloudFormation parameters as plain text.
6. **Trace application bootstrap.** Python boto3, Java AWS SDK, and C# AWSSDK should use default credential chain or web identity—not static keys in config files.
7. **Confirm logging.** CloudTrail data events for S3 and Secrets Manager where sensitivity warrants forensic reconstruction.

## Risk Impact Analysis

**Infrastructure takeover.** `iam:PassRole` or `iam:CreateUser` on wide resources lets an attacker persist access beyond the compromised workload.

**Data exfiltration.** `s3:GetObject` on `*` from a web tier role turns SSRF or RCE into bucket-wide download capability.

**Secret replay.** Long-lived keys in git history remain valid until rotated; scanners and insiders both harvest them.

**Cross-account pivot.** Trust policies without tight conditions let a vendor or sandbox account assume production roles.

**Audit and compliance gaps.** Missing rotation and CloudTrail gaps fail SOC 2 and PCI expectations for credential lifecycle control.

## Vulnerable Examples in Other Formats

### IAM policy JSON

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:*", "secretsmanager:GetSecretValue"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "*"
    }
  ]
}
```

### Trust policy (overly permissive)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "*" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### Java (application integration)

```java
// Static credentials in source — bypasses instance role
BasicAWSCredentials creds = new BasicAWSCredentials(
    "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
AmazonS3 s3 = AmazonS3ClientBuilder.standard()
    .withCredentials(new AWSStaticCredentialsProvider(creds))
    .withRegion(Regions.US_EAST_1)
    .build();
s3.listObjectsV2("prod-customer-data"); // role not scoped to prefix
```

### C# (application integration)

```csharp
// appsettings.Production.json contains access key pair
var creds = new BasicAWSCredentials(
    Configuration["AWS:AccessKey"],
    Configuration["AWS:SecretKey"]);
var client = new AmazonSecretsManagerClient(creds, RegionEndpoint.USEast1);
var secret = await client.GetSecretValueAsync(new GetSecretValueRequest {
    SecretId = "prod/db/password"
});
// Secret logged on error path
_logger.LogError("Failed with secret {Secret}", secret.SecretString);
```

## Fix: Safer Patterns and Libraries to Use

### IAM policy JSON

Scope actions and resources; add conditions; follow [IAM best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadSingleSecret",
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:app/prod/db-*"
    },
    {
      "Sid": "WriteAppPrefixOnly",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::prod-app-data/uploads/${aws:userid}/*"
    }
  ]
}
```

**Important:** Prefer permission boundaries and service control policies at the organization level to cap what project roles can grant.

### Python

Use the default credential chain on AWS compute; fetch secrets at startup from Secrets Manager without literals.

```python
import boto3
from botocore.exceptions import ClientError

def load_db_password(secret_arn: str) -> str:
    client = boto3.client("secretsmanager")  # task role credentials
    try:
        resp = client.get_secret_value(SecretId=secret_arn)
    except ClientError as exc:
        raise RuntimeError("unable to load secret") from exc
    return resp["SecretString"]

def upload_user_file(bucket: str, user_id: str, key: str, body: bytes) -> None:
    s3 = boto3.client("s3")
    s3.put_object(Bucket=bucket, Key=f"uploads/{user_id}/{key}", Body=body)
```

Pair runtime code with IAM Access Analyzer findings and CI policy checks (sample above).

### Java

Use `DefaultCredentialsProvider` on EC2, ECS, or Lambda; narrow SDK clients to required API calls.

```java
AmazonS3 s3 = AmazonS3Client.builder()
    .credentialsProvider(DefaultCredentialsProvider.create())
    .region(Region.US_EAST_1)
    .build();

SecretsManagerClient sm = SecretsManagerClient.builder()
    .credentialsProvider(DefaultCredentialsProvider.create())
    .build();
GetSecretValueResponse resp = sm.getSecretValue(
    GetSecretValueRequest.builder().secretId("app/prod/db").build());
```

### C#

Use `FallbackCredentialsFactory` or `InstanceProfileAWSCredentials`; store secret ARNs in configuration, not secret values.

```csharp
var sm = new AmazonSecretsManagerClient(RegionEndpoint.USEast1);
var resp = await sm.GetSecretValueAsync(new GetSecretValueRequest {
    SecretId = Configuration["Db:SecretArn"]
});
var s3 = new AmazonS3Client(RegionEndpoint.USEast1);
await s3.PutObjectAsync(new PutObjectRequest {
    BucketName = "prod-app-data",
    Key = $"uploads/{userId}/{fileName}",
    InputStream = stream
});
```

Enable [Secrets Manager rotation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html) for database credentials on a defined schedule.

## Verify During Review

- Workload roles grant **least privilege**; no `Action: "*"` or `Resource: "*"` on production data-plane roles without documented exception.
- **Trust policies** restrict `sts:AssumeRole` by account, ARN, or external ID.
- Applications use **IAM roles** (instance profile, task role, IRSA)—not long-lived **IAM user access keys** in source or images.
- Secrets live in **Secrets Manager** (or SSM Parameter Store SecureString) with **rotation** where feasible.
- Code uses the **default credential chain**; grep finds no `AKIA` literals in repos or container layers.
- **CloudTrail** covers Secrets Manager and sensitive S3 buckets when forensic requirements apply.
- Error paths and logs **never print secret values**.

## Reference

- [AWS IAM — Best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [AWS Secrets Manager — Best practices](https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html)
- [AWS Secrets Manager — Rotation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html)
- [AWS IAM — Policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [NIST SP 800-53 — Identification and Authentication (IA)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
