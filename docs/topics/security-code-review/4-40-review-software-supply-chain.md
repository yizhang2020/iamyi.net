---
title: Review Software Supply Chain
keywords:
  - security code review
  - software supply chain
  - SBOM
  - open source dependencies
  - dependency vulnerability
description: How to review software supply chain risk covering OSS dependencies, SBOMs, and dependency hygiene during security review.
---

## 4.40 - Review Software Supply Chain

Software supply chain risk appears when applications depend on vulnerable, tampered, or unmaintained open source packages. Review dependency manifests, lockfiles, and build pipelines. Confirm the team can inventory components with an SBOM (Software Bill of Materials), monitor CVEs, and respond when a dependency is compromised.

## What This Vulnerability Is

Modern applications import most code from open source libraries. A vulnerable version of Log4j, a typosquatted package name, or a compromised maintainer account can affect every service that depends on it. Supply chain attacks target build systems, package registries, and transitive dependencies reviewers rarely read directly.

The unsafe assumption is that `npm install`, `go get`, or Maven Central always deliver trustworthy artifacts. Security review should verify dependency sources, pin versions, scan for known CVEs, and maintain an SBOM so incident response starts with facts instead of manual inventory. The [OpenSSF](https://openssf.org/) ecosystem promotes SBOM standards such as [CycloneDX](https://cyclonedx.org/) and [SPDX](https://spdx.dev/) for documenting what ships in each release.

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **Feature type** | Dependency manifests, Docker base images, CI install steps, private registry config |
| **Unpinned versions** | `latest`, broad semver ranges, missing lockfiles in production services |
| **Known CVEs** | Dependencies with published advisories in OSV, GitHub Advisory, or scanner output |
| **Transitive risk** | Vulnerabilities one or two levels deep in the dependency graph |
| **Install scripts** | `postinstall` hooks and package scripts executing during dependency install |
| **Typosquatting** | Package names close to but not matching canonical registry entries |
| **Base images** | Outdated Docker `FROM` tags without digest pinning or regular rebuilds |

## Sample Vulnerable Code in Python

```text
# requirements.txt — no hashes, unpinned versions, vulnerable transitive deps
requests
pyyaml==5.1          # CVE-affected version left in place
django>=3.0            # floating lower bound pulls latest minor on each CI run
```

```python
# settings.py — installs from arbitrary index without integrity verification
# pip.conf in repo points to untrusted mirror with no hash checking
import subprocess

def bootstrap_deps():
    # Runs install scripts from every package in requirements.txt
    subprocess.run(["pip", "install", "-r", "requirements.txt"], check=True)
```

```dockerfile
# Dockerfile — outdated base, no digest pin
FROM python:3.8-slim
COPY requirements.txt .
RUN pip install -r requirements.txt
```

## Step-by-Step Review Walkthrough

1. **Locate dependency manifests.** Read `pom.xml`, `build.gradle`, `package.json`, `go.mod`, `requirements.txt`, `Gemfile`, and Docker base images.
2. **Check lockfiles.** Confirm lockfiles are committed and CI installs from them; floating ranges increase surprise upgrades.
3. **Review transitive dependencies.** Many CVEs live one or two levels deep; use scanner output, not only direct deps.
4. **Inspect registry configuration.** Review `.npmrc`, `.m2`, and PyPI index settings for mirror trust and integrity checks.
5. **Follow build pipelines.** Verify provenance, signed commits, and that release artifacts match tagged source.
6. **Confirm SBOM generation.** Release builds should produce CycloneDX or SPDX documents stored with deployable artifacts.
7. **Ask about incident response.** Patch SLA, emergency change process, and communication paths for zero-day advisories.

## Risk Impact Analysis

**Widespread compromise from one dependency.** A single vulnerable library (for example Log4Shell) may affect every service that transitively includes it.

**Build pipeline takeover.** Compromised install scripts or typosquatted packages execute attacker code during CI or developer installs.

**Slow incident response.** Without an SBOM, teams spend hours manually inventorying production versions during active advisories.

**Transitive blind spots.** Direct dependencies may be current while nested libraries remain on vulnerable versions.

**Container drift.** Unpinned base images pull new OS packages on rebuild, introducing vulnerabilities without application code changes.

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

## Verify During Review

- Dependency versions are pinned or locked; production builds do not pull floating ranges.
- Automated CVE scanning runs on pull requests and on a schedule for default branches.
- An SBOM is produced for each release (CycloneDX or SPDX) and stored with deployment artifacts.
- Transitive dependencies with critical CVEs have documented upgrade or mitigation plans.
- Build pipelines use trusted registries, verify checksums, and restrict arbitrary install-time script execution where possible.
- Base container images and OS packages are updated on a defined cadence and scanned like application libraries.
- The team can answer "what version of library X is in production?" within minutes using the SBOM or dependency graph.

## Reference

- [CWE-1395: Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html)
- [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)
- [OpenSSF Best Practices for Open Source Developers](https://best.openssf.org/)
- [CycloneDX specification](https://cyclonedx.org/specification/overview/)
- [SPDX specification](https://spdx.github.io/spdx-spec/v2.3/)
- [OSV vulnerability database](https://osv.dev/)
- [pip-tools documentation](https://pip-tools.readthedocs.io/en/latest/)
- [pip-audit](https://pypi.org/project/pip-audit/)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [Go govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
- [GitHub Dependabot documentation](https://docs.github.com/en/code-security/dependabot)
