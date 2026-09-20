---
title: Review Software Supply Chain
keywords:
  - supply chain
  - dependencies
  - SBOM
  - package integrity
description: Review dependency and build-input trust for application security code review.
---

## 4.10 - Review Software Supply Chain

### Overview

Supply-chain review asks whether build and runtime trust unvetted packages, scripts, or artifacts. Evidence lives in lockfiles, registries, CI, and import graphs—not only in application sinks.

The points below are the ideas this family chapter uses again and again.

1. Supply-chain review asks whether build and runtime trust unvetted packages, scripts, or artifacts.
2. Evidence lives in lockfiles, registries, CI, and import graphs—not only application sinks.
3. Pin, verify, and minimize transitive trust.
4. Treat install scripts and build plugins as code under review.
5. Record source of trust, missing control, impact, and a proving test.

After reading this chapter, we should be able to review dependencies and build inputs for trust decisions that affect application security.

## Shared Review Model

Across every variant below, keep the same evidence habit: name the **source**, the **sink**, the **missing control**, the **impact**, and a **test** that would prove a fix.

## Variants in This Family

### Software supply chain {: #supply-chain }

Modern applications import most code from open source libraries. A vulnerable version of Log4j, a typosquatted package name, or a compromised maintainer account can affect every service that depends on it. Supply chain attacks target build systems, package registries, and transitive dependencies reviewers rarely read directly.

**Where to look**

| Signal | Where to look |
| --- | --- |
| **Feature type** | Dependency manifests, Docker base images, CI install steps, private registry config |
| **Unpinned versions** | `latest`, broad semver ranges, missing lockfiles in production services |
| **Known CVEs** | Dependencies with published advisories in OSV, GitHub Advisory, or scanner output |
| **Transitive risk** | Vulnerabilities one or two levels deep in the dependency graph |
| **Install scripts** | `postinstall` hooks and package scripts executing during dependency install |
| **Typosquatting** | Package names close to but not matching canonical registry entries |
| **Base images** | Outdated Docker `FROM` tags without digest pinning or regular rebuilds |

**Appendix detail:** [Software supply chain code reference](appendix/code-level-reference/4-10-review-software-supply-chain.md#supply-chain).

## Worked Example (Software supply chain)

We walk **Software supply chain** in depth. Apply the same tracing steps to the other variants, adjusting sources and sinks from the tables above.

### Sample vulnerable code (Python)

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

### Step-by-step review walkthrough

1. **Locate dependency manifests.** Read `pom.xml`, `build.gradle`, `package.json`, `go.mod`, `requirements.txt`, `Gemfile`, and Docker base images.
2. **Check lockfiles.** Confirm lockfiles are committed and CI installs from them; floating ranges increase surprise upgrades.
3. **Review transitive dependencies.** Many CVEs live one or two levels deep; use scanner output, not only direct deps.
4. **Inspect registry configuration.** Review `.npmrc`, `.m2`, and PyPI index settings for mirror trust and integrity checks.
5. **Follow build pipelines.** Verify provenance, signed commits, and that release artifacts match tagged source.
6. **Confirm SBOM generation.** Release builds should produce CycloneDX or SPDX documents stored with deployable artifacts.
7. **Ask about incident response.** Patch SLA, emergency change process, and communication paths for zero-day advisories.

## Risk Impact (Family)

**Widespread compromise from one dependency.** A single vulnerable library (for example Log4Shell) may affect every service that transitively includes it.

**Build pipeline takeover.** Compromised install scripts or typosquatted packages execute attacker code during CI or developer installs.

**Slow incident response.** Without an SBOM, teams spend hours manually inventorying production versions during active advisories.

**Transitive blind spots.** Direct dependencies may be current while nested libraries remain on vulnerable versions.

**Container drift.** Unpinned base images pull new OS packages on rebuild, introducing vulnerabilities without application code changes.

## Fix Principles

Primary safer patterns for the worked example follow. For other languages and variant-specific fixes, use the [family appendix](appendix/code-level-reference/4-10-review-software-supply-chain.md).

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

## Verify During Review

Use the checklist below as a family-level pass over the variants above. Each item should map to evidence in the change under review.

- Dependency versions are pinned or locked; production builds do not pull floating ranges.
- Automated CVE scanning runs on pull requests and on a schedule for default branches.
- An SBOM is produced for each release (CycloneDX or SPDX) and stored with deployment artifacts.
- Transitive dependencies with critical CVEs have documented upgrade or mitigation plans.
- Build pipelines use trusted registries, verify checksums, and restrict arbitrary install-time script execution where possible.
- Base container images and OS packages are updated on a defined cadence and scanned like application libraries.
- The team can answer "what version of library X is in production?" within minutes using the SBOM or dependency graph.

## Code Reference (Appendix)

Payloads, language-specific sinks, multi-language examples, and full fix catalogs for every variant live in **[4.10 code reference — Review Software Supply Chain](appendix/code-level-reference/4-10-review-software-supply-chain.md)**.

## Reference

- Appendix — [4.10 code reference](appendix/code-level-reference/4-10-review-software-supply-chain.md)

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
