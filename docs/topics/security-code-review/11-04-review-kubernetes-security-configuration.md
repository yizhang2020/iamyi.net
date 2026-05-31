---
title: Review Kubernetes Security Configuration
keywords:
  - security code review
  - Kubernetes
  - RBAC
  - NetworkPolicy
  - Pod Security
  - secrets
description: How to review Kubernetes RBAC, NetworkPolicy, Pod Security standards, and secret mounting patterns so clusters enforce least privilege at runtime.
---

## 11.4 - Review Kubernetes Security Configuration

Kubernetes security is expressed in YAML manifests, Helm values, and operator CRDs—not only in container images. Review who can call the API (RBAC), which pods may talk to each other (NetworkPolicy), which capabilities pods may use (Pod Security Admission), and how sensitive values reach workloads. Production services should mount secrets as volumes, not plain environment variables, when the threat model includes node-level access or process listing.

## What This Misconfiguration Is

Cluster misconfiguration allows pods or users to exceed the intended trust boundary. A `ClusterRoleBinding` to `cluster-admin` for a default service account, missing NetworkPolicy in a multi-tenant namespace, or secrets injected through env vars visible in `/proc` are platform flaws that application code cannot fix alone.

The unsafe assumption is that container isolation replaces network and API authorization. Without NetworkPolicy, any compromised pod may reach the Kubernetes API, metadata services, or peer databases on the flat pod network. This maps to [CWE-284](https://cwe.mitre.org/data/definitions/284.html) (Improper Access Control) and [CWE-526](https://cwe.mitre.org/data/definitions/526.html) (Exposure of Sensitive Information Through Environmental Variables).

## Vulnerability Characteristics (Where to Identify Them)

| Signal | Where to look |
| --- | --- |
| **RBAC escalation** | `cluster-admin` bindings, `*` verbs on secrets or pods, bind to `system:anonymous` |
| **Default service accounts** | Workloads using namespace default SA with automounted token |
| **Network flatness** | No NetworkPolicy in namespace hosting sensitive workloads |
| **Pod privileges** | `privileged: true`, `hostPID`, `hostNetwork`, `allowPrivilegeEscalation` |
| **Secrets in env** | `env.valueFrom.secretKeyRef` for DB passwords in Production manifests |
| **Image trust** | `:latest` tags, missing digest pin, no admission image signature check |
| **PSA gaps** | Namespace without `pod-security.kubernetes.io/enforce=restricted` |
| **Host path mounts** | Docker socket or `/etc/kubernetes` mounted into application pods |

## Sample Vulnerable Configuration in Python

Policy-as-code checks (OPA Rego, Python validators in CI) catch risky manifests before deploy.

```python
import sys
import yaml
from pathlib import Path

def review_manifest(doc: dict, path: str) -> list[str]:
    findings: list[str] = []
    kind = doc.get("kind")
    meta = doc.get("metadata", {})
    name = meta.get("name", "<noname>")
    ns = meta.get("namespace", "default")

    if kind == "ClusterRoleBinding":
        subj = doc.get("subjects", [])
        role = doc.get("roleRef", {})
        if role.get("name") == "cluster-admin":
            findings.append(f"{path}: ClusterRoleBinding {name} grants cluster-admin")

    if kind in ("Deployment", "StatefulSet", "Pod"):
        spec = doc.get("spec", {})
        pod_spec = spec.get("template", spec).get("spec", spec)
        for c in pod_spec.get("containers", []):
            for env in c.get("env", []):
                if "valueFrom" in env and "secretKeyRef" in env["valueFrom"]:
                    findings.append(
                        f"{path}: {kind}/{name} secret {env['name']} via env in ns {ns}"
                    )
            sec = c.get("securityContext", {})
            if sec.get("privileged") or pod_spec.get("hostNetwork"):
                findings.append(f"{path}: {kind}/{name} privileged or hostNetwork")

    if kind == "NetworkPolicy":
        return findings  # presence is good; checked at namespace level

    return findings

def namespace_lacks_netpol(docs: list[dict]) -> bool:
    has_policy = any(d.get("kind") == "NetworkPolicy" for d in docs)
    has_workload = any(d.get("kind") in ("Deployment", "StatefulSet") for d in docs)
    return has_workload and not has_policy

if __name__ == "__main__":
    for arg in sys.argv[1:]:
        p = Path(arg)
        docs = list(yaml.safe_load_all(p.read_text()))
        if namespace_lacks_netpol(docs):
            print(f"{arg}: workload without NetworkPolicy")
        for doc in docs:
            if doc:
                for f in review_manifest(doc, arg):
                    print(f)
```

## Step-by-Step Review Walkthrough

1. **Inventory namespaces and labels.** Note which namespaces host production data services and whether Pod Security Admission enforce labels are set.
2. **Read RBAC bindings.** Follow `RoleBinding` and `ClusterRoleBinding` subjects to service accounts used by running Deployments.
3. **Check service account token mount.** Prefer `automountServiceAccountToken: false` unless the pod needs Kubernetes API access.
4. **Verify NetworkPolicy default deny.** Each sensitive namespace should deny all ingress and egress by default, then allow explicit ports and label selectors.
5. **Inspect pod security context.** Read `securityContext` at pod and container level; flag privileged mode, root user, and writable root filesystem.
6. **Review secret delivery.** Production DB and API keys should use `volumes.secret` mounts; env vars are acceptable only for non-sensitive config with documented rationale.
7. **Cross-check Helm/Kustomize overlays.** Production overlay may reintroduce dev-only permissive RBAC if reviewers read only the base chart.

## Risk Impact Analysis

**Cluster compromise.** `cluster-admin` on a compromised pod service account enables secret theft, workload deployment, and persistence across namespaces.

**Lateral movement.** Missing NetworkPolicy lets attackers scan internal services, reach unmanaged databases, and hit cloud metadata endpoints from any pod.

**Credential exposure.** Secrets in environment variables appear in process listings, debug endpoints, crash dumps, and CI-rendered manifest diffs.

**Container breakout impact.** Privileged pods increase blast radius when a kernel or runtime vulnerability is exploited.

**Multi-tenant bleed.** Shared clusters without policy and PSA enforcement allow one team's pod to read another team's secrets or APIs.

## Vulnerable Examples in Other Formats

### Kubernetes YAML (RBAC and secrets)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: app-admin-binding
subjects:
  - kind: ServiceAccount
    name: default
    namespace: production
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: production
spec:
  template:
    spec:
      serviceAccountName: default
      containers:
        - name: api
          image: myregistry/api:latest
          env:
            - name: DATABASE_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: db-credentials
                  key: password
          securityContext:
            privileged: true
```

No NetworkPolicy in namespace; default service account; secret via env; privileged container.

### NetworkPolicy (missing default deny)

Namespaces with workloads but zero NetworkPolicy resources allow unrestricted pod-to-pod traffic.

### Java (application integration)

```java
// Reads DB password from env — visible in container inspect and /proc
String password = System.getenv("DATABASE_PASSWORD");

// Kubernetes client uses default SA token with cluster-wide list secrets permission
@Configuration
public class K8sConfig {
    @Bean
    KubernetesClient client() {
        return new KubernetesClientBuilder().build(); // in-cluster config
    }
}
// Elsewhere: client.secrets().inAnyNamespace().list(); // over-permissioned RBAC
```

### C# (application integration)

```csharp
// ASP.NET reads JWT signing key from environment variable in Production
var signingKey = Environment.GetEnvironmentVariable("JWT_SIGNING_KEY");

// Mounted volume alternative exists in dev overlay only — prod still uses env
```

## Fix: Safer Patterns and Libraries to Use

### Kubernetes YAML

Apply least-privilege RBAC, restricted Pod Security, default-deny networking, and volume-mounted secrets per [RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) and [NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: api
  namespace: production
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: api-role
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["api-config"]
    verbs: ["get"]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: production
spec:
  template:
    spec:
      serviceAccountName: api
      automountServiceAccountToken: false
      containers:
        - name: api
          image: myregistry/api@sha256:abc123...
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
          volumeMounts:
            - name: db-credentials
              mountPath: /etc/secrets/db
              readOnly: true
      volumes:
        - name: db-credentials
          secret:
            secretName: db-credentials
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-api-to-db
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
  policyTypes: [Egress]
```

**Important:** Mount secrets as files under `/etc/secrets/...` and set file permissions with `defaultMode`. Application reads the file at startup; avoid logging contents.

### Python

Read mounted secret files in application code; validate manifests in CI with the reviewer above or [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/website/docs/).

```python
from pathlib import Path

def read_secret(name: str) -> str:
    path = Path(f"/etc/secrets/db/{name}")
    return path.read_text(encoding="utf-8").strip()

def connect_db():
    password = read_secret("password")
    # use password in connection setup; never log it
```

### Java

Use `Files.readString` on mounted paths; restrict Kubernetes client RBAC to required verbs.

```java
String password = Files.readString(Path.of("/etc/secrets/db/password")).trim();

@Configuration
public class K8sConfig {
    @Bean
    KubernetesClient client() {
        return new KubernetesClientBuilder().build();
    }
}
// Role should allow get on configmaps/api-config only — not secrets in all namespaces
```

### C#

Read secrets from mounted files via `File.ReadAllText`; keep signing keys out of environment variables in production overlays.

```csharp
var signingKey = File.ReadAllText("/etc/secrets/jwt/signing-key").Trim();
```

Follow [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) `restricted` profile for production namespaces unless a documented exception exists.

## Verify During Review

- **RBAC** grants minimum verbs on named resources; no `cluster-admin` for application service accounts.
- **Service accounts** are dedicated per workload; default SA is not used for production pods.
- **NetworkPolicy** implements default deny plus explicit allow rules for required traffic only.
- **Pod Security Admission** enforces baseline or restricted profile on production namespaces.
- Production secrets are **volume-mounted files**, not **environment variables**, unless risk is accepted in writing.
- Containers run **non-root**, without **privileged** mode or unnecessary **host** namespaces.
- Images use **digest pins** or immutable tags; `:latest` is not deployed to production.
- CI runs **policy-as-code** checks on manifests before apply.

## Reference

- [Kubernetes — RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [Kubernetes — Network policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Kubernetes — Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Kubernetes — Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
- [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/website/docs/)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-526: Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)
- [NSA/CISA — Kubernetes Hardening Guidance](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
