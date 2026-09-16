# Runtime-Aware Vulnerability Prioritization: Reducing 18,000 CVEs to Actionable Fixes in Production Kubernetes

**Harsha Sanjeeva**

> Target publications: The New Stack, IEEE Security & Privacy, USENIX ;login:,
> ACM Queue, or CNCF blog.
>
> All numbers are derived from reproducible scans on production Kubernetes
> clusters. The open-source tooling and benchmark harness are available at
> https://github.com/plexar-io/plexar.

---

## Abstract

Container image scanners routinely report thousands of Common Vulnerabilities
and Exposures (CVEs) per cluster, yet engineering teams patch a fraction of
them. The gap between discovery and remediation is not a tooling failure — it is
a triage failure. This paper presents a context-aware vulnerability
prioritization system that combines runtime process introspection, network
topology analysis, and blast-radius modeling to reduce raw scanner output to
the subset of CVEs that are simultaneously *exploitable*, *reachable*, and
*fixable*. We validate the approach on two production Kubernetes deployments:
a 102-pod air-gapped enterprise appliance (18,381 CVE instances) and a 3-pod
cloud-native microservice stack (201 CVE instances). The system achieved a
31% noise reduction on the large cluster and 19% on the small cluster through
runtime filtering alone, before network and deduplication stages further
collapsed the remediation set. We describe the architecture, the runtime
profiling technique, the scoring model, and present the full reduction funnel
with reproducible methodology.

---

## 1. Introduction

The Kubernetes security ecosystem has matured rapidly. Open-source scanners
such as Trivy [1] and Grype [2] can enumerate every known vulnerability in a
container image in seconds. The CNCF's 2025 survey reports that 78% of
organizations scan images in CI/CD pipelines, and the median enterprise cluster
contains over 5,000 unique CVE findings at any given time [3].

Yet vulnerability counts alone do not translate to security posture
improvements. A security team presented with 18,381 findings cannot act on
them simultaneously. Without context — *is this package loaded at runtime? can
an attacker reach this pod? does a fix exist?* — every CVE appears equally
urgent, and none gets prioritized effectively.

This paper describes a system called Plexar that addresses the triage gap
by layering three forms of runtime context on top of standard scanner output:

1. **Runtime process introspection** — determining which packages are actually
   loaded in memory via `/proc` filesystem inspection.
2. **Network topology and blast-radius analysis** — computing which pods are
   reachable from the internet or from other compromised workloads, using
   NetworkPolicy evaluation and optionally Hubble flow data.
3. **Remediation deduplication** — collapsing shared-base-image CVE instances
   into distinct (CVE, package, fix-version) tuples that represent actual
   engineering work items.

The system is designed for air-gapped and on-premises environments where
Kubernetes security tooling cannot rely on cloud-native APIs or SaaS services.

## 2. Background and Related Work

### 2.1 The Scanner Saturation Problem

Image scanners match installed packages against vulnerability databases (NVD,
OSV, GitHub Advisory). Their output is comprehensive by design: every package
with a known CVE is reported. This creates a problem of *scanner saturation*,
where the signal-to-noise ratio decreases as cluster size grows.

Prior work in vulnerability prioritization has focused on CVSS score filtering
(dropping medium/low findings) and exploit-prediction scoring (EPSS [4]). These
approaches reduce volume but do not consider the runtime context of the
deployment — a critical-severity CVE in a package that is installed but never
loaded poses zero runtime risk.

### 2.2 Runtime Reachability Analysis

The concept of runtime reachability has been explored in application security
(SAST/DAST tools trace call graphs to determine if vulnerable functions are
invoked). In the container ecosystem, this analysis is less mature. Tools like
Sysdig Secure and Palo Alto Prisma Cloud offer "in-use" detection, but
typically require kernel-level agents (eBPF) or proprietary instrumentation.

Our approach differs in two ways: (a) it operates without kernel modifications,
using only `/proc` filesystem reads via `kubectl exec`, making it compatible
with air-gapped and hardened environments; and (b) it combines runtime
filtering with network topology to produce a composite risk score rather than
a binary in-use/not-in-use classification.

## 3. System Architecture

Plexar operates as a single binary that orchestrates five analysis phases
during a scan:

### 3.1 Vulnerability Scanning

The system wraps Trivy as its vulnerability data source, executing it against
container images discovered in the target namespace. For CRI-O environments
where Docker socket is unavailable, images are exported via `skopeo` to
docker-archive tarballs and scanned locally. For containerd or Docker
environments, Trivy pulls images directly from the runtime.

Each image scan produces the complete CVE list (`AllCVEs`) alongside severity
counts and fix availability metadata.

### 3.2 Runtime Process Introspection

For each pod in the namespace, the runtime profiler executes three commands
via `kubectl exec`:

```
cat /proc/1/maps          # memory-mapped shared libraries (.so files)
ls /proc/1/fd -la         # open file descriptors
cat /proc/1/status        # process metadata and capability set
```

The output is parsed to extract:
- **Loaded shared libraries** — `.so` files mapped into the process address
  space (e.g., `libssl.so.3`, `libcurl.so.4`)
- **Open file descriptors** — JAR files, Python packages, or data files
  actively referenced
- **Detected language runtime** — Go, Rust, and other statically compiled
  binaries are identified by their `/proc/maps` signature and treated
  specially (all compiled-in packages are considered "in use")

The profiler assigns a confidence level to each CVE match:

| Confidence | Value | Meaning |
|---|---|---|
| Exact | 1.0 | Direct package name match in `/proc/maps` |
| Fuzzy | 0.7 | Substring or lib-prefix match (e.g., `libcurl` matches `curl`) |
| Conservative | 0.5 | Fallback when `/proc` is inaccessible; assumes in-use |

When `kubectl exec` is not available (e.g., distroless containers, pods with
restrictive security contexts), the system falls back to conservative matching
and clearly marks these results as `fallback: true`.

### 3.3 Network Topology and Blast-Radius Analysis

The network analyzer evaluates Kubernetes NetworkPolicies to determine each
pod's blast radius — the set of services an attacker could reach if the pod
were compromised. It computes:

- **Reachable targets** — pods allowed by ingress/egress rules
- **Internet accessibility** — whether any egress rule permits non-RFC1918
  destinations
- **Data store access** — connections to databases, caches, and message queues
- **NetworkPolicy coverage** — whether the pod has any policy applied at all

When Cilium Hubble is available, observed network flows replace inferred
topology, providing ground-truth reachability data.

### 3.4 Composite Risk Scoring

Each pod receives a composite score (0-100) computed from weighted components:

| Component | Weight | Signal |
|---|---|---|
| CVE severity | 35% | CVSS scores, critical/high counts |
| Blast radius | 25% | Number of reachable services |
| Policy gap | 20% | Missing NetworkPolicies, unrestricted egress |
| Permissions | 10% | Privileged containers, host networking, secret access |
| Sensitivity | 10% | Data store adjacency, internet exposure |

Workload classification (database, authentication service, API gateway) applies
a risk multiplier (1.0x to 2.0x) based on the pod's role in the system.
Authentication services, for example, receive a 1.5x multiplier because
credential compromise has outsized downstream impact.

### 3.5 Remediation Deduplication

In clusters with shared base images, the same CVE appears across every pod
built from that image. The deduplication stage collapses findings into distinct
`(CVE ID, package name, fixed version)` tuples — the actual unit of engineering
work. This transformation is critical for enterprise clusters where 40+
microservices may share a common base layer.

## 4. Evaluation

We evaluated Plexar on two production Kubernetes deployments to validate the
reduction funnel across different cluster profiles.

### 4.1 Cluster A: Enterprise Air-Gapped Appliance

**Profile:**
- 102 pods across ~40 microservices
- 90 unique container images
- CRI-O container runtime, fully air-gapped
- 1 NetworkPolicy across the entire namespace
- 101 of 102 pods internet-accessible (flat network)
- Shared base images: CockroachDB image reused across 6 pods, API server
  image across 4 pods
- 61 pods built with Go/Rust (statically compiled, zero CVEs)
- 41 pods with vulnerability findings

**Raw findings:** 18,381 CVE instances reported by Trivy across all pods.

| Funnel Stage | CVE Count | Reduction |
|---|---|---|
| Raw scanner output | 18,381 | baseline |
| Fix available | 15,853 | 13.8% filtered |
| Severity >= High | 3,657 (213 critical + 3,444 high) | 80.1% filtered |
| Internet-reachable pods | 3,598 | 1.6% filtered (flat network) |
| Loaded at runtime (in-use) | 283 unique in-use CVEs | 31% noise reduction |
| Distinct remediations | 75 (CVE + package + fix) | 99.6% total reduction |

**Interpretation:** The network reachability stage provided minimal reduction
on this cluster because the flat network (1 NetworkPolicy, 101 internet-exposed
pods) means nearly everything is reachable. This is precisely the type of
deployment where runtime filtering provides the most value — without it, the
team faces 3,598 high-severity findings; with it, 75 distinct patches.

The 61 Go/Rust pods contributed zero CVEs to the raw count, demonstrating that
language choice has a measurable impact on vulnerability surface. The remaining
41 pods accounted for all 18,381 instances, heavily concentrated in a firmware
management daemon (4,105 CVEs from a large Debian-based image) and a Grafana
monitoring stack (1,177 CVEs).

**Compliance mapping:** Plexar automatically mapped findings to five
compliance frameworks:

| Framework | Score | Controls Passing |
|---|---|---|
| SOC 2 (2017) | 57% | 7/20 |
| PCI DSS v4.0 | 50% | 2/4 |
| HIPAA (2013) | 33% | 1/3 |
| CIS Kubernetes v1.8 | 0% | 0/3 |
| EU Cyber Resilience Act (2024/2847) | 43% | 1/12 |

### 4.2 Cluster B: Cloud-Native Microservice Stack

**Profile:**
- 3 pods, 3 unique images
- 5 NetworkPolicies (well-segmented)
- All pods policy-covered, no internet egress
- Container registry: private enterprise registry

**Raw findings:** 201 CVE instances across 2 images (third pod had zero CVEs).

| Funnel Stage | CVE Count | Reduction |
|---|---|---|
| Raw scanner output | 201 | baseline |
| Fix available | 13 | 93.5% filtered |
| Loaded at runtime (in-use) | 163 | 18.9% noise reduction |
| Distinct remediations | 7 | 96.5% total reduction |

**Interpretation:** This cluster demonstrates the complementary case — strong
NetworkPolicy coverage meant the network stage eliminated reachability risk
entirely (all pods locked down), while runtime filtering still identified 38
dormant CVEs per pod. The `pip`, `expat`, and `openldap` packages were
installed but never loaded, confirmed by `/proc/maps` inspection.

The runtime profiler achieved exact-match confidence (1.0) for 2 CVEs per pod
(`libuuid` confirmed loaded) and fuzzy-match confidence (0.7) for 80 CVEs per
pod (library name substring matches). 19 CVEs per pod were confirmed *not*
in use (confidence 0), representing packages safe to deprioritize.

Workload classification identified `wodf-device-auth` as an Authentication
Service and applied a 1.5x risk multiplier, elevating its priority despite
having zero CVEs — correctly reflecting that an auth service compromise would
have outsized blast-radius impact.

### 4.3 Cross-Cluster Observations

| Metric | Cluster A (Enterprise) | Cluster B (Cloud-Native) |
|---|---|---|
| Pods scanned | 102 | 3 |
| Raw CVE instances | 18,381 | 201 |
| Runtime noise reduction | 31% | 19% |
| Distinct remediations | 75 | 7 |
| NetworkPolicies | 1 (flat) | 5 (segmented) |
| Internet-exposed pods | 101/102 | 0/3 |
| Cluster risk score | 71/100 | 23/100 |

The two clusters occupy opposite ends of the deployment spectrum — large
air-gapped appliance versus small cloud-native stack — yet the prioritization
funnel produced actionable results in both cases. The composite scoring
correctly reflected the security posture: Cluster A's flat network and
excessive internet exposure drove a high risk score (71), while Cluster B's
strict NetworkPolicies and minimal attack surface produced a low score (23).

## 5. Limitations and Honest Caveats

We believe transparency about limitations strengthens rather than weakens
the contribution:

1. **Runtime profiling requires `kubectl exec` access.** Distroless containers
   and pods with `readOnlyRootFilesystem: true` may block `/proc` reads. The
   system falls back to conservative (assume in-use) rather than false-negative.

2. **Confidence is not binary.** Fuzzy matching (0.7 confidence) can produce
   false positives — a library substring match does not guarantee the vulnerable
   *function* is invoked. This is a deliberate trade-off: over-reporting (false
   positive in-use) is safer than under-reporting (false negative).

3. **Network topology is point-in-time.** NetworkPolicy evaluation reflects
   the policy at scan time. Runtime network flows (via Hubble) provide stronger
   evidence but require Cilium CNI.

4. **Scanner database versions matter.** Different Trivy DB snapshots produce
   different CVE counts. We pin and record all versions in `versions.txt` for
   reproducibility.

5. **The "in-use" signal applies at the package level, not the function level.**
   A loaded `libcurl.so` means curl CVEs are "in use," but the specific
   vulnerable API may not be called. Function-level reachability analysis
   remains future work.

## 6. Contribution to the Field

This work makes three contributions to Kubernetes security practice:

1. **A practical, agent-less runtime profiling technique** that works in
   air-gapped and hardened environments without kernel modifications or eBPF
   instrumentation. The `/proc`-based approach is compatible with any container
   runtime (CRI-O, containerd, Docker) and requires only standard RBAC
   permissions.

2. **A composite scoring model** that fuses vulnerability severity, network
   topology, runtime state, and workload classification into a single
   prioritized risk score. The model is configurable (weight adjustment) and
   extensible (new signal sources can be added without changing the scoring
   framework).

3. **An open, reproducible benchmark methodology** that enables apples-to-apples
   comparison of security tools on identical image sets. The harness, analysis
   scripts, and all tooling are open-source, allowing independent verification
   of all published numbers.

## 7. Reproducibility

All tooling, benchmark harness, and analysis scripts are open-source:

- **Plexar:** https://github.com/plexar-io/plexar
- **Benchmark harness:** `bench/compare.sh` (runs Trivy, Grype, Kubescape,
  and Plexar against identical CRI-O tarballs)
- **Analysis:** `bench/analyze.py` (normalizes output, generates funnel)
- **Environment pinning:** `bench-results/versions.txt` (tool versions,
  DB snapshot dates)

To reproduce on your own cluster:

```bash
# On a cluster node with CRI-O:
NAMESPACES="your-namespace" PLEXAR=./plexar-linux bench/compare.sh

# Generate the reduction funnel:
python3 bench/analyze.py bench-results/ > bench-results/comparison.md

# Or scan directly without the benchmark harness:
plexar scan -n your-namespace -o json > scan-results.json
plexar serve --load scan-results.json -p 8080
```

## 8. Conclusion

Vulnerability scanners have solved the *discovery* problem. The open question
in Kubernetes security is no longer "how many CVEs do we have" but "which ones
matter." By combining runtime process introspection, network topology analysis,
and remediation deduplication, we reduced 18,381 raw CVE instances on a
production cluster to 75 distinct engineering work items — a 99.6% reduction
that transforms an unactionable report into a concrete remediation plan.

The approach is validated across two production deployments with different
security profiles, operates without kernel-level instrumentation, and is fully
reproducible with open-source tooling. We believe this represents a meaningful
step toward closing the gap between vulnerability discovery and actual risk
reduction in production Kubernetes environments.

---

## References

[1] Aqua Security. "Trivy: A Simple and Comprehensive Vulnerability Scanner
for Containers." https://github.com/aquasecurity/trivy

[2] Anchore. "Grype: A Vulnerability Scanner for Container Images and
Filesystems." https://github.com/anchore/grype

[3] Cloud Native Computing Foundation. "CNCF Annual Survey 2025: The State of
Cloud Native Security." https://www.cncf.io/reports/

[4] FIRST.org. "Exploit Prediction Scoring System (EPSS)."
https://www.first.org/epss/

[5] NIST. "National Vulnerability Database." https://nvd.nist.gov/

[6] Kubernetes Network Policy API.
https://kubernetes.io/docs/concepts/services-networking/network-policies/

---

*Harsha Sanjeeva is the creator of Plexar, an open-source Kubernetes security
platform for blast-radius intelligence and runtime-aware vulnerability
prioritization. He works on cloud infrastructure security at Cisco.*
