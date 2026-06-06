# Black Hat Briefings CFP Submission

---

## SUBMISSION TYPE

30-Minute Briefing

## TRACK

Cloud, Container, & Infrastructure Security

---

## TITLE

Beyond CVEs: Blast Radius Intelligence for Kubernetes

---

## PROBLEM STATEMENT

Enterprise Kubernetes clusters generate thousands of CVE alerts. A typical
production cluster running 200 pods will surface 2,000–5,000 vulnerabilities,
with 100–300 rated Critical or High by CVSS. Security teams face an impossible
triage problem: every scanner says "fix everything," but no one has the
engineering bandwidth to patch 300 critical CVEs this sprint.

The root cause is that CVSS measures theoretical severity in isolation. It does
not account for the environment the vulnerability lives in. In Kubernetes, the
environment is everything. A Critical CVE on a pod that has no NetworkPolicy,
can reach 14 other services, has egress to the internet, mounts secrets, and
runs as root is an active emergency. The same Critical CVE on a pod behind
strict ingress/egress NetworkPolicies, with a read-only filesystem, no
privilege escalation, and access to exactly one internal service is a backlog
item.

Today, no open-source tool combines CVE severity with live network reachability,
Kubernetes RBAC posture, security context analysis, and policy gap detection to
produce a single, prioritized risk score. Security teams are left correlating
data manually across Trivy, kubectl, and spreadsheets — or worse, ignoring the
alerts entirely.

This gap becomes even more critical as organizations deploy AI agent workloads
(LLM-based pods with broad tool access) where non-deterministic behavior makes
network reachability analysis essential for understanding the true blast radius
of a compromised pod.

---

## ABOUT THE TOOL

Reflex is a new open-source (Apache 2.0) Kubernetes security tool, written in
Go, that introduces the concept of blast radius intelligence to vulnerability
management.

Reflex connects to a Kubernetes cluster, discovers all pods across namespaces,
scans their container images for CVEs using a bundled Trivy scanner, maps the
live network topology (services, endpoints, NetworkPolicies, egress paths),
analyzes security context and RBAC permissions, and produces a composite risk
score from 0 to 100 for every pod.

The score combines five weighted dimensions: CVE severity, network blast radius,
policy gaps, permissions posture, and data sensitivity. The result is a ranked
list that tells security teams exactly which pods to fix first — not because
they have the highest CVSS, but because they have the highest blast radius.

Reflex also auto-generates risk-prioritized Kubernetes NetworkPolicies, maps
findings to compliance frameworks (SOC 2, PCI DSS, HIPAA, CIS Benchmarks),
exports to JSON/CSV/SARIF for CI/CD integration, and includes an interactive
web dashboard with a network topology graph.

The tool runs entirely inside the cluster. No data leaves. No SaaS dependency.
One binary, one command, immediate results.

---

## ABSTRACT

Kubernetes vulnerability scanners report thousands of CVEs per cluster, but CVSS
scores alone cannot tell you which ones matter. A Critical CVE on a pod with no
NetworkPolicy that reaches your database, payment service, and the public
internet is fundamentally more dangerous than the same CVE on an isolated pod
behind strict policies. Yet every scanner today scores them identically.

We introduce blast radius intelligence — a scoring methodology that combines CVE
severity with live network reachability, Kubernetes RBAC, security context, and
policy gaps to produce a composite risk score for every pod. We present Reflex,
an open-source tool that implements this approach.

In this talk, we present the scoring methodology, show real-world examples where
identical CVEs score from 22 (Low) to 95 (Critical) based on network context,
live-demo the tool against a production-like cluster, and discuss extending the
blast radius model to AI agent workloads where non-deterministic network
behavior makes reachability analysis even more critical.

Attendees will leave with a practical, deployable tool and a framework for
prioritizing Kubernetes vulnerabilities by actual exploitability rather than
theoretical severity.

---

## DETAILED OUTLINE

### Part 1 — The Problem: CVE Noise in Kubernetes [5 minutes]

The talk opens with the core problem every Kubernetes security team faces.
We show real numbers: a typical production cluster surfaces 3,000+ CVEs, 200+
Critical. Security teams fix none because they cannot prioritize.

We explain why CVSS alone fails in Kubernetes. CVSS measures theoretical
severity in isolation. It does not know that one pod can reach 14 services and
the internet while another pod is fully isolated behind NetworkPolicies. We
show a concrete example: two pods, both with three Critical CVEs. One has a
blast radius of 14 services plus internet egress. The other is isolated behind
strict policies with access to a single internal service. Same CVEs.
Completely different risk.

We introduce the thesis: network reachability is the multiplier that turns a
vulnerability into a breach. Without it, vulnerability management in Kubernetes
is guesswork.


### Part 2 — Blast Radius Scoring Methodology [7 minutes]

We present the composite scoring model. Every pod receives a score from 0 to
100, computed from five weighted dimensions:

    CVE Severity (30 points) — Critical, High, and Medium vulnerabilities
    weighted by count, with diminishing returns to avoid raw-count inflation.

    Network Blast Radius (25 points) — Number of reachable services, internet
    egress capability, proximity to data stores and sensitive services.

    Policy Gaps (20 points) — Missing NetworkPolicies, unrestricted egress,
    permissive ingress rules, no default-deny posture.

    Permissions Posture (15 points) — Running as root, privileged containers,
    hostNetwork access, writable filesystem, privilege escalation allowed.

    Data Sensitivity (10 points) — Access to PII stores, secrets mounts,
    authentication services, payment processing services.

We explain how network reachability is computed: pod to service to endpoint
mapping, NetworkPolicy evaluation (both ingress and egress), and external
egress detection. We walk through how the score is calculated for a single
pod with a concrete numeric example.

We discuss risk tiers: Critical (75-100) means fix now, High (50-74) means
fix this sprint, Medium (30-49) means plan it, Low (0-29) means monitor.

We explain that weights are fully configurable — PCI environments may weight
policy gaps higher, healthcare environments may weight data sensitivity
higher — and show the configuration interface.


### Part 3 — Architecture and Implementation [5 minutes]

We walk through the tool's architecture. Reflex is a single Go binary that
connects to the Kubernetes API server. It reads pods, services, endpoints,
NetworkPolicies, and RBAC bindings. For CVE data, it bundles Trivy and runs it
as a subprocess against container images — no prior scanner installation
required. It also supports reading existing Trivy Operator CRDs for clusters
that already have Trivy Operator deployed, or skipping CVE scanning entirely
for pure network-topology analysis.

We explain the pluggable scanner interface: enterprises using Grype, Snyk, or
other scanners can integrate without forking. We show the multi-namespace
scanning capability — single namespace, comma-separated list, or full cluster
scan.

We emphasize the zero-trust data model: everything runs in-cluster, no data
is exfiltrated, no SaaS callbacks, no telemetry. The tool produces results
locally and never phones home.


### Part 4 — Live Demonstration [8 minutes]

We run Reflex against a live multi-namespace Kubernetes cluster with
intentionally misconfigured workloads.

    Demo 1: CLI scan. We run "reflex scan --all-namespaces" and show the
    ranked output. We highlight two pods with identical CVEs that score 22
    and 95 respectively, and explain the difference using the blast radius
    topology.

    Demo 2: NetworkPolicy generation. We run "reflex generate netpol" and
    show the generated YAML targeting the highest-risk pods. We apply the
    policies and re-scan, showing the score drop from 95 to 30 in real
    time.

    Demo 3: Dashboard. We open the interactive web dashboard and show the
    network topology graph. We click on a Critical-tier pod and see its
    blast radius highlighted — every service it can reach, every egress
    path, every policy gap. We show the compliance view mapping findings
    to SOC 2 and PCI DSS controls.

    Demo 4: CI/CD integration. We show SARIF export being consumed by
    GitHub Advanced Security, and JSON export feeding a Slack alert via
    webhook.


### Part 5 — Real-World Findings and Patterns [3 minutes]

We present three patterns observed in production clusters:

    The default namespace trap. Organizations deploy workloads to the default
    namespace with zero NetworkPolicies. Every pod can reach every other pod
    and the internet. Average blast radius score: 78 (Critical).

    The over-permissioned sidecar. Istio and Envoy sidecars running with
    NET_ADMIN capability and no egress restrictions create lateral movement
    paths that bypass application-level security.

    The CI runner. Jenkins and GitHub Actions runner pods with cluster-admin
    RBAC, no network restrictions, and access to every secret in the
    namespace. A single CVE on a CI runner is a cluster takeover.

We quantify the impact: before Reflex, 3,000 CVEs with no prioritization.
After: 12 pods flagged Critical, 4 NetworkPolicies generated, cluster score
dropped from 78 to 31 in one afternoon.


### Part 6 — Future: Blast Radius for AI Agent Workloads [2 minutes]

We close by extending the model to AI agent workloads. LLM-based pods deployed
with broad tool access (MCP servers, database connections, external API keys)
represent a new class of blast radius that traditional CVE scanning cannot
address. These agents make non-deterministic network calls that cannot be
predicted from static code analysis.

We describe how Reflex's blast radius model extends to score AI agent tool
surface area, guardrail coverage, and observability gaps. We pose the question
the industry is not yet asking: if an AI agent goes rogue, what is its blast
radius, and who is watching?

---

## KEY TAKEAWAYS

1. CVSS scores without network context are misleading in Kubernetes. Blast
   radius is the missing multiplier that determines actual exploitability.

2. A practical scoring methodology that combines five dimensions — CVE severity,
   network reachability, policy gaps, permissions, and data sensitivity — into
   a single actionable score.

3. An open-source tool (Reflex) that attendees can deploy immediately to
   prioritize their own cluster's vulnerabilities by blast radius.

4. A technique for auto-generating risk-prioritized Kubernetes NetworkPolicies
   that measurably reduce blast radius.

5. A framework for extending blast radius analysis to AI agent workloads, an
   emerging and largely unaddressed security challenge.

---

## TRACK ALIGNMENT

This talk aligns with the Cloud, Container, & Infrastructure Security track.

The core contribution is a new methodology for prioritizing Kubernetes
vulnerabilities using live network reachability data — a problem that sits
squarely at the intersection of cloud infrastructure security and vulnerability
management. The talk addresses how default Kubernetes configurations create
dangerous blast radius conditions, how NetworkPolicy enforcement (or lack
thereof) directly determines post-compromise lateral movement, and how security
teams can use infrastructure-aware scoring to cut through vulnerability noise.

Every technical element — pod security contexts, RBAC analysis, NetworkPolicy
evaluation, service mesh considerations, egress path mapping — is native to
Kubernetes and cloud-native infrastructure. The live demo runs against a real
Kubernetes cluster. The tool generates Kubernetes-native remediation artifacts
(NetworkPolicy YAML). The compliance mapping targets cloud-relevant frameworks
(CIS Kubernetes Benchmarks, SOC 2 for SaaS providers, PCI DSS for payment
infrastructure running on Kubernetes).

The AI agent extension in the closing section connects cloud infrastructure
security to an emerging challenge: securing non-deterministic AI workloads
deployed as Kubernetes pods with broad network and tool access.

---

## INDUSTRY APPLICABILITY

This research applies to any organization running workloads on Kubernetes,
which includes the majority of Fortune 500 companies and a growing share of
mid-market enterprises.

Financial Services — Banks and payment processors running on Kubernetes face
PCI DSS requirements for network segmentation. Reflex identifies pods that
violate segmentation assumptions and maps findings directly to PCI DSS controls
(Requirement 1: network segmentation, Requirement 6: vulnerability management).
The blast radius score quantifies what auditors ask qualitatively: "if this
system is compromised, what can the attacker reach?"

Healthcare — HIPAA requires organizations to assess the risk of ePHI exposure.
Reflex's data sensitivity scoring identifies pods with access to patient data
stores and quantifies their blast radius. Healthcare organizations can use the
compliance mapping to demonstrate risk assessment due diligence.

SaaS and Technology — Multi-tenant SaaS platforms running on Kubernetes need to
ensure tenant isolation. Reflex identifies cross-namespace reachability and
policy gaps that could allow lateral movement between tenant workloads. SOC 2
Type II mapping provides evidence for customer audits.

Government and Defense — Organizations operating Kubernetes under FedRAMP or
NIST 800-53 controls need continuous monitoring of network segmentation and
vulnerability posture. Reflex's continuous operator mode and Prometheus metrics
integration provide the ongoing assessment these frameworks require.

AI and ML Platform Teams — Organizations deploying LLM-based agents and ML
pipelines on Kubernetes face a new class of blast radius from non-deterministic
workloads with broad tool access. The blast radius model extends to score
AI agent risk, an area with no existing tooling.

DevSecOps and Platform Engineering — Any team responsible for securing a
Kubernetes platform benefits from blast-radius-aware prioritization. The tool
integrates into existing CI/CD pipelines via SARIF export, feeds existing SIEM
and alerting infrastructure via JSON/webhook, and requires zero changes to
existing cluster configuration.

---

## SUPPORTING MATERIALS

1. Open-Source Tool Repository
   Reflex source code, documentation, and installation instructions will be
   publicly available on GitHub before the conference. Attendees can clone the
   repository and run the tool against their own clusters during or after the
   talk.
   URL: https://github.com/plexar-io/plexar

2. Live Demo Environment
   A pre-configured multi-namespace Kubernetes cluster (using kind or k3d)
   with intentionally misconfigured workloads will be used for the live
   demonstration. The cluster configuration scripts will be published in the
   repository under examples/demo-cluster/ so attendees can reproduce the
   exact demo environment.

3. Scoring Methodology Whitepaper
   A technical document detailing the blast radius scoring algorithm,
   weight calibration rationale, and network reachability computation
   methodology will be available in the repository under docs/.

4. Sample Scan Output
   Example JSON output from scanning a production-like cluster, including
   ranked pod scores, blast radius topology data, generated NetworkPolicies,
   and compliance mapping. Available in the repository under examples/.

5. Grafana Dashboard
   Pre-built Grafana dashboard JSON for visualizing blast radius metrics
   over time. Available at deploy/grafana-dashboard.json in the repository.

6. Slide Deck
   Will be submitted and made available to attendees after the talk.

---

## WHY THIS TALK IS NOVEL

No existing open-source tool combines CVE severity with live Kubernetes network
reachability for composite risk scoring. The blast radius scoring methodology
presented in this talk is new and has not been published elsewhere. The
extension to AI agent workloads has not been discussed at any security
conference to date.

Unlike vendor-sponsored talks about commercial CNAPP platforms, this talk
presents a fully open-source, zero-dependency tool that attendees can run
against their own clusters during the conference. The approach is practical
and immediately actionable.

---

## PRIOR PUBLICATION

This research has not been presented at any other conference or published in
any journal. The tool will be publicly available on GitHub before the
conference date.

---

## SPEAKER BIO

(To be filled in)

---

## TOOL INFORMATION

    Name:     Reflex
    URL:      https://github.com/plexar-io/plexar
    License:  Apache 2.0
    Language: Go
    Platform: Kubernetes (any distribution)
