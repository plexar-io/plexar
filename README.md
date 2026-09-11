<div align="center">

# 🔭 Plexar

**See further. Secure what matters.**

The security, compliance, and runtime intelligence layer for Kubernetes workloads.

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen?style=flat-square)]()
[![CNCF Landscape](https://img.shields.io/badge/CNCF-Landscape-326CE5?style=flat-square&logo=cncf)](https://landscape.cncf.io)

[Quick Start](#-quick-start) · [Features](#-features) · [Documentation](#-compliance-frameworks) · [API Reference](#-api-reference) · [Contributing](#-contributing)

</div>

---

## Why Plexar?

Traditional scanners tell you _"this pod has 3 critical CVEs."_

Plexar tells you:

> **"This pod has 3 critical CVEs, can reach your database, has cluster-admin RBAC, runs privileged, and has internet egress. The CVEs are loaded in memory at runtime. Fix this one first."**

|                   | `payment-service` | `inventory-service` |
| ----------------- | ----------------- | ------------------- |
| **CVEs**          | 3 Critical        | 3 Critical          |
| **NetworkPolicy** | None              | Applied             |
| **RBAC**          | secret-reader     | default SA          |
| **Reachable**     | 8 svc + internet  | 1 service           |
| **Runtime**       | 3/3 in use        | 0/3 in use          |
| **Plexar Score**  | **92** Critical   | **12** Low          |

Same CVEs. Completely different risk. **Plexar tells you which one to fix first.**

### What makes Plexar different

| Capability                      | Trivy | Kubescape |  Sysdig   | **Plexar** |
| ------------------------------- | :---: | :-------: | :-------: | :--------: |
| CVE scanning                    |  Yes  |    Yes    |    Yes    |  **Yes**   |
| Runtime "in use" filtering      |   -   |     -     |    $$$    |  **Yes**   |
| Attack path analysis            |   -   |     -     |    $$$    |  **Yes**   |
| CVE exploit chain analysis      |   -   |     -     |     -     |  **Yes**   |
| Observed network flows (Hubble) |   -   |     -     |    $$$    |  **Yes**   |
| AI agent-aware risk scoring     |   -   |     -     |     -     |  **Yes**   |
| Compliance evidence vault       |   -   |     -     |     -     |  **Yes**   |
| SOC 2 / PCI DSS / HIPAA mapping |   -   |     -     |  Partial  |  **Yes**   |
| EU CRA / EU AI Act reports      |   -   |     -     |     -     |  **Yes**   |
| Vanta / Drata integration       |   -   |     -     |     -     |  **Yes**   |
| Self-hosted                     |  Yes  |  Partial  |     -     |  **Yes**   |
| MCP server (AI assistants)      |   -   |    Yes    |     -     |  **Yes**   |
| **Price**                       | Free  | Freemium  | $100k+/yr |  **Free**  |

---

## ◈ Quick Start

### Install

```bash
# Homebrew
brew install plexar-io/tap/plexar

# Go
go install github.com/plexar-io/plexar@latest

# Binary
curl -sfL https://get.plexar.io | sh

# Helm (Kubernetes)
helm repo add plexar https://charts.plexar.io
helm install plexar plexar/plexar --namespace plexar-system --create-namespace

# From source
git clone https://github.com/plexar-io/plexar.git
cd plexar && go build -o plexar .
```

### Try the demo (5 minutes)

```bash
git clone https://github.com/plexar-io/plexar.git && cd plexar
./demo/setup.sh          # creates a kind cluster with 10 vulnerable workloads
```

```bash
◈ plexar scan -n acme-prod
```

```
◈ Plexar Scan — acme-prod
  Cluster: plexar-demo | 10 pods | 6 namespaces

  RANK  SCORE  TIER       POD                 CLASS                    CVEs        BLAST
  1     100    critical   api-gateway         API Gateway / Ingress    26C/137H    10 svc+inet
  2     100    critical   cart-service        Cache / In-Memory Store  12C/100H    10 svc+inet
  3      92    critical   payment-service     Payment / Financial Svc  3C/45H      8 svc+inet
  4      76    critical   auth-service        Authentication Service   107C/1651H  3 svc
  5      58    high       ml-pipeline         ML / AI Workload         0C/9H       2 svc
  ...

  Runtime: 847 total CVEs → 72 in use (91.5% noise reduction)
  Attack Paths: 3 critical, 1 high (shortest: internet → api-gateway → cluster-admin)

  Compliance: SOC 2 63/100 | PCI DSS 71/100 | EU CRA 58/100
```

### Core commands

```bash
# One-shot scan
◈ plexar scan -n production                       # CLI table output
◈ plexar scan -n production -o json                # JSON
◈ plexar scan -n production -o soc2-report.pdf     # SOC 2 PDF
◈ plexar scan -n production -o euai-report.pdf     # EU AI Act PDF

# Ingest external scanner data
◈ plexar ingest --source kubescape --file report.json
◈ plexar ingest --source kyverno --file policyreport.json
◈ plexar ingest --source trivy-sbom --file sbom.cdx.json

# Generate NetworkPolicies
◈ plexar generate netpol -n production

# Continuous operator mode
◈ plexar serve -n production --scan-interval 5m \
    --alert-slack-url "$SLACK_WEBHOOK" \
    --vanta-token "$VANTA_TOKEN" \
    --evidence-sink "s3://key:secret@minio:9000/evidence" \
    --hubble-relay hubble-relay.kube-system:4245

# MCP server for AI assistants
◈ plexar mcp -n production
```

---

## ◈ Features

### Blast Radius Scoring

Every pod gets a **0–100 composite risk score** combining five weighted signals:

```
Score = CVE Severity (30) + Blast Radius (25) + Policy Gap (20) + Permissions (15) + Data Sensitivity (10)
      × Workload Risk Multiplier
```

| Score  | Tier         | Action                            |
| :----: | ------------ | --------------------------------- |
| 75–100 | **Critical** | Fix now — active exploitable risk |
| 50–74  | **High**     | Fix soon — significant exposure   |
| 30–49  | **Medium**   | Plan — needs attention            |
|  0–29  | **Low**      | Monitor — good posture            |

### Runtime "In Use" CVE Detection

Plexar reads `/proc/<pid>/maps` and `/proc/<pid>/fd` to identify which packages are **actually loaded in memory** at runtime, then cross-references against SBOM vulnerabilities:

- **Exact match** (confidence 1.0) — package name directly in loaded libs
- **Fuzzy match** (confidence 0.7) — `libssl` ↔ `openssl` style matching
- **Conservative** (confidence 0.5) — fallback when /proc unavailable
- **Go/Rust detection** — identifies statically-linked binaries via ELF headers
- **~95% noise reduction** — only in-use CVEs bubble to the top

> _Sysdig charges $100k+/yr for this. Plexar does it free, self-hosted._

### Attack Path Analysis

Graph-based attack chain modeling from internet-facing pods to critical assets:

```
internet ──network_reach──▶ api-gateway ──rbac_escalate──▶ cluster-admin ──secret_access──▶ secrets
   │                           │                              │
   │ weight: 1                 │ weight: 2                    │ weight: 1
   │                           │                              │
   └── Remediation:            └── Remediation:               └── Remediation:
       Add NetworkPolicy           Remove ClusterRoleBinding       Restrict RBAC secrets
```

- **Dijkstra shortest-path** from internet to cluster-admin/secrets
- **Per-edge remediation** — specific fix for each hop
- **Risk reduction estimates** — "Fixing weakest link drops severity from critical to medium"
- **Severity scoring** — combined CVE × reachability × RBAC × runtime

### CVE Exploit Chain Analysis

DFS-based traversal finds multi-hop exploit chains where each hop requires a matching CVE exploit type:

```
web-frontend ──SSRF──▶ api-service ──RCE──▶ db-proxy ──SQLi──▶ database
  CVE-2024-1234          CVE-2024-5678        CVE-2024-9012
```

- **CVE-type-aware chaining** — SSRF enables network hops, RCE enables exec, SQLi enables data access
- **Agent-aware scoring** — AI workloads get 1.5× chain risk multiplier
- **Break-the-chain fixes** — identifies which single CVE patch eliminates the most chains
- **Severity classification** — chains scored by hop count, CVE severity, and agent involvement

### Cilium Hubble Integration

Dual-mode network analysis — **observed flows preferred**, K8s API inference as fallback:

```bash
# Auto-detect Hubble Relay (via K8s service discovery)
◈ plexar serve -n production

# Explicit Hubble Relay address
◈ plexar serve -n production --hubble-relay hubble-relay.kube-system:4245
```

- **Auto-detection** — discovers `hubble-relay` service in `kube-system` automatically
- **Ground-truth reachability** — observed traffic replaces inferred blast radius
- **Graceful fallback** — if Hubble unavailable, falls back to K8s API inference
- **Flow aggregation** — deduplicates and summarizes per pod-pair

### Multi-Source Ingestion

Import findings from external scanners and normalize into Plexar's unified model:

| Source         | Format                | What's extracted                            |
| -------------- | --------------------- | ------------------------------------------- |
| **Kubescape**  | JSON                  | Controls, pass/fail/warn, resource findings |
| **Kyverno**    | PolicyReport JSON     | Policy results, severity, category          |
| **Trivy SBOM** | CycloneDX / SPDX JSON | Components, packages, vulnerabilities       |

```bash
◈ plexar ingest --source kubescape --file report.json
# 📥 Ingested kubescape: 147 findings (98 pass, 32 fail, 17 warn)
```

### Evidence Sinks

Push compliance evidence to external storage automatically after each scan:

```bash
# S3 / MinIO
◈ plexar serve --evidence-sink "s3://accessKey:secretKey@minio:9000/evidence-bucket"

# Webhook
◈ plexar serve --evidence-sink "webhook://https://siem.company.com/ingest?header=Authorization:Bearer+token"
```

### AI Workload Classifier

Automatic classification of **19 workload types** with risk multipliers:

| Class            | Multiplier |     | Class          | Multiplier |
| ---------------- | :--------: | --- | -------------- | :--------: |
| AI Agent Runtime |   ×1.55    |     | API Gateway    |   ×1.30    |
| Auth Service     |   ×1.50    |     | Search Engine  |   ×1.30    |
| Payment Service  |   ×1.50    |     | Cache / Redis  |   ×1.25    |
| LLM Inference    |   ×1.50    |     | Object Storage |   ×1.25    |
| Secret Manager   |   ×1.50    |     | Message Queue  |   ×1.20    |
| AI Gateway       |   ×1.45    |     | General App    |   ×1.00    |
| Database         |   ×1.40    |     | Monitoring     |   ×0.85    |
| CI/CD Pipeline   |   ×1.40    |     |                |            |
| RAG Pipeline     |   ×1.40    |     |                |            |
| Model Registry   |   ×1.40    |     |                |            |
| ML / AI Workload |   ×1.35    |     |                |            |

### Web Dashboard (12 pages)

Embedded in the binary — no separate frontend build. Served at `http://localhost:8080`.

| Page                 | Description                                                             |
| -------------------- | ----------------------------------------------------------------------- |
| **Dashboard**        | Cluster risk score, pod counts, CVE stats, In Use toggle, noise banner  |
| **Topology**         | Interactive blast radius map with network lines                         |
| **Pods**             | Full pod table with class, multiplier, CVEs, reachability               |
| **CVE Explorer**     | Browse all CVEs with namespace/severity/package/in-use filters, export  |
| **Compliance**       | Tabbed framework view with scores, findings, remediation                |
| **RBAC Audit**       | Cluster-admin, wildcard, exec, secret flags with filtering              |
| **Evidence Vault**   | Hash chain integrity, drift timeline, control pass rates                |
| **Integrations**     | Vanta/Drata provider cards and push history                             |
| **Alerts**           | Alert rules, destinations, recent events                                |
| **Runtime Insights** | In Use vs Dormant CVEs, per-pod charts, confidence scores               |
| **Attack Paths**     | Path visualization with node chains, edge details, remediation          |
| **Settings**         | Scoring weights, scan configuration                                     |

---

## ◈ Compliance Frameworks

### SOC 2 Trust Service Criteria (20 controls)

```bash
◈ plexar scan -n production -o soc2-report.pdf
```

| Control | Name                                 | What Plexar Assesses                        |
| ------- | ------------------------------------ | ------------------------------------------- |
| CC3.1   | Risk Identification                  | Pod risk tiers, blast radius scores         |
| CC3.2   | Risk Assessment of Changes           | Drift detection, snapshot deltas            |
| CC3.4   | Fraud & Unauthorized Activity        | Privileged containers, cluster-admin RBAC   |
| CC6.1   | Logical Access Controls              | NetworkPolicy coverage                      |
| CC6.3   | Least Privilege                      | RBAC audit: privileged, root, exec, secrets |
| CC6.6   | Network Security                     | Internet egress, segmentation               |
| CC7.1   | Detection of Unauthorized Activities | Real-time scanning, alerting                |
| CC8.1   | Vulnerability Remediation            | Critical CVE counts, fixable CVEs           |
| C1.1    | Confidential Info Protection         | Env secrets, RBAC secret access             |
|         | _...and 11 more controls_            |                                             |

### EU Cyber Resilience Act (CRA)

Maps to **Regulation (EU) 2024/2847 Article 13** requirements:

```bash
◈ plexar scan -n production    # EU CRA included in compliance output
```

| Control  | Article 13 Requirement                                    |
| -------- | --------------------------------------------------------- |
| CRA-13.1 | Security by design — no known exploitable vulnerabilities |
| CRA-13.2 | Secure default configuration                              |
| CRA-13.3 | Security updates and patch management                     |
| CRA-13.4 | Access control and authentication                         |
| CRA-13.5 | Confidentiality and integrity of data                     |
| CRA-13.6 | Minimal data processing and attack surface                |
| CRA-13.7 | Availability and resilience                               |
| CRA-13.8 | Logging, monitoring, and audit trails                     |

### EU AI Act Annex IV

```bash
◈ plexar scan -n ml-production -o euai-report.pdf
```

8 sections covering Articles 9, 10, 14, 15 of Regulation (EU) 2024/1689. Automatically identifies AI/ML workloads for targeted assessment.

### Also included

- **PCI DSS** — Payment card data protection controls
- **HIPAA** — Healthcare data safeguards
- **CIS Kubernetes Benchmark** — Infrastructure hardening

---

## ◈ Integrations

### GRC Platforms

```bash
# Vanta — automated evidence + control status push
◈ plexar serve --vanta-token $VANTA_TOKEN

# Drata — automated evidence + control status push
◈ plexar serve --drata-key $DRATA_KEY
```

### Alert Destinations

```bash
# Slack — Block Kit messages with pod, score delta, remediation
◈ plexar serve --alert-slack-url "$SLACK_WEBHOOK"
```

Also supports **PagerDuty** (Events API v2) and **Jira** (auto-created tickets).

### MCP Server (AI Assistants)

```json
{
  "mcpServers": {
    "reflex": {
      "command": "reflex",
      "args": ["mcp", "--namespace", "production"]
    }
  }
}
```

| Tool                 | Description               |
| -------------------- | ------------------------- |
| `scan_namespace`     | Full blast radius scan    |
| `get_pod_risk`       | Per-pod risk breakdown    |
| `check_compliance`   | SOC 2 / EU CRA assessment |
| `classify_workloads` | Workload classification   |
| `find_critical_cves` | Critical/high CVEs        |
| `audit_rbac`         | RBAC permission audit     |

### Evidence Sinks

```bash
◈ plexar serve \
    --evidence-sink "s3://key:secret@minio:9000/bucket" \
    --evidence-sink "webhook://https://siem.corp.com/ingest"
```

---

## ◈ API Reference

All endpoints available when running `◈ plexar serve`:

| Endpoint                          | Method | Description                                                   |
| --------------------------------- | :----: | ------------------------------------------------------------- |
| `/api/scan`                       |  GET   | Run scan, return full results                                 |
| `/api/cves`                       |  GET   | All CVEs with filters: namespace, severity, package, inuse    |
| `/api/compliance`                 |  GET   | All compliance framework results                              |
| `/api/compliance/framework?name=` |  GET   | Single framework (soc2, eu-cra, pci-dss, hipaa, cis)          |
| `/api/ingest?source=`             |  POST  | Ingest external scanner data (kubescape, kyverno, trivy-sbom) |
| `/api/rbac`                       |  GET   | RBAC audit findings                                           |
| `/api/runtime`                    |  GET   | Runtime in-use insights, noise reduction, profiles            |
| `/api/attackpath`                 |  GET   | Attack path analysis with remediation                         |
| `/api/chains`                     |  GET   | CVE exploit chain analysis with break-the-chain fixes         |
| `/api/flows`                      |  GET   | Observed network flows (Hubble) or flow source status         |
| `/api/history`                    |  GET   | Historical scan snapshots                                     |
| `/api/history/latest`             |  GET   | Most recent snapshot                                          |
| `/api/history/delta`              |  GET   | Delta between last two snapshots                              |
| `/api/evidence`                   |  GET   | Evidence vault records (filterable)                           |
| `/api/evidence/summary`           |  GET   | Control pass rates over time                                  |
| `/api/evidence/drift`             |  GET   | Drift events (filterable by severity)                         |
| `/api/evidence/verify`            |  GET   | Hash chain integrity check                                    |
| `/api/evidence/sinks`             |  GET   | Configured evidence sinks status                              |
| `/api/alerts`                     |  GET   | Alert rules                                                   |
| `/api/alerts/events`              |  GET   | Recent alert events                                           |
| `/api/integrations`               |  GET   | Vanta/Drata provider status                                   |
| `/api/generate/netpol`            |  GET   | NetworkPolicy suggestions                                     |
| `/api/namespaces`                 |  GET   | Scannable namespaces                                          |
| `/api/export/csv`                 |  GET   | CSV download                                                  |
| `/api/settings/weights`           |  GET   | Scoring weights                                               |
| `/api/meta`                       |  GET   | Server version and config                                     |
| `/healthz`                        |  GET   | Liveness probe                                                |
| `/readyz`                         |  GET   | Readiness probe                                               |
| `/metrics`                        |  GET   | Prometheus metrics (port 9090)                                |

---

## ◈ Architecture

```
                          ┌─────────────────────────────┐
                          │    ◈ Plexar Operator        │
                          │                             │
  ┌──────────┐           │  ┌──────────┐ ┌──────────┐ │          ┌──────────┐
  │ Trivy    │──scan────▶│  │ Scanner  │ │ Runtime  │ │──push──▶│ Vanta    │
  │ Operator │           │  │ + SBOM   │ │ Profiler │ │          │ Drata    │
  └──────────┘           │  └────┬─────┘ └────┬─────┘ │          └──────────┘
                          │       │            │       │
  ┌──────────┐           │  ┌────▼────────────▼────┐  │          ┌──────────┐
  │Kubescape │──ingest──▶│  │  Scoring Engine      │  │──sink──▶│ S3/MinIO │
  │ Kyverno  │           │  │  + Attack Path       │  │          │ Webhook  │
  └──────────┘           │  │  + Compliance Mapper  │  │          └──────────┘
                          │  └────┬────────────┬────┘  │
  ┌──────────┐           │       │            │       │          ┌──────────┐
  │ kubectl  │◀──api────│  ┌────▼─────┐ ┌───▼────┐  │──alert─▶│ Slack    │
  │ Dashboard│           │  │ Evidence │ │ History │  │          │ PagerDuty│
  │ MCP/AI   │           │  │ Vault    │ │ Store   │  │          │ Jira     │
  └──────────┘           │  └──────────┘ └────────┘  │          └──────────┘
                          └─────────────────────────────┘
```

---

## ◈ Project Structure

```
plexar/
├── cmd/                          # CLI commands
│   ├── root.go                   # Global flags, kubeconfig, namespace
│   ├── scan.go                   # ◈ plexar scan — one-shot scan + PDF
│   ├── serve.go                  # ◈ plexar serve — operator + dashboard
│   ├── ingest.go                 # ◈ plexar ingest — import external scans
│   ├── mcp.go                    # ◈ plexar mcp — AI assistant server
│   ├── generate.go               # ◈ plexar generate netpol
│   └── version.go                # ◈ plexar version
│
├── pkg/
│   ├── api/handler.go            # Scan orchestration pipeline
│   ├── scanner/                  # Trivy, Trivy Operator, noop, cache
│   ├── ingest/                   # Multi-source ingestion (kubescape, kyverno, trivy-sbom)
│   ├── runtime/
│   │   ├── profiler.go           # /proc-based runtime profiler + Go/Rust detection
│   │   └── matcher.go            # In-use matching with confidence scoring
│   ├── attackpath/
│   │   ├── graph.go              # Directed weighted attack graph + CVE/agent enrichment
│   │   ├── analyzer.go           # Dijkstra + remediation + risk reduction + chain analysis
│   │   ├── chains.go             # DFS exploit chain traversal + agent-aware scoring
│   │   └── cvetypes.go           # CVE exploit type classifier (SSRF, RCE, SQLi, etc.)
│   ├── compliance/
│   │   ├── mapper.go             # SOC 2, PCI DSS, HIPAA, CIS
│   │   └── cra.go                # EU Cyber Resilience Act (Article 13)
│   ├── evidence/
│   │   ├── vault.go              # Hash-chained immutable evidence store
│   │   ├── drift.go              # Drift detection engine
│   │   ├── sink.go               # Sink interface + manager
│   │   ├── sink_s3.go            # S3/MinIO sink (SigV4)
│   │   └── sink_webhook.go       # Webhook sink
│   ├── rbac/auditor.go           # Per-pod RBAC analysis
│   ├── hubble/
│   │   ├── client.go             # Hubble Relay client + auto-detection
│   │   └── collector.go          # Flow aggregation + reachable target extraction
│   ├── network/network.go        # Reachability + blast radius (dual-mode: Hubble/inferred)
│   ├── scorer/                   # Risk scoring + configurable weights
│   ├── permissions/              # Security context analysis
│   ├── classifier/               # AI workload classifier (19 classes, agent-aware)
│   ├── alerting/                 # Rule engine + Slack/PD/Jira
│   ├── integrations/             # Vanta + Drata API clients
│   ├── report/                   # SOC 2 PDF + EU AI Act PDF
│   ├── mcp/server.go             # MCP protocol (6 tools, JSON-RPC)
│   ├── history/store.go          # 90-day snapshot retention
│   ├── auth/auth.go              # OIDC + namespace RBAC
│   ├── metrics/                  # Prometheus collector
│   ├── reporter/                 # CLI table, JSON, CSV, SARIF
│   ├── netpol/                   # NetworkPolicy YAML generation
│   ├── preflight/                # Environment validation
│   └── k8s/client.go             # Kubernetes client
│
├── internal/types/types.go       # Shared data types
├── web/                          # Embedded 11-page dashboard
├── demo/                         # Kind cluster + vulnerable workloads
├── charts/plexar/                # Helm chart
│   ├── Chart.yaml
│   ├── values.yaml
│   └── templates/               # K8s resource templates
├── deploy/                       # K8s manifests + Grafana dashboard
├── examples/                     # Sample weights, configs
├── .goreleaser.yaml              # GoReleaser multi-platform release config
├── Dockerfile
├── Makefile
├── go.mod
└── LICENSE                       # Apache 2.0
```

---

## ◈ Prerequisites

- **Kubernetes cluster** — or use `./demo/setup.sh` to create one with kind
- **kubectl** — configured with cluster access
- **Trivy** _(optional)_ — for CVE scanning. Not required with `--vuln-source trivy-operator` or `--vuln-source none`
- **skopeo** _(optional)_ — required only for CRI-O based clusters (auto-detected)

---

## ◈ Building from Source

### Local (macOS/Linux)

```bash
git clone https://github.com/plexar-io/plexar.git
cd plexar
go build -o plexar .
```

### Cross-compile for a remote Linux server

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/plexar-linux .
```

The binary is fully self-contained — the dashboard, all templates, and static assets are embedded. No external files needed.

---

## ◈ Scanning Restricted Clusters (CRI-O / Nexus Dashboard)

Standard Kubernetes clusters use Docker or containerd where Trivy can pull images directly. Some environments (Cisco NDFC, OpenShift, etc.) use **CRI-O** where images aren't available via `docker pull`. Plexar handles this automatically.

### How it works

1. Plexar auto-detects CRI-O by checking the container runtime on nodes
2. Uses `skopeo` to export images from CRI-O's local storage
3. Feeds the exported tar to Trivy for scanning

### Requirements

On the node where you run plexar:

```bash
# Install skopeo (if not already present)
# RHEL/CentOS
yum install -y skopeo

# Ubuntu/Debian
apt-get install -y skopeo
```

### Usage

```bash
# Auto-detect (recommended) — detects CRI-O automatically
sudo plexar scan -n cisco-ndfc

# Explicit CRI-O mode
sudo plexar scan -n cisco-ndfc --image-source crio

# Force Docker Hub mode (skip CRI-O detection)
sudo plexar scan -n cisco-ndfc --image-source docker
```

> **Note:** `sudo` is required for CRI-O scanning (access to container storage) and runtime profiling (access to `/proc`).

### Saving scan results

```bash
sudo plexar scan -n cisco-ndfc -o json > plexar-scan.json
```

This JSON file contains all pod scores, CVEs, blast radius, RBAC findings, compliance results, and attack paths. It can be loaded into the dashboard later without needing cluster access.

---

## ◈ Dashboard Deployment

The web dashboard is embedded in the binary. There are several ways to run it depending on your environment.

### Option 1: Local viewing (easiest)

View scan results on your own machine. No cluster access needed.

```bash
# Run the scan on the cluster, save results
sudo plexar scan -n production -o json > plexar-scan.json

# View the dashboard locally
./plexar serve --load plexar-scan.json -p 8080
# Open http://localhost:8080
```

### Option 2: Live operator mode

Continuous scanning with automatic refresh:

```bash
plexar serve -n production --scan-interval 5m -p 8080
```

### Option 3: Remote server for team access

Deploy on a server your team can reach. This is the recommended approach for sharing the dashboard.

**Step 1:** Build and copy to the server

```bash
# Cross-compile
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/plexar-linux .

# Copy binary and scan data
scp bin/plexar-linux user@server:~/plexar
scp plexar-scan.json user@server:~/plexar-scan.json
```

**Step 2:** Run on the server

```bash
ssh user@server

# Run in background (survives disconnect)
nohup ~/plexar serve --load ~/plexar-scan.json -p 7777 --metrics-port 7778 \
  > ~/plexar.log 2>&1 &

# Verify it's running
curl -s http://localhost:7777/api/meta
```

> **Important:** Use `nohup` or `tmux` to keep plexar running after you disconnect. Without it, the process dies when your SSH session closes.

**Step 3:** Open the firewall port

Most servers have a default DROP policy on INPUT. You need to allow the dashboard port:

```bash
# Check current policy
sudo iptables -L INPUT -n | head -3

# If policy is DROP, allow the dashboard port
sudo iptables -I INPUT 1 -p tcp --dport 7777 -j ACCEPT

# Verify the rule is in place
sudo iptables -L INPUT -n --line-numbers | head -5
```

**Step 4:** Access from any browser

```
http://<server-ip>:7777
```

Share this URL with your team. No client-side setup needed.

**Cleanup:** Remove the firewall rule when done:

```bash
sudo iptables -D INPUT -p tcp --dport 7777 -j ACCEPT
```

> **Note:** iptables rules don't survive reboots unless explicitly saved. This is a feature for temporary dashboard sharing.

### Troubleshooting remote deployment

| Problem | Cause | Fix |
| --- | --- | --- |
| `bind: address already in use` | Port already taken | Use a different port: `-p 7777` |
| Dashboard loads but no data | Scan file path wrong | Use absolute path: `--load /full/path/to/scan.json` |
| `~/file` not found (as root) | `~` resolves to `/root/` | Use absolute path instead |
| Chrome spins forever | Firewall blocking | Add iptables rule (see above) |
| SSH tunnel hangs | Appliance network isolation | SSH daemons on some appliances (NDFC, etc.) run in restricted network namespaces; use iptables direct access instead |
| `nohup: command not found` | Minimal container OS | Use `tmux` or `screen` instead |
| Process dies on disconnect | Forgot `nohup` / `tmux` | Prefix with `nohup ... &` |

### SSH port forwarding (alternative to iptables)

If you can't modify firewall rules, SSH tunneling works on standard Linux servers:

```bash
# From your laptop — maps local port 8080 to remote port 7777
ssh -N -L 8080:localhost:7777 user@server
# Then open http://localhost:8080

# If localhost doesn't work (containerized SSH daemons), try the server's IP:
ssh -N -L 8080:<server-ip>:7777 user@server
```

> **Warning:** On appliance platforms (Cisco NDFC, etc.), the SSH daemon may run in an isolated network namespace where `localhost` doesn't reach host-network services. In this case, SSH tunneling won't work — use the iptables approach instead.

---

## ◈ CVE Explorer

The dashboard includes a full **CVE Explorer** page for browsing all vulnerabilities across namespaces and pods.

### Features

- **Filter by namespace, severity, package name, In Use status**
- **Sortable columns** — click any header to sort by CVSS, severity, pod, etc.
- **Pagination** — handles thousands of CVEs efficiently
- **CSV export** — download filtered results for spreadsheets or ticketing
- **In Use / Dormant badges** — shows which CVEs are loaded in memory at runtime

### API

```bash
# All CVEs
curl http://localhost:8080/api/cves

# Filter by namespace
curl http://localhost:8080/api/cves?namespace=production

# Filter by severity
curl http://localhost:8080/api/cves?severity=CRITICAL

# Only in-use CVEs
curl http://localhost:8080/api/cves?inuse=true

# Search by package
curl http://localhost:8080/api/cves?package=openssl

# Combine filters
curl "http://localhost:8080/api/cves?namespace=production&severity=CRITICAL&inuse=true"
```

---

## ◈ Runtime In Use Filtering

The dashboard includes an **In Use Only** toggle in the top-right corner of the Dashboard page. When enabled:

- **Stat cards** show only in-use CVE counts
- **Pod tables** show filtered critical/high counts
- **Topology CVE panel** shows IN USE / DORMANT badges
- **Noise reduction banner** shows the percentage of CVEs eliminated

### How runtime profiling works

```bash
# Run with sudo for /proc access
sudo plexar scan -n production -o json > scan-with-runtime.json

# View in dashboard — In Use toggle will show real filtering
./plexar serve --load scan-with-runtime.json
```

Without `sudo`, all CVEs default to "in use" (conservative mode, confidence 0.5). With `sudo`, Plexar reads `/proc/<pid>/maps` to identify actually loaded packages, typically achieving **90-96% noise reduction**.

---

## ◈ Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

```bash
# Development setup
git clone https://github.com/plexar-io/plexar.git
cd plexar
go build ./...
go test ./...

# Run the demo cluster
./demo/setup.sh
◈ plexar scan -n acme-prod
```

---

## ◈ License

Apache 2.0 — see [LICENSE](LICENSE).

---

<div align="center">

**◈ Plexar** — See further. Secure what matters.

[Website](https://plexar.io) · [Documentation](https://docs.plexar.io) · [GitHub](https://github.com/plexar-io/plexar) · [Discord](https://discord.gg/reflex)

</div>
