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
brew install plexar-security/tap/plexar

# Go
go install github.com/plexar-security/plexar@latest

# Binary
curl -sfL https://get.plexar-security.io | sh

# From source
git clone https://github.com/plexar-security/plexar.git
cd plexar && go build -o reflex .
```

### Try the demo (5 minutes)

```bash
git clone https://github.com/plexar-security/plexar.git && cd plexar
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
    --evidence-sink "s3://key:secret@minio:9000/evidence"

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

Automatic classification of **14 workload types** with risk multipliers:

| Class            | Multiplier |     | Class          | Multiplier |
| ---------------- | :--------: | --- | -------------- | :--------: |
| Auth Service     |   ×1.50    |     | API Gateway    |   ×1.30    |
| Payment Service  |   ×1.50    |     | Search Engine  |   ×1.30    |
| Secret Manager   |   ×1.50    |     | Cache / Redis  |   ×1.25    |
| Database         |   ×1.40    |     | Object Storage |   ×1.25    |
| CI/CD Pipeline   |   ×1.40    |     | Message Queue  |   ×1.20    |
| ML / AI Workload |   ×1.35    |     | General App    |   ×1.00    |
| LLM Inference    |   ×1.60    |     | Monitoring     |   ×0.85    |

### Web Dashboard (11 pages)

Embedded in the binary — no separate frontend build. Served at `http://localhost:8080`.

| Page                 | Description                                                     |
| -------------------- | --------------------------------------------------------------- |
| **Dashboard**        | Cluster risk score, pod counts, CVE stats, compliance sparkline |
| **Topology**         | Interactive blast radius map with network lines                 |
| **Pods**             | Full pod table with class, multiplier, CVEs, reachability       |
| **Compliance**       | Tabbed framework view with scores, findings, remediation        |
| **RBAC Audit**       | Cluster-admin, wildcard, exec, secret flags with filtering      |
| **Evidence Vault**   | Hash chain integrity, drift timeline, control pass rates        |
| **Integrations**     | Vanta/Drata provider cards and push history                     |
| **Alerts**           | Alert rules, destinations, recent events                        |
| **Runtime Insights** | In Use vs Dormant CVEs, per-pod charts, confidence scores       |
| **Attack Paths**     | Path visualization with node chains, edge details, remediation  |
| **Settings**         | Scoring weights, scan configuration                             |

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
| `/api/compliance`                 |  GET   | All compliance framework results                              |
| `/api/compliance/framework?name=` |  GET   | Single framework (soc2, eu-cra, pci-dss, hipaa, cis)          |
| `/api/ingest?source=`             |  POST  | Ingest external scanner data (kubescape, kyverno, trivy-sbom) |
| `/api/rbac`                       |  GET   | RBAC audit findings                                           |
| `/api/runtime`                    |  GET   | Runtime in-use insights, noise reduction, profiles            |
| `/api/attackpath`                 |  GET   | Attack path analysis with remediation                         |
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
reflex/
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
│   │   ├── graph.go              # Directed weighted attack graph
│   │   └── analyzer.go           # Dijkstra + remediation + risk reduction
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
│   ├── network/network.go        # Reachability + blast radius
│   ├── scorer/                   # Risk scoring + configurable weights
│   ├── permissions/              # Security context analysis
│   ├── classifier/               # AI workload classifier (14 classes)
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
├── deploy/                       # K8s manifests + Grafana dashboard
├── examples/                     # Sample weights, configs
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

---

## ◈ Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

```bash
# Development setup
git clone https://github.com/plexar-security/plexar.git
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

[Website](https://plexar-security.io) · [Documentation](https://docs.plexar-security.io) · [GitHub](https://github.com/plexar-security/plexar) · [Discord](https://discord.gg/reflex)

</div>
