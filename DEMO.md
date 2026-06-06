# Plexar — Deploy on a Kubernetes Cluster

Step-by-step guide to run Plexar on a real Kubernetes cluster.

---

## Prerequisites

| Tool | Install | Verify |
|------|---------|--------|
| **kubectl** | `brew install kubectl` | `kubectl version --client` |
| **Cluster access** | Any K8s cluster (EKS, GKE, AKS, self-managed) | `kubectl get nodes` |
| **Go 1.22+** | [go.dev/dl](https://go.dev/dl/) | `go version` |
| **Trivy** _(optional)_ | `brew install trivy` | `trivy version` |

> You need `kubectl` configured and pointing at your cluster. Verify with `kubectl cluster-info`.

---

## Step 1 — Install Plexar

### Option A: Build from source

```bash
git clone https://github.com/plexar-io/plexar.git
cd plexar
go build -o plexar .
sudo mv plexar /usr/local/bin/   # optional: put on PATH
```

### Option B: Go install

```bash
go install github.com/plexar-io/plexar@latest
```

### Option C: Helm (runs inside the cluster)

```bash
helm repo add plexar https://charts.plexar.io
helm install plexar plexar/plexar \
  --namespace plexar-system --create-namespace \
  --set config.targetNamespace=production \
  --set config.scanInterval=5m
```

---

## Step 2 — Verify Cluster Access

```bash
# Confirm you're pointing at the right cluster
kubectl cluster-info
kubectl get namespaces

# List pods in your target namespace
kubectl get pods -n <your-namespace>
```

---

## Step 3 — Choose Your Vulnerability Source

Plexar supports three vulnerability scanning modes:

| Mode | Flag | What it does | When to use |
|------|------|-------------|-------------|
| **Trivy binary** | `--vuln-source trivy` | Runs `trivy image` against every container image | You have `trivy` installed locally and want fresh scans |
| **Trivy Operator** | `--vuln-source trivy-operator` | Reads existing `VulnerabilityReport` CRDs from the cluster | Trivy Operator is already deployed in your cluster |
| **None** | `--vuln-source none` | Skips CVE scanning entirely | You only want blast radius, RBAC, and network analysis |

### Check if Trivy Operator is installed

```bash
kubectl get crd vulnerabilityreports.aquasecurity.github.io 2>/dev/null && echo "✅ Trivy Operator CRDs found" || echo "❌ Not installed"
kubectl get vulnerabilityreports -n <your-namespace> --no-headers 2>/dev/null | wc -l
```

### Install Trivy Operator (if not present)

```bash
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm install trivy-operator aqua/trivy-operator \
  --namespace trivy-system --create-namespace \
  --set trivy.ignoreUnfixed=true
```

Wait a few minutes for it to generate vulnerability reports for your pods.

---

## Step 4 — Run a One-Shot Scan

```bash
plexar scan \
  --namespace <your-namespace> \
  --vuln-source trivy-operator
```

This outputs a ranked table showing every pod's blast radius score, CVE counts, network reachability, runtime "in use" status, and compliance mapping.

### Export reports

```bash
# JSON (for piping to other tools)
plexar scan -n <your-namespace> --vuln-source trivy-operator -o json

# CSV
plexar scan -n <your-namespace> --vuln-source trivy-operator -o csv

# SOC 2 compliance PDF
plexar scan -n <your-namespace> --vuln-source trivy-operator -o soc2-report.pdf

# EU AI Act Annex IV PDF
plexar scan -n <your-namespace> --vuln-source trivy-operator -o euai-report.pdf

# SARIF (GitHub Security tab)
plexar scan -n <your-namespace> --vuln-source trivy-operator -o sarif
```

### Multi-namespace scan

```bash
# Comma-separated
plexar scan -n production,staging,monitoring --vuln-source trivy-operator

# All non-system namespaces
plexar scan --all-namespaces --vuln-source trivy-operator
```

---

## Step 5 — Start the Dashboard

```bash
plexar serve \
  --namespace <your-namespace> \
  --vuln-source trivy-operator \
  --scan-interval 5m \
  -p 8080
```

Open **http://localhost:8080** in your browser.

### Dashboard pages

| Page | What it shows |
|------|---------------|
| **Dashboard** | Cluster risk score, top blast radius pods, exploit chain summary with break-the-chain fix, compliance overview |
| **Topology** | Interactive force-directed network graph — configured vs actual access, per-pod blast radius |
| **Pods** | Full pod table with CVEs, reachability, runtime in-use status, workload class, risk tier |
| **Compliance** | SOC 2, PCI DSS, HIPAA, EU CRA control mapping with per-control scores and evidence |
| **CVEs** | All vulnerabilities with **In Use** / **Dormant** runtime tagging |
| **RBAC** | Audit findings — cluster-admin bindings, secret access, privilege escalation risks |
| **Runtime** | Runtime "in use" CVE filtering with noise reduction metric (typically 90%+) |
| **Attack Paths** | Shortest-path analysis: internet → exposed pod → RBAC escalation → cluster-admin → secrets |
| **Evidence Vault** | Tamper-evident hash-chained compliance evidence with drift detection |
| **Settings** | Scoring weight tuning |

### Production flags

```bash
plexar serve \
  --namespace production \
  --vuln-source trivy-operator \
  --scan-interval 5m \
  --bind 0.0.0.0 -p 8080 \
  --alert-slack-url "$SLACK_WEBHOOK" \
  --vanta-token "$VANTA_TOKEN" \
  --drata-key "$DRATA_KEY" \
  --evidence-sink "s3://key:secret@minio:9000/evidence" \
  --hubble-relay hubble-relay.kube-system:4245 \
  --oidc-issuer "https://accounts.google.com"
```

| Flag | Purpose |
|------|---------|
| `--scan-interval` | How often to re-scan (e.g., `5m`, `1h`, `24h`) |
| `--vuln-source` | `trivy`, `trivy-operator`, or `none` |
| `--alert-slack-url` | Slack webhook for drift/threshold alerts |
| `--vanta-token` | Push compliance evidence to Vanta |
| `--drata-key` | Push compliance evidence to Drata |
| `--evidence-sink` | External evidence storage (S3/MinIO or webhook) |
| `--hubble-relay` | Cilium Hubble Relay address for observed network flows |
| `--oidc-issuer` | OIDC provider for dashboard authentication |

---

## Step 6 — Explore the API

While `plexar serve` is running:

```bash
# Core scan results
curl http://localhost:8080/api/scan | jq '.clusterScore, .totalPods'

# Exploit chains (CVE-type-aware attack chains)
curl http://localhost:8080/api/chains | jq '.summary'

# Attack paths (internet → critical assets)
curl http://localhost:8080/api/attackpath | jq '.totalPaths, .criticalPaths'

# Runtime "in use" insights
curl http://localhost:8080/api/runtime | jq '.noiseReduction'

# Compliance scores
curl http://localhost:8080/api/compliance | jq '.[].framework, .[].score'

# RBAC audit
curl http://localhost:8080/api/rbac | jq 'length'

# Observed Hubble flows
curl http://localhost:8080/api/flows | jq '.totalFlows'

# Evidence vault
curl http://localhost:8080/api/evidence/summary | jq '.'

# Generate NetworkPolicies
curl http://localhost:8080/api/netpol | jq '.policies | length'
```

---

## Optional: Cilium Hubble Integration

If your cluster runs [Cilium](https://cilium.io/) with Hubble enabled, Plexar can use **observed pod-to-pod flows** instead of inferred network reachability.

```bash
# Check if Hubble Relay is available
kubectl get svc -n kube-system hubble-relay

# Pass the relay address to Plexar
plexar serve \
  --namespace production \
  --vuln-source trivy-operator \
  --hubble-relay hubble-relay.kube-system:4245
```

This replaces inferred reachability with ground-truth traffic data in the topology graph and exploit chain analysis.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `connection refused` / `no configuration found` | Ensure `kubectl` is configured: `kubectl cluster-info` |
| `port 8080 already in use` | Use a different port: `-p 8090` |
| Dashboard says "Initial scan in progress" | Use `--vuln-source trivy-operator` (reading CRDs is instant vs. `trivy` binary scanning every image) |
| No vulnerability data | Verify Trivy Operator reports exist: `kubectl get vulnerabilityreports -n <ns>` |
| `forbidden` errors on scan | Plexar needs RBAC read access — ensure your kubeconfig has permissions to list pods, services, secrets, roles, and CRDs |
| Slow scans with `--vuln-source trivy` | Trivy pulls vulnerability DBs and scans each image. Use `trivy-operator` for pre-computed results |
| No Hubble flow data | Hubble Relay must be accessible. Check: `kubectl port-forward -n kube-system svc/hubble-relay 4245` |
