#!/usr/bin/env bash
set -euo pipefail

# ── Reflex Demo Environment Setup ──
# Creates a kind cluster with intentionally vulnerable workloads
# for demonstrating Reflex blast radius scanning and SOC 2 compliance.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLUSTER_NAME="reflex-demo"
NAMESPACE="acme-prod"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}ℹ${NC}  $*"; }
ok()    { echo -e "${GREEN}✅${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC}  $*"; }
fail()  { echo -e "${RED}❌${NC} $*"; exit 1; }

# ── Preflight checks ──
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Reflex Demo Environment Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

command -v kind   >/dev/null 2>&1 || fail "kind not found. Install: brew install kind"
command -v kubectl >/dev/null 2>&1 || fail "kubectl not found. Install: brew install kubectl"

# Check if Trivy is available (optional)
TRIVY_AVAILABLE=false
if command -v trivy >/dev/null 2>&1; then
    TRIVY_AVAILABLE=true
    ok "Trivy found: $(trivy --version 2>/dev/null | head -1)"
else
    warn "Trivy not found — scans will use --vuln-source=none (blast radius only)"
    warn "Install Trivy for full CVE scanning: brew install trivy"
fi

# ── Create kind cluster ──
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    info "Cluster '${CLUSTER_NAME}' already exists, reusing..."
else
    info "Creating kind cluster '${CLUSTER_NAME}'..."
    kind create cluster --config "${SCRIPT_DIR}/kind-config.yaml"
    ok "Cluster created"
fi

# Switch context
kubectl cluster-info --context "kind-${CLUSTER_NAME}" >/dev/null 2>&1
ok "Connected to kind-${CLUSTER_NAME}"

# ── Deploy demo workloads ──
info "Deploying demo workloads to namespace '${NAMESPACE}'..."
kubectl apply -f "${SCRIPT_DIR}/workloads.yaml"
ok "Workloads deployed"

# ── Wait for pods ──
info "Waiting for pods to be ready (timeout 120s)..."
kubectl wait --for=condition=Ready pod --all -n "${NAMESPACE}" --timeout=120s 2>/dev/null || true

POD_COUNT=$(kubectl get pods -n "${NAMESPACE}" --no-headers 2>/dev/null | wc -l | tr -d ' ')
ok "${POD_COUNT} pods running in ${NAMESPACE}"

# ── Show cluster state ──
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Demo Environment Ready"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Cluster:   kind-${CLUSTER_NAME}"
echo "  Namespace: ${NAMESPACE}"
echo "  Pods:      ${POD_COUNT}"
echo ""

kubectl get pods -n "${NAMESPACE}" -o wide --no-headers | while read -r line; do
    echo "    ${line}"
done

echo ""
echo "  NetworkPolicies:"
kubectl get networkpolicies -n "${NAMESPACE}" --no-headers 2>/dev/null | while read -r line; do
    echo "    ${line}"
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Try these commands:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ "${TRIVY_AVAILABLE}" = true ]; then
    echo "  # Full scan with CVE detection"
    echo "  reflex scan --namespace ${NAMESPACE}"
    echo ""
    echo "  # Generate SOC 2 PDF report"
    echo "  reflex scan --namespace ${NAMESPACE} -o soc2-report.pdf"
else
    echo "  # Scan without Trivy (blast radius + RBAC only)"
    echo "  reflex scan --namespace ${NAMESPACE} --vuln-source none"
    echo ""
    echo "  # Generate SOC 2 PDF report"
    echo "  reflex scan --namespace ${NAMESPACE} --vuln-source none -o soc2-report.pdf"
fi

echo ""
echo "  # Start continuous monitoring with dashboard"
echo "  reflex serve --namespace ${NAMESPACE} --scan-interval 1m"
echo ""
echo "  # Generate NetworkPolicies for unprotected pods"
echo "  reflex generate netpol --namespace ${NAMESPACE}"
echo ""
echo "  # JSON output for CI/CD"
echo "  reflex scan --namespace ${NAMESPACE} -o json | jq '.scores[] | {pod: .podName, score: .total, tier}'"
echo ""
echo "  # Tear down when done"
echo "  kind delete cluster --name ${CLUSTER_NAME}"
echo ""
