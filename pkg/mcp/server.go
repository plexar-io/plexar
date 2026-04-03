package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/plexar-security/plexar/internal/types"
	"github.com/plexar-security/plexar/pkg/api"
	"github.com/plexar-security/plexar/pkg/classifier"
	"github.com/plexar-security/plexar/pkg/report"
)

// Server implements a Model Context Protocol (MCP) server over stdio
// that exposes Plexar vulnerability scanning as tools for AI assistants.
type Server struct {
	kubeconfig string
	writer     io.Writer
	reader     io.Reader
}

// NewServer creates an MCP server
func NewServer(kubeconfig string) *Server {
	return &Server{
		kubeconfig: kubeconfig,
		writer:     os.Stdout,
		reader:     os.Stdin,
	}
}

// ── MCP Protocol Types ──

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *mcpError   `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type mcpToolResult struct {
	Content []mcpContent `json:"content"`
	IsError bool         `json:"isError,omitempty"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// Run starts the MCP server, reading JSON-RPC from stdin and writing to stdout
func (s *Server) Run() error {
	decoder := json.NewDecoder(s.reader)
	encoder := json.NewEncoder(s.writer)

	for {
		var req mcpRequest
		if err := decoder.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("decode request: %w", err)
		}

		resp := s.handleRequest(req)
		if err := encoder.Encode(resp); err != nil {
			return fmt.Errorf("encode response: %w", err)
		}
	}
}

func (s *Server) handleRequest(req mcpRequest) mcpResponse {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(req)
	default:
		return mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &mcpError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)},
		}
	}
}

func (s *Server) handleInitialize(req mcpRequest) mcpResponse {
	return mcpResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]bool{},
			},
			"serverInfo": map[string]string{
				"name":    "plexar-mcp",
				"version": "1.0.0",
			},
		},
	}
}

func (s *Server) handleToolsList(req mcpRequest) mcpResponse {
	tools := []mcpToolDef{
		{
			Name:        "scan_namespace",
			Description: "Scan a Kubernetes namespace for vulnerabilities, blast radius, RBAC risks, and compliance. Returns a summary with pod scores, workload classifications, and risk tiers.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"namespace": {
						"type": "string",
						"description": "Kubernetes namespace to scan (default: 'default')"
					}
				}
			}`),
		},
		{
			Name:        "get_pod_risk",
			Description: "Get detailed risk information for a specific pod including CVEs, blast radius, RBAC permissions, workload classification, and remediation recommendations.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"namespace": {
						"type": "string",
						"description": "Kubernetes namespace"
					},
					"pod_name": {
						"type": "string",
						"description": "Pod name or prefix to search for"
					}
				},
				"required": ["pod_name"]
			}`),
		},
		{
			Name:        "check_compliance",
			Description: "Run a SOC 2 compliance check against a namespace. Returns 20 Trust Service Criteria controls with pass/fail status, scores, evidence, and remediation.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"namespace": {
						"type": "string",
						"description": "Kubernetes namespace to assess (default: 'default')"
					},
					"framework": {
						"type": "string",
						"description": "Compliance framework: 'soc2', 'euaiact' (default: 'soc2')"
					}
				}
			}`),
		},
		{
			Name:        "classify_workloads",
			Description: "Classify all workloads in a namespace by type (database, API gateway, auth, cache, ML, payment, etc.) and show risk multipliers applied to each.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"namespace": {
						"type": "string",
						"description": "Kubernetes namespace (default: 'default')"
					}
				}
			}`),
		},
		{
			Name:        "find_critical_cves",
			Description: "Find all critical and high-severity CVEs across pods in a namespace, grouped by severity with fix versions where available.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"namespace": {
						"type": "string",
						"description": "Kubernetes namespace (default: 'default')"
					},
					"min_severity": {
						"type": "string",
						"description": "Minimum severity: 'critical', 'high', 'medium' (default: 'high')"
					}
				}
			}`),
		},
		{
			Name:        "audit_rbac",
			Description: "Audit RBAC permissions in a namespace. Identifies pods with cluster-admin, wildcard access, exec capability, secret access, and other dangerous permissions.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"namespace": {
						"type": "string",
						"description": "Kubernetes namespace (default: 'default')"
					}
				}
			}`),
		},
	}

	return mcpResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  map[string]interface{}{"tools": tools},
	}
}

func (s *Server) handleToolsCall(req mcpRequest) mcpResponse {
	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return mcpResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &mcpError{Code: -32602, Message: "invalid params"},
		}
	}

	var result mcpToolResult
	switch params.Name {
	case "scan_namespace":
		result = s.toolScanNamespace(params.Arguments)
	case "get_pod_risk":
		result = s.toolGetPodRisk(params.Arguments)
	case "check_compliance":
		result = s.toolCheckCompliance(params.Arguments)
	case "classify_workloads":
		result = s.toolClassifyWorkloads(params.Arguments)
	case "find_critical_cves":
		result = s.toolFindCriticalCVEs(params.Arguments)
	case "audit_rbac":
		result = s.toolAuditRBAC(params.Arguments)
	default:
		result = mcpToolResult{
			Content: []mcpContent{{Type: "text", Text: fmt.Sprintf("unknown tool: %s", params.Name)}},
			IsError: true,
		}
	}

	return mcpResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	}
}

// ── Tool Implementations ──

func (s *Server) runScan(ns string) (*types.ScanResult, error) {
	if ns == "" {
		ns = "default"
	}
	return api.RunScan(s.kubeconfig, ns, io.Discard)
}

func (s *Server) toolScanNamespace(args json.RawMessage) mcpToolResult {
	var p struct {
		Namespace string `json:"namespace"`
	}
	json.Unmarshal(args, &p)

	result, err := s.runScan(p.Namespace)
	if err != nil {
		return mcpToolResult{Content: []mcpContent{{Type: "text", Text: fmt.Sprintf("scan failed: %v", err)}}, IsError: true}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "# Scan Results: %s/%s\n\n", result.ClusterName, result.Namespace)
	fmt.Fprintf(&sb, "**Cluster Score:** %d/100\n", result.ClusterScore)
	fmt.Fprintf(&sb, "**Pods:** %d | **NetworkPolicies:** %d\n\n", result.TotalPods, result.NetworkPolicies)

	for _, w := range result.Warnings {
		fmt.Fprintf(&sb, "> ⚠️ %s\n\n", w)
	}

	fmt.Fprintf(&sb, "| Rank | Score | Tier | Pod | Class | CVEs |\n")
	fmt.Fprintf(&sb, "|------|-------|------|-----|-------|------|\n")
	for i, s := range result.Scores {
		wc := s.WorkloadClass
		if wc == "" {
			wc = "—"
		}
		fmt.Fprintf(&sb, "| %d | %d | %s | %s | %s | %dC/%dH |\n",
			i+1, s.Total, s.Tier, shortPod(s.PodName), wc, s.Vulns.Critical, s.Vulns.High)
	}

	return mcpToolResult{Content: []mcpContent{{Type: "text", Text: sb.String()}}}
}

func (s *Server) toolGetPodRisk(args json.RawMessage) mcpToolResult {
	var p struct {
		Namespace string `json:"namespace"`
		PodName   string `json:"pod_name"`
	}
	json.Unmarshal(args, &p)

	result, err := s.runScan(p.Namespace)
	if err != nil {
		return mcpToolResult{Content: []mcpContent{{Type: "text", Text: fmt.Sprintf("scan failed: %v", err)}}, IsError: true}
	}

	// Find matching pod
	var match *types.PlexarScore
	for i, s := range result.Scores {
		if strings.Contains(strings.ToLower(s.PodName), strings.ToLower(p.PodName)) {
			match = &result.Scores[i]
			break
		}
	}
	if match == nil {
		return mcpToolResult{Content: []mcpContent{{Type: "text", Text: fmt.Sprintf("no pod matching '%s' found in namespace %s", p.PodName, p.Namespace)}}, IsError: true}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "# Pod Risk: %s\n\n", match.PodName)
	fmt.Fprintf(&sb, "**Image:** %s\n", match.ImageName)
	fmt.Fprintf(&sb, "**Score:** %d/100 (%s)\n", match.Total, match.Tier)
	if match.WorkloadClass != "" {
		fmt.Fprintf(&sb, "**Class:** %s (×%.2f multiplier, base score: %d)\n", match.WorkloadClass, match.RiskMultiplier, match.BaseScore)
	}
	fmt.Fprintf(&sb, "\n## Score Breakdown\n")
	fmt.Fprintf(&sb, "- CVE: %d | Blast: %d | Permissions: %d | Policy Gap: %d | Sensitivity: %d\n\n",
		match.CVEScore, match.BlastScore, match.PermScore, match.PolicyGapScore, match.SensitivityScore)

	fmt.Fprintf(&sb, "## Vulnerabilities\n")
	fmt.Fprintf(&sb, "- Critical: %d | High: %d | Medium: %d | Total: %d (Fixable: %d)\n\n",
		match.Vulns.Critical, match.Vulns.High, match.Vulns.Medium, match.Vulns.TotalCount, match.Vulns.FixableCount)

	if len(match.Vulns.TopCVEs) > 0 {
		fmt.Fprintf(&sb, "### Top CVEs\n")
		for _, cve := range match.Vulns.TopCVEs[:min(5, len(match.Vulns.TopCVEs))] {
			fix := ""
			if cve.FixedVersion != "" {
				fix = " → " + cve.FixedVersion
			}
			fmt.Fprintf(&sb, "- **%s** %s (CVSS %.1f) %s%s\n", cve.Severity, cve.ID, cve.CVSS, cve.Package, fix)
		}
	}

	fmt.Fprintf(&sb, "\n## Blast Radius\n")
	fmt.Fprintf(&sb, "- Reachable: %d services\n", len(match.Blast.ReachableTargets))
	fmt.Fprintf(&sb, "- NetworkPolicy: %v\n", match.Blast.HasNetworkPolicy)
	fmt.Fprintf(&sb, "- Internet: %v\n", match.Blast.InternetAccess)

	fmt.Fprintf(&sb, "\n## Permissions\n")
	fmt.Fprintf(&sb, "- Root: %v | Privileged: %v | Host Network: %v\n",
		match.Permissions.RunAsRoot, match.Permissions.Privileged, match.Permissions.HostNetwork)

	if len(match.Recommendations) > 0 {
		fmt.Fprintf(&sb, "\n## Recommendations\n")
		for _, r := range match.Recommendations {
			fmt.Fprintf(&sb, "- **[%s]** %s\n", r.Priority, r.Title)
		}
	}

	return mcpToolResult{Content: []mcpContent{{Type: "text", Text: sb.String()}}}
}

func (s *Server) toolCheckCompliance(args json.RawMessage) mcpToolResult {
	var p struct {
		Namespace string `json:"namespace"`
		Framework string `json:"framework"`
	}
	json.Unmarshal(args, &p)

	result, err := s.runScan(p.Namespace)
	if err != nil {
		return mcpToolResult{Content: []mcpContent{{Type: "text", Text: fmt.Sprintf("scan failed: %v", err)}}, IsError: true}
	}

	if p.Framework == "euaiact" {
		annexReport := report.GenerateAnnexIVReport(result)
		var sb strings.Builder
		fmt.Fprintf(&sb, "# EU AI Act Annex IV Assessment: %s/%s\n\n", result.ClusterName, result.Namespace)
		fmt.Fprintf(&sb, "**Overall Score:** %d/100 — %s\n", annexReport.OverallScore, annexReport.RiskLevel)
		fmt.Fprintf(&sb, "**AI Workloads:** %d/%d\n\n", annexReport.AIWorkloads, annexReport.TotalWorkloads)

		fmt.Fprintf(&sb, "| Section | Title | Status | Score | Gaps |\n")
		fmt.Fprintf(&sb, "|---------|-------|--------|-------|------|\n")
		for _, sec := range annexReport.Sections {
			fmt.Fprintf(&sb, "| %s | %s | %s | %d | %d |\n", sec.ID, sec.Title, sec.Status, sec.Score, len(sec.Gaps))
		}
		return mcpToolResult{Content: []mcpContent{{Type: "text", Text: sb.String()}}}
	}

	// Default: SOC 2
	var soc2 *types.ComplianceResult
	for i, c := range result.Compliance {
		if c.Framework == "SOC 2" {
			soc2 = &result.Compliance[i]
			break
		}
	}
	if soc2 == nil {
		return mcpToolResult{Content: []mcpContent{{Type: "text", Text: "no SOC 2 data"}}, IsError: true}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "# SOC 2 Compliance: %s/%s\n\n", result.ClusterName, result.Namespace)
	fmt.Fprintf(&sb, "**Score:** %d/100 | **Passing:** %d/%d\n\n", soc2.Score, soc2.Passing, soc2.TotalChecks)

	fmt.Fprintf(&sb, "| Control | Name | Status | Score |\n")
	fmt.Fprintf(&sb, "|---------|------|--------|-------|\n")
	for _, c := range soc2.Controls {
		fmt.Fprintf(&sb, "| %s | %s | %s | %d |\n", c.ID, c.Name, c.Status, c.Score)
	}

	return mcpToolResult{Content: []mcpContent{{Type: "text", Text: sb.String()}}}
}

func (s *Server) toolClassifyWorkloads(args json.RawMessage) mcpToolResult {
	var p struct {
		Namespace string `json:"namespace"`
	}
	json.Unmarshal(args, &p)

	result, err := s.runScan(p.Namespace)
	if err != nil {
		return mcpToolResult{Content: []mcpContent{{Type: "text", Text: fmt.Sprintf("scan failed: %v", err)}}, IsError: true}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "# Workload Classification: %s/%s\n\n", result.ClusterName, result.Namespace)

	// Group by class
	classes := map[string][]types.PlexarScore{}
	for _, s := range result.Scores {
		wc := s.WorkloadClass
		if wc == "" {
			wc = "General Application"
		}
		classes[wc] = append(classes[wc], s)
	}

	fmt.Fprintf(&sb, "| Pod | Class | Multiplier | Base | Final | Tier |\n")
	fmt.Fprintf(&sb, "|-----|-------|------------|------|-------|------|\n")
	for _, s := range result.Scores {
		wc := s.WorkloadClass
		if wc == "" {
			wc = "General Application"
		}
		fmt.Fprintf(&sb, "| %s | %s | ×%.2f | %d | %d | %s |\n",
			shortPod(s.PodName), wc, s.RiskMultiplier, s.BaseScore, s.Total, s.Tier)
	}

	fmt.Fprintf(&sb, "\n**Available classifiers:** %d types\n", len(classifier.ListClasses()))

	return mcpToolResult{Content: []mcpContent{{Type: "text", Text: sb.String()}}}
}

func (s *Server) toolFindCriticalCVEs(args json.RawMessage) mcpToolResult {
	var p struct {
		Namespace   string `json:"namespace"`
		MinSeverity string `json:"min_severity"`
	}
	json.Unmarshal(args, &p)
	if p.MinSeverity == "" {
		p.MinSeverity = "high"
	}

	result, err := s.runScan(p.Namespace)
	if err != nil {
		return mcpToolResult{Content: []mcpContent{{Type: "text", Text: fmt.Sprintf("scan failed: %v", err)}}, IsError: true}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "# CVE Report: %s/%s (>=%s)\n\n", result.ClusterName, result.Namespace, p.MinSeverity)

	totalCrit, totalHigh := 0, 0
	for _, s := range result.Scores {
		totalCrit += s.Vulns.Critical
		totalHigh += s.Vulns.High
	}
	fmt.Fprintf(&sb, "**Critical:** %d | **High:** %d\n\n", totalCrit, totalHigh)

	fmt.Fprintf(&sb, "| Pod | Severity | CVE | CVSS | Package | Fix |\n")
	fmt.Fprintf(&sb, "|-----|----------|-----|------|---------|-----|\n")
	for _, s := range result.Scores {
		for _, cve := range s.Vulns.TopCVEs {
			sev := strings.ToLower(cve.Severity)
			if p.MinSeverity == "critical" && sev != "critical" {
				continue
			}
			if p.MinSeverity == "high" && sev != "critical" && sev != "high" {
				continue
			}
			fix := cve.FixedVersion
			if fix == "" {
				fix = "—"
			}
			fmt.Fprintf(&sb, "| %s | %s | %s | %.1f | %s | %s |\n",
				shortPod(s.PodName), cve.Severity, cve.ID, cve.CVSS, cve.Package, fix)
		}
	}

	return mcpToolResult{Content: []mcpContent{{Type: "text", Text: sb.String()}}}
}

func (s *Server) toolAuditRBAC(args json.RawMessage) mcpToolResult {
	var p struct {
		Namespace string `json:"namespace"`
	}
	json.Unmarshal(args, &p)

	result, err := s.runScan(p.Namespace)
	if err != nil {
		return mcpToolResult{Content: []mcpContent{{Type: "text", Text: fmt.Sprintf("scan failed: %v", err)}}, IsError: true}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "# RBAC Audit: %s/%s\n\n", result.ClusterName, result.Namespace)
	fmt.Fprintf(&sb, "**Pods audited:** %d\n\n", len(result.RBACFindings))

	if len(result.RBACFindings) == 0 {
		fmt.Fprintf(&sb, "No RBAC findings.\n")
		return mcpToolResult{Content: []mcpContent{{Type: "text", Text: sb.String()}}}
	}

	fmt.Fprintf(&sb, "| Pod | SA | Risk | Flags |\n")
	fmt.Fprintf(&sb, "|-----|----|----- |-------|\n")
	for _, f := range result.RBACFindings {
		flags := strings.Join(f.Flags, ", ")
		if flags == "" {
			flags = "—"
		}
		fmt.Fprintf(&sb, "| %s | %s | %s (%d) | %s |\n",
			shortPod(f.PodName), f.ServiceAccountName, f.RiskLevel, f.RiskScore, flags)
	}

	return mcpToolResult{Content: []mcpContent{{Type: "text", Text: sb.String()}}}
}

func shortPod(name string) string {
	parts := strings.Split(name, "-")
	if len(parts) > 2 {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return name
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
