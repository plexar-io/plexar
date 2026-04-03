package ingest

import (
	"encoding/json"
	"fmt"
)

// kubescapeResult represents the top-level Kubescape JSON output
type kubescapeResult struct {
	SummaryDetails kubescapeSummary   `json:"summaryDetails"`
	Results        []kubescapeControl `json:"results"`
}

type kubescapeSummary struct {
	Frameworks []kubescapeFramework `json:"frameworks"`
}

type kubescapeFramework struct {
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}

type kubescapeControl struct {
	ControlID string                  `json:"controlID"`
	Name      string                  `json:"name"`
	Status    kubescapeStatus         `json:"status"`
	Rules     []kubescapeRule         `json:"rules"`
	Resources []kubescapeResourceResult `json:"resourceResults"`
}

type kubescapeStatus struct {
	Status    string `json:"status"`
	SubStatus string `json:"subStatus"`
}

type kubescapeRule struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

type kubescapeResourceResult struct {
	ResourceID string                `json:"resourceID"`
	Controls   []kubescapeCtrlResult `json:"controls"`
}

type kubescapeCtrlResult struct {
	ControlID string          `json:"controlID"`
	Name      string          `json:"name"`
	Status    kubescapeStatus `json:"status"`
	Rules     []kubescapeRuleResult `json:"rules"`
}

type kubescapeRuleResult struct {
	Name   string          `json:"name"`
	Status kubescapeStatus `json:"status"`
	Paths  []kubescapePath `json:"paths"`
}

type kubescapePath struct {
	FailedPath string `json:"failedPath"`
	FixPath    string `json:"fixPath"`
	FixCommand string `json:"fixCommand"`
}

func ingestKubescape(data []byte) (*IngestResult, error) {
	var ks kubescapeResult
	if err := json.Unmarshal(data, &ks); err != nil {
		return nil, fmt.Errorf("failed to parse Kubescape JSON: %w", err)
	}

	result := &IngestResult{
		Source: SourceKubescape,
	}

	for _, ctrl := range ks.Results {
		severity := kubescapeSeverity(ctrl.ControlID)
		remediation := ""
		if len(ctrl.Rules) > 0 {
			remediation = ctrl.Rules[0].Remediation
		}

		status := normalizeKubescapeStatus(ctrl.Status.Status)

		finding := ExternalFinding{
			Source:      SourceKubescape,
			Category:    "misconfiguration",
			Severity:    severity,
			RuleID:      ctrl.ControlID,
			RuleName:    ctrl.Name,
			Message:     fmt.Sprintf("Control %s: %s — %s", ctrl.ControlID, ctrl.Name, ctrl.Status.Status),
			Remediation: remediation,
			Status:      status,
		}

		// Expand per-resource findings
		if len(ctrl.Resources) > 0 {
			for _, res := range ctrl.Resources {
				f := finding
				f.Resource = res.ResourceID
				result.Findings = append(result.Findings, f)

				switch status {
				case "pass":
					result.PassCount++
				case "fail":
					result.FailCount++
				default:
					result.WarnCount++
				}
			}
		} else {
			result.Findings = append(result.Findings, finding)
			switch status {
			case "pass":
				result.PassCount++
			case "fail":
				result.FailCount++
			default:
				result.WarnCount++
			}
		}
	}

	result.TotalFindings = len(result.Findings)
	return result, nil
}

func normalizeKubescapeStatus(s string) string {
	switch s {
	case "passed", "pass":
		return "pass"
	case "failed", "fail":
		return "fail"
	case "warning", "warn":
		return "warn"
	case "skipped", "skip":
		return "skip"
	default:
		return "warn"
	}
}

// kubescapeSeverity maps known Kubescape control IDs to severity levels.
// High-numbered controls (C-00xx) are generally higher severity.
func kubescapeSeverity(controlID string) string {
	// Controls known to be critical/high severity
	criticalControls := map[string]bool{
		"C-0002": true, // Exec into container
		"C-0004": true, // Resources memory limit
		"C-0009": true, // Resource limits
		"C-0013": true, // Non-root containers
		"C-0016": true, // Allow privilege escalation
		"C-0017": true, // Immutable container filesystem
		"C-0034": true, // Automatic mapping of SA
		"C-0035": true, // Cluster-admin binding
		"C-0038": true, // Host PID/IPC privileges
		"C-0041": true, // HostNetwork access
		"C-0044": true, // Container hostPort
		"C-0046": true, // Insecure capabilities
		"C-0055": true, // Linux hardening
		"C-0057": true, // Privileged container
		"C-0086": true, // CVE exposure
	}

	highControls := map[string]bool{
		"C-0001": true, // Forbidden Container Registries
		"C-0005": true, // API server insecure port
		"C-0007": true, // Data Destruction
		"C-0012": true, // Applications credentials in config
		"C-0014": true, // Access K8s dashboard
		"C-0015": true, // List K8s secrets
		"C-0018": true, // Configured readiness probe
		"C-0020": true, // Mount service principal
		"C-0021": true, // Exposed sensitive interfaces
		"C-0026": true, // Kubernetes CronJob
		"C-0030": true, // Ingress and Egress blocked
		"C-0036": true, // Validate admission controller
		"C-0037": true, // CoreDNS poisoning
		"C-0042": true, // SSH server running
		"C-0045": true, // Writable hostPath mount
		"C-0048": true, // HostPath mount
		"C-0056": true, // Configured liveness probe
		"C-0058": true, // CVE-2022-0185
	}

	if criticalControls[controlID] {
		return "critical"
	}
	if highControls[controlID] {
		return "high"
	}
	return "medium"
}
