package ingest

import (
	"encoding/json"
	"fmt"

	"github.com/plexar-io/plexar/internal/types"
)

// kyvernoPolicyReportList is the top-level response from
// `kubectl get policyreports -A -o json`
type kyvernoPolicyReportList struct {
	Items []kyvernoPolicyReport `json:"items"`
}

// kyvernoPolicyReport is a single Kyverno PolicyReport resource
type kyvernoPolicyReport struct {
	Metadata kyvernoMeta          `json:"metadata"`
	Summary  kyvernoSummary       `json:"summary"`
	Results  []kyvernoResult      `json:"results"`
}

type kyvernoMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type kyvernoSummary struct {
	Pass  int `json:"pass"`
	Fail  int `json:"fail"`
	Warn  int `json:"warn"`
	Error int `json:"error"`
	Skip  int `json:"skip"`
}

type kyvernoResult struct {
	Policy    string            `json:"policy"`
	Rule      string            `json:"rule"`
	Result    string            `json:"result"` // pass, fail, warn, error, skip
	Message   string            `json:"message"`
	Severity  string            `json:"severity"` // critical, high, medium, low, info
	Category  string            `json:"category"`
	Scored    bool              `json:"scored"`
	Resources []kyvernoResource `json:"resources"`
}

type kyvernoResource struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	UID        string `json:"uid"`
}

func ingestKyverno(data []byte) (*IngestResult, error) {
	// Try as PolicyReportList first (kubectl get -o json)
	var reportList kyvernoPolicyReportList
	if err := json.Unmarshal(data, &reportList); err == nil && len(reportList.Items) > 0 {
		return parseKyvernoReports(reportList.Items)
	}

	// Try as single PolicyReport
	var singleReport kyvernoPolicyReport
	if err := json.Unmarshal(data, &singleReport); err == nil && len(singleReport.Results) > 0 {
		return parseKyvernoReports([]kyvernoPolicyReport{singleReport})
	}

	// Try as array of PolicyReports
	var reports []kyvernoPolicyReport
	if err := json.Unmarshal(data, &reports); err == nil && len(reports) > 0 {
		return parseKyvernoReports(reports)
	}

	return nil, fmt.Errorf("failed to parse Kyverno PolicyReport JSON: unrecognized format")
}

func parseKyvernoReports(reports []kyvernoPolicyReport) (*IngestResult, error) {
	result := &IngestResult{
		Source: SourceKyverno,
	}

	for _, report := range reports {
		ns := report.Metadata.Namespace

		for _, r := range report.Results {
			severity := r.Severity
			if severity == "" {
				severity = kyvernoSeverityFromPolicy(r.Policy)
			}

			resourceName := ""
			resourceNS := ns
			if len(r.Resources) > 0 {
				resourceName = r.Resources[0].Kind + "/" + r.Resources[0].Name
				if r.Resources[0].Namespace != "" {
					resourceNS = r.Resources[0].Namespace
				}
			}

			status := normalizeKyvernoStatus(r.Result)

			finding := ExternalFinding{
				Source:    SourceKyverno,
				Category: kyvernoCategory(r.Category),
				Severity: severity,
				Resource: resourceName,
				Namespace: resourceNS,
				RuleID:   r.Policy + "/" + r.Rule,
				RuleName: r.Policy + ": " + r.Rule,
				Message:  r.Message,
				Status:   status,
			}

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

	// Convert to ComplianceChecks for integration with Plexar compliance mapper
	result.ComplianceChecks = kyvernoToComplianceChecks(result.Findings)

	return result, nil
}

func normalizeKyvernoStatus(s string) string {
	switch s {
	case "pass":
		return "pass"
	case "fail":
		return "fail"
	case "warn":
		return "warn"
	case "error":
		return "fail"
	case "skip":
		return "skip"
	default:
		return "warn"
	}
}

func kyvernoCategory(cat string) string {
	if cat == "" {
		return "policy-violation"
	}
	return cat
}

func kyvernoSeverityFromPolicy(policy string) string {
	// Map well-known Kyverno policies to severity
	criticalPolicies := []string{
		"disallow-privileged",
		"disallow-host-namespaces",
		"disallow-host-path",
	}
	highPolicies := []string{
		"require-run-as-nonroot",
		"disallow-capabilities",
		"restrict-escalation",
		"disallow-default-serviceaccount",
	}

	for _, p := range criticalPolicies {
		if policy == p {
			return "critical"
		}
	}
	for _, p := range highPolicies {
		if policy == p {
			return "high"
		}
	}
	return "medium"
}

// kyvernoToComplianceChecks converts Kyverno findings to Plexar ComplianceChecks
func kyvernoToComplianceChecks(findings []ExternalFinding) []types.ComplianceCheck {
	// Group by policy
	grouped := make(map[string][]ExternalFinding)
	for _, f := range findings {
		grouped[f.RuleID] = append(grouped[f.RuleID], f)
	}

	var checks []types.ComplianceCheck
	for ruleID, group := range grouped {
		if len(group) == 0 {
			continue
		}

		passCount := 0
		failCount := 0
		for _, f := range group {
			if f.Status == "pass" {
				passCount++
			} else if f.Status == "fail" {
				failCount++
			}
		}

		total := passCount + failCount
		score := 0
		if total > 0 {
			score = (passCount * 100) / total
		}

		status := "pass"
		if failCount > 0 && passCount == 0 {
			status = "fail"
		} else if failCount > 0 {
			status = "partial"
		}

		var findingMessages []string
		for _, f := range group {
			if f.Status == "fail" {
				findingMessages = append(findingMessages, fmt.Sprintf("%s: %s", f.Resource, f.Message))
			}
		}

		checks = append(checks, types.ComplianceCheck{
			ID:        ruleID,
			Name:      group[0].RuleName,
			Status:    status,
			Score:     score,
			Violations: failCount,
			Evidence:  fmt.Sprintf("Kyverno: %d pass, %d fail out of %d resources", passCount, failCount, total),
			Findings:  findingMessages,
		})
	}

	return checks
}
