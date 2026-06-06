package ingest

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/plexar-io/plexar/internal/types"
)

// Supported ingest source formats
const (
	SourceKubescape = "kubescape"
	SourceKyverno   = "kyverno"
	SourceTrivySBOM = "trivy-sbom"
)

// ExternalFinding represents a normalized finding from an external scanner
type ExternalFinding struct {
	Source      string `json:"source"`      // kubescape, kyverno, trivy-sbom
	Category   string `json:"category"`     // vulnerability, misconfiguration, policy-violation, sbom
	Severity   string `json:"severity"`     // critical, high, medium, low, info
	Resource   string `json:"resource"`     // pod/deployment/namespace name
	Namespace  string `json:"namespace"`    // kubernetes namespace
	RuleID     string `json:"ruleId"`       // external rule/control ID
	RuleName   string `json:"ruleName"`     // human-readable rule name
	Message    string `json:"message"`      // finding description
	Remediation string `json:"remediation"` // suggested fix
	Status     string `json:"status"`       // pass, fail, warn, skip
}

// IngestResult is the normalized output of ingesting external scanner data
type IngestResult struct {
	Source           string                 `json:"source"`
	TotalFindings    int                    `json:"totalFindings"`
	PassCount        int                    `json:"passCount"`
	FailCount        int                    `json:"failCount"`
	WarnCount        int                    `json:"warnCount"`
	Findings         []ExternalFinding      `json:"findings"`
	ComplianceChecks []types.ComplianceCheck `json:"complianceChecks,omitempty"`
	SBOMComponents   []SBOMComponent        `json:"sbomComponents,omitempty"`
}

// SBOMComponent represents a software component from an SBOM
type SBOMComponent struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"`     // library, framework, application, os
	PkgType  string `json:"pkgType"`  // npm, pip, gem, go, cargo, apk, deb
	Licenses []string `json:"licenses,omitempty"`
	PodName  string `json:"podName,omitempty"`
}

// Ingest reads scanner output from the given reader and normalizes it
func Ingest(source string, r io.Reader) (*IngestResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}

	source = strings.ToLower(strings.TrimSpace(source))

	switch source {
	case SourceKubescape:
		return ingestKubescape(data)
	case SourceKyverno:
		return ingestKyverno(data)
	case SourceTrivySBOM:
		return ingestTrivySBOM(data)
	default:
		return nil, fmt.Errorf("unsupported source %q (supported: %s, %s, %s)",
			source, SourceKubescape, SourceKyverno, SourceTrivySBOM)
	}
}

// IngestJSON is a convenience wrapper that unmarshals JSON directly
func IngestJSON(source string, data []byte) (*IngestResult, error) {
	source = strings.ToLower(strings.TrimSpace(source))
	switch source {
	case SourceKubescape:
		return ingestKubescape(data)
	case SourceKyverno:
		return ingestKyverno(data)
	case SourceTrivySBOM:
		return ingestTrivySBOM(data)
	default:
		return nil, fmt.Errorf("unsupported source %q", source)
	}
}

// MergeFindings converts external findings into compliance evidence strings
// suitable for appending to EvidenceRecord controls
func MergeFindings(findings []ExternalFinding) []types.ControlEvidence {
	// Group findings by source + ruleID
	grouped := make(map[string][]ExternalFinding)
	for _, f := range findings {
		key := f.Source + "/" + f.RuleID
		grouped[key] = append(grouped[key], f)
	}

	var evidence []types.ControlEvidence
	for _, group := range grouped {
		if len(group) == 0 {
			continue
		}
		first := group[0]
		violations := 0
		for _, f := range group {
			if f.Status == "fail" {
				violations++
			}
		}

		status := "pass"
		if violations > 0 {
			status = "fail"
		}

		evidence = append(evidence, types.ControlEvidence{
			Framework:   "external/" + first.Source,
			ControlID:   first.RuleID,
			ControlName: first.RuleName,
			Status:      status,
			Violations:  violations,
			Evidence:    fmt.Sprintf("%d findings from %s (%d pass, %d fail)", len(group), first.Source, len(group)-violations, violations),
		})
	}

	return evidence
}

// severityFromScore maps a numeric score to a severity string
func severityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score >= 0.1:
		return "low"
	default:
		return "info"
	}
}

// isJSON checks if data looks like JSON
func isJSON(data []byte) bool {
	var js json.RawMessage
	return json.Unmarshal(data, &js) == nil
}
