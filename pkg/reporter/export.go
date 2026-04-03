package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/plexar-security/plexar/internal/types"
)

// ExportJSON writes the full scan result as pretty-printed JSON
func ExportJSON(w io.Writer, result *types.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// ExportCSV writes a flattened per-pod CSV with key risk columns
func ExportCSV(w io.Writer, result *types.ScanResult) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := []string{
		"rank", "pod_name", "service", "namespace", "image",
		"total_score", "tier", "cve_score", "blast_score", "perm_score",
		"policy_gap_score", "sensitivity_score",
		"critical_cves", "high_cves", "medium_cves", "total_cves", "fixable_cves",
		"reachable_services", "configured_targets", "data_stores",
		"has_network_policy", "unrestricted_egress", "internet_access",
		"run_as_root", "privileged", "host_network",
		"top_cve_ids", "top_recommendation",
	}
	if err := cw.Write(header); err != nil {
		return fmt.Errorf("write CSV header: %w", err)
	}

	for i, s := range result.Scores {
		var cveIDs []string
		for j, cve := range s.Vulns.TopCVEs {
			if j >= 5 {
				break
			}
			cveIDs = append(cveIDs, cve.ID)
		}

		topRec := ""
		if len(s.Recommendations) > 0 {
			topRec = fmt.Sprintf("[%s] %s", s.Recommendations[0].Priority, s.Recommendations[0].Title)
		}

		row := []string{
			strconv.Itoa(i + 1),
			s.PodName,
			shortName(s.PodName),
			s.Namespace,
			s.ImageName,
			strconv.Itoa(s.Total),
			s.Tier,
			strconv.Itoa(s.CVEScore),
			strconv.Itoa(s.BlastScore),
			strconv.Itoa(s.PermScore),
			strconv.Itoa(s.PolicyGapScore),
			strconv.Itoa(s.SensitivityScore),
			strconv.Itoa(s.Vulns.Critical),
			strconv.Itoa(s.Vulns.High),
			strconv.Itoa(s.Vulns.Medium),
			strconv.Itoa(s.Vulns.TotalCount),
			strconv.Itoa(s.Vulns.FixableCount),
			strconv.Itoa(len(s.Blast.ReachableTargets)),
			strconv.Itoa(len(s.Blast.ConfiguredTargets)),
			strings.Join(s.Blast.DataStoreAccess, "; "),
			strconv.FormatBool(s.Blast.HasNetworkPolicy),
			strconv.FormatBool(s.Blast.UnrestrictedEgress),
			strconv.FormatBool(s.Blast.InternetAccess),
			strconv.FormatBool(s.Permissions.RunAsRoot),
			strconv.FormatBool(s.Permissions.Privileged),
			strconv.FormatBool(s.Permissions.HostNetwork),
			strings.Join(cveIDs, "; "),
			topRec,
		}
		if err := cw.Write(row); err != nil {
			return fmt.Errorf("write CSV row %d: %w", i, err)
		}
	}

	return nil
}

// ExportSARIF writes scan results in SARIF format for GitHub Security tab
func ExportSARIF(w io.Writer, result *types.ScanResult) error {
	type SARIFMessage struct {
		Text string `json:"text"`
	}
	type SARIFResult struct {
		RuleID  string      `json:"ruleId"`
		Level   string      `json:"level"`
		Message SARIFMessage `json:"message"`
	}
	type SARIFRun struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"driver"`
		} `json:"tool"`
		Results []SARIFResult `json:"results"`
	}
	type SARIF struct {
		Version string     `json:"version"`
		Schema  string     `json:"$schema"`
		Runs    []SARIFRun `json:"runs"`
	}

	var results []SARIFResult
	for _, s := range result.Scores {
		level := "note"
		if s.Tier == "critical" {
			level = "error"
		} else if s.Tier == "high" {
			level = "warning"
		}

		results = append(results, SARIFResult{
			RuleID: fmt.Sprintf("plexar/blast-radius/%s", s.Tier),
			Level:  level,
			Message: SARIFMessage{
				Text: fmt.Sprintf("%s: blast radius score %d/100, %d critical CVEs, reaches %d services. %s",
					s.PodName, s.Total, s.Vulns.Critical, len(s.Blast.ReachableTargets), s.Roast),
			},
		})
	}

	sarif := SARIF{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
	}

	run := SARIFRun{Results: results}
	run.Tool.Driver.Name = "plexar"
	run.Tool.Driver.Version = "0.1.0"
	sarif.Runs = []SARIFRun{run}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarif)
}
