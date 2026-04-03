package scanner

import (
	"context"
	"fmt"
	"sort"

	"github.com/plexar-security/plexar/internal/types"
	"github.com/plexar-security/plexar/pkg/k8s"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var vulnReportGVR = schema.GroupVersionResource{
	Group:    "aquasecurity.github.io",
	Version:  "v1alpha1",
	Resource: "vulnerabilityreports",
}

// TrivyOperatorScanner reads existing Trivy Operator VulnerabilityReport CRDs.
// Use this when Trivy Operator is already installed in the cluster.
type TrivyOperatorScanner struct{}

func (t *TrivyOperatorScanner) Name() string { return "trivy-operator" }

// ScanNamespace reads all VulnerabilityReports in the namespace and returns per-pod summaries
func (t *TrivyOperatorScanner) ScanNamespace(ctx context.Context, client *k8s.Client, namespace string) ([]types.VulnSummary, error) {
	reports, err := client.DynamicClient.Resource(vulnReportGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list VulnerabilityReports: %w", err)
	}

	podVulns := make(map[string]*types.VulnSummary)

	for _, report := range reports.Items {
		labels := report.GetLabels()
		podName := labels["trivy-operator.resource.name"]
		if podName == "" {
			continue
		}

		spec, ok := report.Object["report"].(map[string]interface{})
		if !ok {
			continue
		}

		vulnsRaw, ok := spec["vulnerabilities"].([]interface{})
		if !ok {
			continue
		}

		summary, exists := podVulns[podName]
		if !exists {
			imageName := ""
			if artifact, ok := spec["artifact"].(map[string]interface{}); ok {
				if repo, ok := artifact["repository"].(string); ok {
					tag := ""
					if t, ok := artifact["tag"].(string); ok {
						tag = t
					}
					imageName = repo + ":" + tag
				}
			}
			summary = &types.VulnSummary{
				PodName:   podName,
				ImageName: imageName,
			}
			podVulns[podName] = summary
		}

		for _, v := range vulnsRaw {
			vuln, ok := v.(map[string]interface{})
			if !ok {
				continue
			}

			severity, _ := vuln["severity"].(string)
			switch severity {
			case "CRITICAL":
				summary.Critical++
			case "HIGH":
				summary.High++
			case "MEDIUM":
				summary.Medium++
			case "LOW":
				summary.Low++
			}
			summary.TotalCount++

			if fixedVersion, ok := vuln["fixedVersion"].(string); ok && fixedVersion != "" {
				summary.FixableCount++
			}

			// Collect top CVEs (up to 10)
			if len(summary.TopCVEs) < 10 && (severity == "CRITICAL" || severity == "HIGH") {
				cvss := 0.0
				if score, ok := vuln["score"].(float64); ok {
					cvss = score
				}
				pkg := ""
				if p, ok := vuln["resource"].(string); ok {
					pkg = p
				}
				fixVer := ""
				if fv, ok := vuln["fixedVersion"].(string); ok {
					fixVer = fv
				}
				cveID, _ := vuln["vulnerabilityID"].(string)
				pubDate, _ := vuln["publishedDate"].(string)

				summary.TopCVEs = append(summary.TopCVEs, types.CVEInfo{
					ID:            cveID,
					Severity:      severity,
					CVSS:          cvss,
					Package:       pkg,
					FixedVersion:  fixVer,
					PublishedDate: pubDate,
				})
			}
		}
	}

	var results []types.VulnSummary
	for _, summary := range podVulns {
		sort.Slice(summary.TopCVEs, func(i, j int) bool {
			return summary.TopCVEs[i].CVSS > summary.TopCVEs[j].CVSS
		})
		results = append(results, *summary)
	}

	return results, nil
}
