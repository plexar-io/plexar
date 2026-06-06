package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/plexar-io/plexar/internal/types"
)

// Colors
var (
	colorPass    = [3]int{34, 139, 34}   // forest green
	colorPartial = [3]int{218, 165, 32}  // goldenrod
	colorFail    = [3]int{200, 30, 30}   // red
	colorHeader  = [3]int{25, 25, 112}   // midnight blue
	colorSubHead = [3]int{70, 70, 70}    // dark gray
	colorLight   = [3]int{245, 245, 245} // light gray bg
	colorWhite   = [3]int{255, 255, 255}
	colorBlack   = [3]int{0, 0, 0}
)

// GenerateSOC2PDF creates a multi-page SOC 2 compliance PDF report
func GenerateSOC2PDF(result *types.ScanResult, outputPath string) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 20)

	// Extract SOC 2 result
	var soc2 *types.ComplianceResult
	for i := range result.Compliance {
		if result.Compliance[i].Framework == "SOC 2" {
			soc2 = &result.Compliance[i]
			break
		}
	}
	if soc2 == nil {
		return fmt.Errorf("no SOC 2 compliance data found in scan result")
	}

	// Page 1: Cover
	renderCoverPage(pdf, result, soc2)

	// Pages 2+: Each control gets its own section
	for _, control := range soc2.Controls {
		renderControlPage(pdf, control, result)
	}

	// Final page: Top 5 blast radius pods
	renderBlastRadiusPage(pdf, result)

	return pdf.OutputFileAndClose(outputPath)
}

// ── Cover Page ──

func renderCoverPage(pdf *fpdf.Fpdf, result *types.ScanResult, soc2 *types.ComplianceResult) {
	pdf.AddPage()

	// Title block
	pdf.SetFillColor(colorHeader[0], colorHeader[1], colorHeader[2])
	pdf.Rect(0, 0, 210, 80, "F")

	pdf.SetTextColor(colorWhite[0], colorWhite[1], colorWhite[2])
	pdf.SetFont("Helvetica", "B", 28)
	pdf.SetY(18)
	pdf.CellFormat(190, 14, "SOC 2 Compliance Report", "", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "", 14)
	pdf.CellFormat(190, 8, "Trust Service Criteria Assessment", "", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "", 11)
	pdf.CellFormat(190, 6, fmt.Sprintf("Generated: %s", result.ScanTime.Format("January 2, 2006 at 3:04 PM MST")), "", 1, "C", false, 0, "")
	pdf.CellFormat(190, 6, "Powered by Plexar — Kubernetes Blast Radius Intelligence", "", 1, "C", false, 0, "")

	// Cluster metadata
	pdf.SetTextColor(colorBlack[0], colorBlack[1], colorBlack[2])
	pdf.SetY(90)
	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(190, 8, "Cluster Information", "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 11)
	metaItems := [][]string{
		{"Cluster", result.ClusterName},
		{"Namespace", result.Namespace},
		{"Pods Scanned", fmt.Sprintf("%d", result.TotalPods)},
		{"NetworkPolicies", fmt.Sprintf("%d", result.NetworkPolicies)},
		{"Cluster Risk Score", fmt.Sprintf("%d/100", result.ClusterScore)},
		{"Scan Time", result.ScanTime.Format(time.RFC3339)},
	}
	for _, item := range metaItems {
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(50, 6, item[0]+":", "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		pdf.CellFormat(140, 6, item[1], "", 1, "L", false, 0, "")
	}

	// Overall compliance status
	pdf.Ln(6)
	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(190, 8, "Compliance Summary", "", 1, "L", false, 0, "")

	overallStatus := "PASS"
	statusColor := colorPass
	if soc2.Score < 40 {
		overallStatus = "FAIL"
		statusColor = colorFail
	} else if soc2.Score < 80 {
		overallStatus = "NEEDS ATTENTION"
		statusColor = colorPartial
	}

	// Big score box
	pdf.SetFillColor(statusColor[0], statusColor[1], statusColor[2])
	pdf.SetTextColor(colorWhite[0], colorWhite[1], colorWhite[2])
	pdf.SetFont("Helvetica", "B", 24)
	boxX := 15.0
	pdf.SetX(boxX)
	pdf.CellFormat(50, 20, fmt.Sprintf("%d%%", soc2.Score), "0", 0, "C", true, 0, "")

	pdf.SetX(boxX + 55)
	pdf.SetTextColor(colorBlack[0], colorBlack[1], colorBlack[2])
	pdf.SetFont("Helvetica", "B", 16)
	pdf.CellFormat(80, 10, overallStatus, "", 0, "L", false, 0, "")
	pdf.Ln(12)
	pdf.SetX(boxX + 55)
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(80, 6, fmt.Sprintf("%d controls assessed | %d passing | %d require action",
		soc2.TotalChecks, soc2.Passing, soc2.TotalChecks-soc2.Passing), "", 1, "L", false, 0, "")

	// Control summary table
	pdf.Ln(8)
	renderControlSummaryTable(pdf, soc2.Controls)

	// RBAC summary
	if len(result.RBACFindings) > 0 {
		pdf.Ln(6)
		pdf.SetFont("Helvetica", "B", 12)
		pdf.SetTextColor(colorHeader[0], colorHeader[1], colorHeader[2])
		pdf.CellFormat(190, 7, "RBAC Audit Summary", "", 1, "L", false, 0, "")
		pdf.SetTextColor(colorBlack[0], colorBlack[1], colorBlack[2])

		critical, high := 0, 0
		for _, f := range result.RBACFindings {
			switch f.RiskLevel {
			case "critical":
				critical++
			case "high":
				high++
			}
		}
		pdf.SetFont("Helvetica", "", 10)
		pdf.CellFormat(190, 5, fmt.Sprintf("%d pods audited | %d critical RBAC risk | %d high RBAC risk",
			len(result.RBACFindings), critical, high), "", 1, "L", false, 0, "")
	}
}

func renderControlSummaryTable(pdf *fpdf.Fpdf, controls []types.ComplianceCheck) {
	// Table header
	pdf.SetFillColor(colorHeader[0], colorHeader[1], colorHeader[2])
	pdf.SetTextColor(colorWhite[0], colorWhite[1], colorWhite[2])
	pdf.SetFont("Helvetica", "B", 9)

	pdf.CellFormat(18, 6, "Control", "1", 0, "C", true, 0, "")
	pdf.CellFormat(80, 6, "Name", "1", 0, "L", true, 0, "")
	pdf.CellFormat(18, 6, "Status", "1", 0, "C", true, 0, "")
	pdf.CellFormat(18, 6, "Score", "1", 0, "C", true, 0, "")
	pdf.CellFormat(25, 6, "Violations", "1", 0, "C", true, 0, "")
	pdf.CellFormat(31, 6, "Findings", "1", 1, "C", true, 0, "")

	pdf.SetFont("Helvetica", "", 8)
	for i, c := range controls {
		// Alternate row colors
		if i%2 == 0 {
			pdf.SetFillColor(colorLight[0], colorLight[1], colorLight[2])
		} else {
			pdf.SetFillColor(colorWhite[0], colorWhite[1], colorWhite[2])
		}

		pdf.SetTextColor(colorBlack[0], colorBlack[1], colorBlack[2])
		pdf.CellFormat(18, 5, c.ID, "1", 0, "C", true, 0, "")

		// Truncate name if needed
		name := c.Name
		if len(name) > 48 {
			name = name[:45] + "..."
		}
		pdf.CellFormat(80, 5, name, "1", 0, "L", true, 0, "")

		// Status with color
		sc := statusColor(c.Status)
		pdf.SetTextColor(sc[0], sc[1], sc[2])
		pdf.SetFont("Helvetica", "B", 8)
		pdf.CellFormat(18, 5, strings.ToUpper(c.Status), "1", 0, "C", true, 0, "")

		pdf.SetTextColor(colorBlack[0], colorBlack[1], colorBlack[2])
		pdf.SetFont("Helvetica", "", 8)
		pdf.CellFormat(18, 5, fmt.Sprintf("%d/100", c.Score), "1", 0, "C", true, 0, "")
		pdf.CellFormat(25, 5, fmt.Sprintf("%d", c.Violations), "1", 0, "C", true, 0, "")

		findingsCount := 0
		if c.Findings != nil {
			findingsCount = len(c.Findings)
		}
		pdf.CellFormat(31, 5, fmt.Sprintf("%d", findingsCount), "1", 1, "C", true, 0, "")
	}
}

// ── Control Detail Pages ──

func renderControlPage(pdf *fpdf.Fpdf, control types.ComplianceCheck, result *types.ScanResult) {
	pdf.AddPage()

	// Control header bar
	sc := statusColor(control.Status)
	pdf.SetFillColor(sc[0], sc[1], sc[2])
	pdf.Rect(0, 10, 6, 15, "F")

	pdf.SetTextColor(colorHeader[0], colorHeader[1], colorHeader[2])
	pdf.SetFont("Helvetica", "B", 16)
	pdf.SetX(10)
	pdf.CellFormat(180, 8, fmt.Sprintf("%s — %s", control.ID, control.Name), "", 1, "L", false, 0, "")

	// Status / Score row
	pdf.SetX(10)
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(sc[0], sc[1], sc[2])
	pdf.CellFormat(40, 7, fmt.Sprintf("Status: %s", strings.ToUpper(control.Status)), "", 0, "L", false, 0, "")

	pdf.SetTextColor(colorBlack[0], colorBlack[1], colorBlack[2])
	pdf.SetFont("Helvetica", "", 12)
	pdf.CellFormat(40, 7, fmt.Sprintf("Score: %d/100", control.Score), "", 0, "L", false, 0, "")
	pdf.CellFormat(40, 7, fmt.Sprintf("Violations: %d", control.Violations), "", 1, "L", false, 0, "")

	pdf.Ln(4)

	// Evidence section
	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetTextColor(colorSubHead[0], colorSubHead[1], colorSubHead[2])
	pdf.CellFormat(190, 6, "Evidence", "", 1, "L", false, 0, "")
	pdf.SetTextColor(colorBlack[0], colorBlack[1], colorBlack[2])

	if control.Evidence != "" {
		pdf.SetFont("Helvetica", "", 9)
		pdf.MultiCell(185, 4.5, control.Evidence, "", "L", false)
		pdf.Ln(2)
	}

	if len(control.EvidenceItems) > 0 {
		pdf.SetFont("Helvetica", "", 9)
		for _, item := range control.EvidenceItems {
			pdf.SetX(15)
			pdf.CellFormat(4, 4.5, "\u2022", "", 0, "L", false, 0, "")
			pdf.MultiCell(171, 4.5, item, "", "L", false)
		}
		pdf.Ln(2)
	}

	// Findings section
	if len(control.Findings) > 0 {
		pdf.SetFont("Helvetica", "B", 11)
		pdf.SetTextColor(colorSubHead[0], colorSubHead[1], colorSubHead[2])
		pdf.CellFormat(190, 6, fmt.Sprintf("Findings (%d)", len(control.Findings)), "", 1, "L", false, 0, "")
		pdf.SetTextColor(colorBlack[0], colorBlack[1], colorBlack[2])

		pdf.SetFont("Helvetica", "", 8)
		for i, finding := range control.Findings {
			if i >= 15 {
				pdf.SetX(15)
				pdf.CellFormat(175, 4, fmt.Sprintf("... and %d more findings", len(control.Findings)-15), "", 1, "L", false, 0, "")
				break
			}

			// Color-code by severity prefix
			fc := findingColor(finding)
			pdf.SetTextColor(fc[0], fc[1], fc[2])
			pdf.SetX(15)
			pdf.MultiCell(171, 4, finding, "", "L", false)
		}
		pdf.SetTextColor(colorBlack[0], colorBlack[1], colorBlack[2])
		pdf.Ln(2)
	}

	// Remediation section
	if control.Remediation != "" {
		pdf.SetFont("Helvetica", "B", 11)
		pdf.SetTextColor(colorSubHead[0], colorSubHead[1], colorSubHead[2])
		pdf.CellFormat(190, 6, "Remediation", "", 1, "L", false, 0, "")

		pdf.SetFillColor(240, 248, 255)
		pdf.SetTextColor(colorBlack[0], colorBlack[1], colorBlack[2])
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetX(12)
		pdf.MultiCell(183, 4.5, control.Remediation, "1", "L", true)
		pdf.Ln(2)
	}
}

// ── Blast Radius Page ──

func renderBlastRadiusPage(pdf *fpdf.Fpdf, result *types.ScanResult) {
	pdf.AddPage()

	pdf.SetTextColor(colorHeader[0], colorHeader[1], colorHeader[2])
	pdf.SetFont("Helvetica", "B", 16)
	pdf.CellFormat(190, 10, "Top 5 Highest Blast Radius Pods", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	// Sort by score descending (already sorted, but ensure)
	sorted := make([]types.PlexarScore, len(result.Scores))
	copy(sorted, result.Scores)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Total > sorted[j].Total
	})

	limit := 5
	if len(sorted) < limit {
		limit = len(sorted)
	}

	// Table header
	pdf.SetFillColor(colorHeader[0], colorHeader[1], colorHeader[2])
	pdf.SetTextColor(colorWhite[0], colorWhite[1], colorWhite[2])
	pdf.SetFont("Helvetica", "B", 9)

	pdf.CellFormat(10, 6, "#", "1", 0, "C", true, 0, "")
	pdf.CellFormat(45, 6, "Pod", "1", 0, "L", true, 0, "")
	pdf.CellFormat(18, 6, "Score", "1", 0, "C", true, 0, "")
	pdf.CellFormat(18, 6, "Tier", "1", 0, "C", true, 0, "")
	pdf.CellFormat(25, 6, "CVEs (C/H)", "1", 0, "C", true, 0, "")
	pdf.CellFormat(25, 6, "Blast", "1", 0, "C", true, 0, "")
	pdf.CellFormat(49, 6, "Image", "1", 1, "L", true, 0, "")

	pdf.SetFont("Helvetica", "", 8)
	for i := 0; i < limit; i++ {
		s := sorted[i]

		if i%2 == 0 {
			pdf.SetFillColor(colorLight[0], colorLight[1], colorLight[2])
		} else {
			pdf.SetFillColor(colorWhite[0], colorWhite[1], colorWhite[2])
		}

		// Tier color
		tc := tierColor(s.Tier)
		pdf.SetTextColor(colorBlack[0], colorBlack[1], colorBlack[2])
		pdf.CellFormat(10, 7, fmt.Sprintf("%d", i+1), "1", 0, "C", true, 0, "")

		podName := shortPodName(s.PodName)
		if len(podName) > 28 {
			podName = podName[:25] + "..."
		}
		pdf.CellFormat(45, 7, podName, "1", 0, "L", true, 0, "")

		pdf.SetTextColor(tc[0], tc[1], tc[2])
		pdf.SetFont("Helvetica", "B", 8)
		pdf.CellFormat(18, 7, fmt.Sprintf("%d", s.Total), "1", 0, "C", true, 0, "")
		pdf.CellFormat(18, 7, s.Tier, "1", 0, "C", true, 0, "")

		pdf.SetTextColor(colorBlack[0], colorBlack[1], colorBlack[2])
		pdf.SetFont("Helvetica", "", 8)
		pdf.CellFormat(25, 7, fmt.Sprintf("%dC/%dH", s.Vulns.Critical, s.Vulns.High), "1", 0, "C", true, 0, "")

		blastStr := fmt.Sprintf("%d svc", len(s.Blast.ReachableTargets))
		if s.Blast.InternetAccess {
			blastStr += "+inet"
		}
		pdf.CellFormat(25, 7, blastStr, "1", 0, "C", true, 0, "")

		img := s.ImageName
		if len(img) > 30 {
			img = img[:27] + "..."
		}
		pdf.CellFormat(49, 7, img, "1", 1, "L", true, 0, "")
	}

	// Pod details
	pdf.Ln(6)
	for i := 0; i < limit; i++ {
		s := sorted[i]
		pdf.SetFont("Helvetica", "B", 10)
		tc := tierColor(s.Tier)
		pdf.SetTextColor(tc[0], tc[1], tc[2])
		pdf.CellFormat(190, 6, fmt.Sprintf("#%d  %s — Score: %d/100 (%s)", i+1, shortPodName(s.PodName), s.Total, s.Tier), "", 1, "L", false, 0, "")

		pdf.SetTextColor(colorBlack[0], colorBlack[1], colorBlack[2])
		pdf.SetFont("Helvetica", "", 8)

		details := []string{
			fmt.Sprintf("Image: %s", s.ImageName),
			fmt.Sprintf("CVEs: %d critical, %d high, %d medium (%d total, %d fixable)", s.Vulns.Critical, s.Vulns.High, s.Vulns.Medium, s.Vulns.TotalCount, s.Vulns.FixableCount),
			fmt.Sprintf("Blast radius: %d reachable services | Internet: %v | NetworkPolicy: %v", len(s.Blast.ReachableTargets), s.Blast.InternetAccess, s.Blast.HasNetworkPolicy),
			fmt.Sprintf("Privileged: %v | Root: %v | Read-only FS: %v", s.Permissions.Privileged, s.Permissions.RunAsRoot, s.Permissions.ReadOnlyRootFS),
		}
		for _, d := range details {
			pdf.SetX(15)
			pdf.CellFormat(175, 4, d, "", 1, "L", false, 0, "")
		}

		// Recommendations
		if len(s.Recommendations) > 0 {
			pdf.SetFont("Helvetica", "I", 8)
			for _, rec := range s.Recommendations {
				if rec.Priority == "critical" || rec.Priority == "high" {
					pdf.SetX(15)
					pdf.CellFormat(175, 4, fmt.Sprintf("[%s] %s", rec.Priority, rec.Title), "", 1, "L", false, 0, "")
				}
			}
		}
		pdf.Ln(3)
	}

	// Footer
	pdf.Ln(6)
	pdf.SetFont("Helvetica", "I", 8)
	pdf.SetTextColor(colorSubHead[0], colorSubHead[1], colorSubHead[2])
	pdf.CellFormat(190, 4, fmt.Sprintf("Report generated by Plexar v1.0 on %s", time.Now().Format("2006-01-02 15:04:05 MST")), "", 1, "C", false, 0, "")
	pdf.CellFormat(190, 4, "This report is intended for SOC 2 Type II audit evidence. All data sourced from live Kubernetes cluster scan.", "", 1, "C", false, 0, "")
}

// ── Helpers ──

func statusColor(status string) [3]int {
	switch status {
	case "pass":
		return colorPass
	case "partial":
		return colorPartial
	case "fail":
		return colorFail
	default:
		return colorBlack
	}
}

func tierColor(tier string) [3]int {
	switch tier {
	case "critical":
		return colorFail
	case "high":
		return [3]int{200, 100, 0}
	case "medium":
		return colorPartial
	default:
		return colorPass
	}
}

func findingColor(finding string) [3]int {
	upper := strings.ToUpper(finding)
	if strings.HasPrefix(upper, "CRITICAL:") {
		return colorFail
	}
	if strings.HasPrefix(upper, "HIGH:") {
		return [3]int{200, 100, 0}
	}
	if strings.HasPrefix(upper, "MEDIUM:") {
		return colorPartial
	}
	return colorBlack
}

func shortPodName(name string) string {
	parts := strings.Split(name, "-")
	if len(parts) > 2 {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return name
}
