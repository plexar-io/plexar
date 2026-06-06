package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/plexar-io/plexar/internal/types"
)

// AnnexIVSection represents a section of EU AI Act Annex IV technical documentation
type AnnexIVSection struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Article     string   `json:"article"`
	Status      string   `json:"status"` // documented, partial, gap
	Score       int      `json:"score"`
	Evidence    []string `json:"evidence"`
	Findings    []string `json:"findings"`
	Gaps        []string `json:"gaps"`
	Description string   `json:"description"`
}

// AnnexIVReport is the full EU AI Act Annex IV assessment
type AnnexIVReport struct {
	GeneratedAt    time.Time        `json:"generatedAt"`
	ClusterName    string           `json:"clusterName"`
	Namespace      string           `json:"namespace"`
	AIWorkloads    int              `json:"aiWorkloads"`
	TotalWorkloads int              `json:"totalWorkloads"`
	OverallScore   int              `json:"overallScore"`
	RiskLevel      string           `json:"riskLevel"`
	Sections       []AnnexIVSection `json:"sections"`
}

// GenerateAnnexIVReport builds the EU AI Act Annex IV assessment from scan data
func GenerateAnnexIVReport(result *types.ScanResult) *AnnexIVReport {
	aiPods := []types.PlexarScore{}
	for _, s := range result.Scores {
		if s.WorkloadClass == "ML / AI Workload" {
			aiPods = append(aiPods, s)
		}
	}

	report := &AnnexIVReport{
		GeneratedAt:    time.Now(),
		ClusterName:    result.ClusterName,
		Namespace:      result.Namespace,
		AIWorkloads:    len(aiPods),
		TotalWorkloads: result.TotalPods,
	}

	report.Sections = buildAnnexIVSections(result, aiPods)

	// Compute overall score
	total := 0
	for _, s := range report.Sections {
		total += s.Score
	}
	if len(report.Sections) > 0 {
		report.OverallScore = total / len(report.Sections)
	}

	switch {
	case report.OverallScore >= 70:
		report.RiskLevel = "Acceptable"
	case report.OverallScore >= 40:
		report.RiskLevel = "Needs Attention"
	default:
		report.RiskLevel = "Non-Compliant"
	}

	return report
}

func buildAnnexIVSections(result *types.ScanResult, aiPods []types.PlexarScore) []AnnexIVSection {
	sections := []AnnexIVSection{}

	// Section 1: General Description (Art. 11(1), Annex IV §1)
	sec1 := AnnexIVSection{
		ID:          "AIV.1",
		Title:       "General Description of the AI System",
		Article:     "Annex IV §1",
		Description: "A general description of the AI system including its intended purpose, the persons and entities that developed it, and the date and version.",
	}
	sec1.Evidence = append(sec1.Evidence,
		fmt.Sprintf("Cluster: %s", result.ClusterName),
		fmt.Sprintf("Namespace: %s", result.Namespace),
		fmt.Sprintf("Total workloads: %d", result.TotalPods),
		fmt.Sprintf("AI/ML workloads identified: %d", len(aiPods)),
	)
	for _, p := range aiPods {
		sec1.Evidence = append(sec1.Evidence, fmt.Sprintf("AI workload: %s (image: %s)", shortPodName(p.PodName), p.ImageName))
	}
	if len(aiPods) > 0 {
		sec1.Status = "documented"
		sec1.Score = 80
	} else {
		sec1.Status = "gap"
		sec1.Score = 30
		sec1.Gaps = append(sec1.Gaps, "No AI/ML workloads detected — classification may need manual review")
	}
	sections = append(sections, sec1)

	// Section 2: Detailed Description of Elements and Development Process (Annex IV §2)
	sec2 := AnnexIVSection{
		ID:          "AIV.2",
		Title:       "Elements and Development Process",
		Article:     "Annex IV §2",
		Description: "Detailed description of the elements of the AI system and of the process for its development, including methodologies and techniques used.",
	}
	for _, p := range aiPods {
		sec2.Evidence = append(sec2.Evidence,
			fmt.Sprintf("%s: image=%s, risk_score=%d, class=%s", shortPodName(p.PodName), p.ImageName, p.Total, p.WorkloadClass),
		)
	}
	// Check for CI/CD workloads (development process evidence)
	cicdCount := 0
	for _, s := range result.Scores {
		if s.WorkloadClass == "CI/CD Pipeline" {
			cicdCount++
			sec2.Evidence = append(sec2.Evidence, fmt.Sprintf("CI/CD pipeline: %s (development process)", shortPodName(s.PodName)))
		}
	}
	if cicdCount > 0 {
		sec2.Score = 60
		sec2.Status = "partial"
		sec2.Findings = append(sec2.Findings, fmt.Sprintf("%d CI/CD pipeline(s) detected — development process is partially observable", cicdCount))
	} else {
		sec2.Score = 20
		sec2.Status = "gap"
		sec2.Gaps = append(sec2.Gaps, "No CI/CD pipelines detected in cluster — development process documentation needed externally")
	}
	sections = append(sections, sec2)

	// Section 3: Monitoring, Functioning and Control (Annex IV §3)
	sec3 := AnnexIVSection{
		ID:          "AIV.3",
		Title:       "Monitoring, Functioning and Control",
		Article:     "Annex IV §3",
		Description: "Detailed information about the monitoring, functioning and control of the AI system, including its level of accuracy, robustness, and cybersecurity.",
	}
	monitorCount := 0
	for _, s := range result.Scores {
		if s.WorkloadClass == "Monitoring / Observability" {
			monitorCount++
			sec3.Evidence = append(sec3.Evidence, fmt.Sprintf("Monitoring: %s", shortPodName(s.PodName)))
		}
	}
	sec3.Evidence = append(sec3.Evidence, fmt.Sprintf("NetworkPolicies: %d", result.NetworkPolicies))
	sec3.Evidence = append(sec3.Evidence, fmt.Sprintf("Cluster risk score: %d/100", result.ClusterScore))

	if monitorCount > 0 {
		sec3.Score = 70
		sec3.Status = "partial"
		sec3.Findings = append(sec3.Findings, fmt.Sprintf("%d monitoring workload(s) provide operational observability", monitorCount))
	} else {
		sec3.Score = 25
		sec3.Status = "gap"
		sec3.Gaps = append(sec3.Gaps, "No monitoring/observability workloads detected — Article 14 requires human oversight measures")
	}
	sections = append(sections, sec3)

	// Section 4: Risk Management (Annex IV §4, Art. 9)
	sec4 := AnnexIVSection{
		ID:          "AIV.4",
		Title:       "Risk Management System",
		Article:     "Annex IV §4, Art. 9",
		Description: "Description of the risk management system in accordance with Article 9, including identification and analysis of known and foreseeable risks.",
	}
	criticalPods, highPods := 0, 0
	for _, s := range result.Scores {
		switch s.Tier {
		case "critical":
			criticalPods++
		case "high":
			highPods++
		}
	}
	sec4.Evidence = append(sec4.Evidence,
		fmt.Sprintf("Risk scoring: %d pods assessed with 0-100 blast radius scores", result.TotalPods),
		fmt.Sprintf("Critical-tier pods: %d", criticalPods),
		fmt.Sprintf("High-tier pods: %d", highPods),
		fmt.Sprintf("Cluster risk score: %d/100", result.ClusterScore),
	)

	// RBAC risk evidence
	rbacCritical := 0
	for _, f := range result.RBACFindings {
		if f.RiskLevel == "critical" {
			rbacCritical++
		}
	}
	sec4.Evidence = append(sec4.Evidence, fmt.Sprintf("RBAC critical findings: %d", rbacCritical))

	if result.ClusterScore < 40 {
		sec4.Score = 80
		sec4.Status = "documented"
	} else if result.ClusterScore < 70 {
		sec4.Score = 50
		sec4.Status = "partial"
		sec4.Findings = append(sec4.Findings, "Elevated cluster risk score indicates incomplete risk mitigation")
	} else {
		sec4.Score = 25
		sec4.Status = "gap"
		sec4.Gaps = append(sec4.Gaps, "High cluster risk score — risk management measures insufficient for high-risk AI systems")
	}
	sections = append(sections, sec4)

	// Section 5: Data Governance (Annex IV §5, Art. 10)
	sec5 := AnnexIVSection{
		ID:          "AIV.5",
		Title:       "Data and Data Governance",
		Article:     "Annex IV §5, Art. 10",
		Description: "Description of data governance measures including training, validation and testing data sets, data quality, and any data biases.",
	}
	dbCount := 0
	for _, s := range result.Scores {
		if s.WorkloadClass == "Database" || s.WorkloadClass == "Search Engine" || s.WorkloadClass == "Object Storage" {
			dbCount++
			sec5.Evidence = append(sec5.Evidence, fmt.Sprintf("Data store: %s (%s)", shortPodName(s.PodName), s.WorkloadClass))
		}
	}

	netPolCoverage := 0
	if result.TotalPods > 0 {
		covered := 0
		for _, s := range result.Scores {
			if s.Blast.HasNetworkPolicy {
				covered++
			}
		}
		netPolCoverage = (covered * 100) / result.TotalPods
	}
	sec5.Evidence = append(sec5.Evidence, fmt.Sprintf("Data store network segmentation: %d%% pods have NetworkPolicy", netPolCoverage))

	secretExposed := 0
	for _, f := range result.RBACFindings {
		if f.HasSecretAccess {
			secretExposed++
		}
	}
	sec5.Evidence = append(sec5.Evidence, fmt.Sprintf("Pods with secret access: %d", secretExposed))

	if netPolCoverage >= 80 && secretExposed == 0 {
		sec5.Score = 75
		sec5.Status = "documented"
	} else if netPolCoverage >= 50 {
		sec5.Score = 45
		sec5.Status = "partial"
		sec5.Findings = append(sec5.Findings, "Incomplete network segmentation of data stores")
	} else {
		sec5.Score = 20
		sec5.Status = "gap"
		sec5.Gaps = append(sec5.Gaps, "Insufficient data governance controls — data stores lack network segmentation and access controls")
	}
	sections = append(sections, sec5)

	// Section 6: Cybersecurity (Annex IV §6, Art. 15)
	sec6 := AnnexIVSection{
		ID:          "AIV.6",
		Title:       "Cybersecurity Measures",
		Article:     "Annex IV §6, Art. 15",
		Description: "Description of cybersecurity measures taken, including protection against attempts by unauthorized third parties to exploit vulnerabilities.",
	}
	totalCritCVEs, totalHighCVEs := 0, 0
	for _, s := range result.Scores {
		totalCritCVEs += s.Vulns.Critical
		totalHighCVEs += s.Vulns.High
	}
	privilegedPods := 0
	rootPods := 0
	for _, s := range result.Scores {
		if s.Permissions.Privileged {
			privilegedPods++
		}
		if s.Permissions.RunAsRoot {
			rootPods++
		}
	}
	internetExposed := 0
	for _, s := range result.Scores {
		if s.Blast.InternetAccess {
			internetExposed++
		}
	}

	sec6.Evidence = append(sec6.Evidence,
		fmt.Sprintf("Critical CVEs: %d", totalCritCVEs),
		fmt.Sprintf("High CVEs: %d", totalHighCVEs),
		fmt.Sprintf("Privileged containers: %d", privilegedPods),
		fmt.Sprintf("Root containers: %d", rootPods),
		fmt.Sprintf("Internet-exposed pods: %d", internetExposed),
		fmt.Sprintf("NetworkPolicy coverage: %d%%", netPolCoverage),
	)

	cyberScore := 100
	if totalCritCVEs > 0 {
		cyberScore -= 30
		sec6.Findings = append(sec6.Findings, fmt.Sprintf("%d critical CVEs require immediate remediation", totalCritCVEs))
	}
	if privilegedPods > 0 {
		cyberScore -= 20
		sec6.Findings = append(sec6.Findings, fmt.Sprintf("%d privileged containers violate principle of least privilege", privilegedPods))
	}
	if rootPods > 0 {
		cyberScore -= 15
	}
	if netPolCoverage < 80 {
		cyberScore -= 15
	}
	if internetExposed > len(result.Scores)/2 {
		cyberScore -= 10
	}
	if cyberScore < 0 {
		cyberScore = 0
	}
	sec6.Score = cyberScore
	switch {
	case cyberScore >= 70:
		sec6.Status = "documented"
	case cyberScore >= 40:
		sec6.Status = "partial"
	default:
		sec6.Status = "gap"
		sec6.Gaps = append(sec6.Gaps, "Cybersecurity posture insufficient for high-risk AI system deployment")
	}
	sections = append(sections, sec6)

	// Section 7: Accuracy, Robustness, Cybersecurity Levels (Annex IV §7)
	sec7 := AnnexIVSection{
		ID:          "AIV.7",
		Title:       "Accuracy, Robustness and Cybersecurity Levels",
		Article:     "Annex IV §7, Art. 15",
		Description: "Information about the levels of accuracy, robustness and cybersecurity of the AI system and any known limitations.",
	}
	sec7.Evidence = append(sec7.Evidence,
		fmt.Sprintf("Infrastructure risk score: %d/100 (lower is better)", result.ClusterScore),
	)
	for _, p := range aiPods {
		sec7.Evidence = append(sec7.Evidence,
			fmt.Sprintf("AI pod %s: risk=%d, base=%d, multiplier=×%.2f", shortPodName(p.PodName), p.Total, p.BaseScore, p.RiskMultiplier),
		)
	}
	if len(aiPods) > 0 {
		avgAIRisk := 0
		for _, p := range aiPods {
			avgAIRisk += p.Total
		}
		avgAIRisk /= len(aiPods)
		sec7.Evidence = append(sec7.Evidence, fmt.Sprintf("Average AI workload risk: %d/100", avgAIRisk))

		if avgAIRisk < 40 {
			sec7.Score = 80
			sec7.Status = "documented"
		} else if avgAIRisk < 70 {
			sec7.Score = 50
			sec7.Status = "partial"
			sec7.Findings = append(sec7.Findings, "AI workload risk scores indicate moderate infrastructure vulnerability")
		} else {
			sec7.Score = 20
			sec7.Status = "gap"
			sec7.Gaps = append(sec7.Gaps, "AI workload infrastructure has critical security gaps")
		}
	} else {
		sec7.Score = 30
		sec7.Status = "gap"
		sec7.Gaps = append(sec7.Gaps, "No AI workloads detected for accuracy/robustness assessment")
	}
	sections = append(sections, sec7)

	// Section 8: Human Oversight (Annex IV §8, Art. 14)
	sec8 := AnnexIVSection{
		ID:          "AIV.8",
		Title:       "Human Oversight Measures",
		Article:     "Annex IV §8, Art. 14",
		Description: "Description of human oversight measures, including technical measures to facilitate interpretation of outputs.",
	}
	hasAuth := false
	for _, s := range result.Scores {
		if s.WorkloadClass == "Authentication Service" {
			hasAuth = true
			sec8.Evidence = append(sec8.Evidence, fmt.Sprintf("Authentication service: %s", shortPodName(s.PodName)))
		}
	}
	if monitorCount > 0 {
		sec8.Evidence = append(sec8.Evidence, fmt.Sprintf("Monitoring services: %d (provide operational visibility)", monitorCount))
	}
	sec8.Evidence = append(sec8.Evidence, fmt.Sprintf("RBAC enforcement: %d pods audited", len(result.RBACFindings)))

	if hasAuth && monitorCount > 0 {
		sec8.Score = 65
		sec8.Status = "partial"
		sec8.Findings = append(sec8.Findings, "Authentication and monitoring are present but human oversight mechanisms need explicit documentation")
	} else if hasAuth || monitorCount > 0 {
		sec8.Score = 35
		sec8.Status = "partial"
	} else {
		sec8.Score = 15
		sec8.Status = "gap"
		sec8.Gaps = append(sec8.Gaps, "No authentication or monitoring services detected — human oversight mechanisms required by Article 14")
	}
	sections = append(sections, sec8)

	return sections
}

// GenerateAnnexIVPDF creates a PDF report for EU AI Act Annex IV compliance
func GenerateAnnexIVPDF(result *types.ScanResult, outputPath string) error {
	report := GenerateAnnexIVReport(result)

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 20)

	// Cover page
	renderAIActCover(pdf, result, report)

	// Section pages
	for _, sec := range report.Sections {
		renderAIActSection(pdf, sec)
	}

	// Summary page
	renderAIActSummary(pdf, report)

	return pdf.OutputFileAndClose(outputPath)
}

func renderAIActCover(pdf *fpdf.Fpdf, result *types.ScanResult, report *AnnexIVReport) {
	pdf.AddPage()

	// Title block — dark blue
	pdf.SetFillColor(15, 32, 75)
	pdf.Rect(0, 0, 210, 85, "F")

	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 26)
	pdf.SetY(16)
	pdf.CellFormat(190, 12, "EU AI Act — Annex IV", "", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "", 14)
	pdf.CellFormat(190, 8, "Technical Documentation for High-Risk AI Systems", "", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "", 11)
	pdf.CellFormat(190, 6, fmt.Sprintf("Regulation (EU) 2024/1689 — Article 11 & Annex IV"), "", 1, "C", false, 0, "")
	pdf.CellFormat(190, 6, fmt.Sprintf("Generated: %s", report.GeneratedAt.Format("January 2, 2006 at 3:04 PM MST")), "", 1, "C", false, 0, "")
	pdf.CellFormat(190, 6, "Powered by Plexar — Kubernetes Blast Radius Intelligence", "", 1, "C", false, 0, "")

	// Cluster metadata
	pdf.SetTextColor(0, 0, 0)
	pdf.SetY(95)
	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(190, 8, "System Under Assessment", "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 11)
	items := [][]string{
		{"Cluster", result.ClusterName},
		{"Namespace", result.Namespace},
		{"Total Workloads", fmt.Sprintf("%d", result.TotalPods)},
		{"AI/ML Workloads", fmt.Sprintf("%d", report.AIWorkloads)},
		{"Infrastructure Risk", fmt.Sprintf("%d/100", result.ClusterScore)},
		{"Annex IV Score", fmt.Sprintf("%d/100", report.OverallScore)},
		{"Assessment", report.RiskLevel},
	}
	for _, item := range items {
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(55, 6, item[0]+":", "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		pdf.CellFormat(135, 6, item[1], "", 1, "L", false, 0, "")
	}

	// Section summary table
	pdf.Ln(8)
	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(190, 8, "Annex IV Section Assessment", "", 1, "L", false, 0, "")

	// Table header
	pdf.SetFillColor(15, 32, 75)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.CellFormat(18, 6, "Section", "1", 0, "C", true, 0, "")
	pdf.CellFormat(85, 6, "Title", "1", 0, "L", true, 0, "")
	pdf.CellFormat(28, 6, "Article", "1", 0, "C", true, 0, "")
	pdf.CellFormat(22, 6, "Status", "1", 0, "C", true, 0, "")
	pdf.CellFormat(18, 6, "Score", "1", 0, "C", true, 0, "")
	pdf.CellFormat(19, 6, "Gaps", "1", 1, "C", true, 0, "")

	pdf.SetFont("Helvetica", "", 8)
	for i, s := range report.Sections {
		if i%2 == 0 {
			pdf.SetFillColor(245, 245, 245)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}
		pdf.SetTextColor(0, 0, 0)
		pdf.CellFormat(18, 5, s.ID, "1", 0, "C", true, 0, "")

		title := s.Title
		if len(title) > 50 {
			title = title[:47] + "..."
		}
		pdf.CellFormat(85, 5, title, "1", 0, "L", true, 0, "")
		pdf.CellFormat(28, 5, s.Article, "1", 0, "C", true, 0, "")

		sc := aiActStatusColor(s.Status)
		pdf.SetTextColor(sc[0], sc[1], sc[2])
		pdf.SetFont("Helvetica", "B", 8)
		pdf.CellFormat(22, 5, strings.ToUpper(s.Status), "1", 0, "C", true, 0, "")

		pdf.SetTextColor(0, 0, 0)
		pdf.SetFont("Helvetica", "", 8)
		pdf.CellFormat(18, 5, fmt.Sprintf("%d/100", s.Score), "1", 0, "C", true, 0, "")
		pdf.CellFormat(19, 5, fmt.Sprintf("%d", len(s.Gaps)), "1", 1, "C", true, 0, "")
	}
}

func renderAIActSection(pdf *fpdf.Fpdf, sec AnnexIVSection) {
	pdf.AddPage()

	// Section header bar
	sc := aiActStatusColor(sec.Status)
	pdf.SetFillColor(sc[0], sc[1], sc[2])
	pdf.Rect(0, 10, 6, 15, "F")

	pdf.SetTextColor(15, 32, 75)
	pdf.SetFont("Helvetica", "B", 16)
	pdf.SetX(10)
	pdf.CellFormat(180, 8, fmt.Sprintf("%s — %s", sec.ID, sec.Title), "", 1, "L", false, 0, "")

	// Status and score
	pdf.SetX(10)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetTextColor(sc[0], sc[1], sc[2])
	pdf.CellFormat(50, 7, fmt.Sprintf("Status: %s", strings.ToUpper(sec.Status)), "", 0, "L", false, 0, "")
	pdf.SetTextColor(0, 0, 0)
	pdf.SetFont("Helvetica", "", 11)
	pdf.CellFormat(50, 7, fmt.Sprintf("Score: %d/100", sec.Score), "", 0, "L", false, 0, "")
	pdf.CellFormat(80, 7, sec.Article, "", 1, "R", false, 0, "")

	// Description
	pdf.Ln(4)
	pdf.SetFont("Helvetica", "I", 9)
	pdf.SetTextColor(80, 80, 80)
	pdf.MultiCell(180, 4, sec.Description, "", "L", false)

	// Evidence
	if len(sec.Evidence) > 0 {
		pdf.Ln(4)
		pdf.SetFont("Helvetica", "B", 11)
		pdf.SetTextColor(15, 32, 75)
		pdf.CellFormat(180, 6, "Evidence Collected", "", 1, "L", false, 0, "")

		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(0, 0, 0)
		for _, e := range sec.Evidence {
			ev := e
			if len(ev) > 100 {
				ev = ev[:97] + "..."
			}
			pdf.CellFormat(5, 4, "", "", 0, "", false, 0, "")
			pdf.CellFormat(175, 4, "- "+ev, "", 1, "L", false, 0, "")
		}
	}

	// Findings
	if len(sec.Findings) > 0 {
		pdf.Ln(3)
		pdf.SetFont("Helvetica", "B", 11)
		pdf.SetTextColor(218, 165, 32)
		pdf.CellFormat(180, 6, "Findings", "", 1, "L", false, 0, "")

		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(0, 0, 0)
		for _, f := range sec.Findings {
			pdf.CellFormat(5, 4, "", "", 0, "", false, 0, "")
			pdf.CellFormat(175, 4, "* "+f, "", 1, "L", false, 0, "")
		}
	}

	// Gaps
	if len(sec.Gaps) > 0 {
		pdf.Ln(3)
		pdf.SetFont("Helvetica", "B", 11)
		pdf.SetTextColor(200, 30, 30)
		pdf.CellFormat(180, 6, "Documentation Gaps", "", 1, "L", false, 0, "")

		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(0, 0, 0)
		for _, g := range sec.Gaps {
			pdf.CellFormat(5, 4, "", "", 0, "", false, 0, "")
			pdf.CellFormat(175, 4, "! "+g, "", 1, "L", false, 0, "")
		}
	}
}

func renderAIActSummary(pdf *fpdf.Fpdf, report *AnnexIVReport) {
	pdf.AddPage()

	pdf.SetFont("Helvetica", "B", 18)
	pdf.SetTextColor(15, 32, 75)
	pdf.CellFormat(190, 10, "Assessment Summary", "", 1, "L", false, 0, "")
	pdf.Ln(4)

	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(0, 0, 0)
	pdf.MultiCell(180, 5, fmt.Sprintf(
		"This report assesses the Kubernetes infrastructure hosting AI/ML workloads against "+
			"EU AI Act Annex IV technical documentation requirements. The assessment covers %d "+
			"workloads across the '%s' namespace in cluster '%s'. %d AI/ML workloads were identified "+
			"and assessed for compliance with Regulation (EU) 2024/1689.",
		report.TotalWorkloads, report.ClusterName, report.ClusterName, report.AIWorkloads), "", "L", false)

	pdf.Ln(6)

	// Score summary
	pdf.SetFont("Helvetica", "B", 14)
	pdf.CellFormat(190, 8, fmt.Sprintf("Overall Annex IV Score: %d/100 — %s", report.OverallScore, report.RiskLevel), "", 1, "L", false, 0, "")

	pdf.Ln(4)

	// Gap count
	totalGaps := 0
	for _, s := range report.Sections {
		totalGaps += len(s.Gaps)
	}
	pdf.SetFont("Helvetica", "", 10)
	pdf.CellFormat(190, 6, fmt.Sprintf("Sections assessed: %d | Documentation gaps: %d", len(report.Sections), totalGaps), "", 1, "L", false, 0, "")

	pdf.Ln(6)
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(15, 32, 75)
	pdf.CellFormat(190, 7, "Disclaimer", "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "I", 9)
	pdf.SetTextColor(80, 80, 80)
	pdf.MultiCell(180, 4,
		"This assessment is generated automatically by Plexar from Kubernetes infrastructure data. "+

			"It provides evidence about the deployment environment but does not constitute a full Annex IV "+
			"technical documentation package. Organizations must supplement this with documentation about "+
			"training data, model architecture, validation procedures, and intended use cases. Consult "+
			"legal counsel for full EU AI Act compliance.",
		"", "L", false)
}

func aiActStatusColor(status string) [3]int {
	switch status {
	case "documented":
		return [3]int{34, 139, 34}
	case "partial":
		return [3]int{218, 165, 32}
	default:
		return [3]int{200, 30, 30}
	}
}
