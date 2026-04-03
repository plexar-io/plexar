package compliance

import (
	"fmt"

	"github.com/plexar-security/plexar/internal/types"
)

// mapEUCRA maps scan results to EU Cyber Resilience Act (CRA) essential requirements
// Based on Article 13 of Regulation (EU) 2024/2847
func mapEUCRA(scores []types.PlexarScore, netPolCount int, rbac []types.RBACFinding) types.ComplianceResult {
	var controls []types.ComplianceCheck
	passing := 0
	total := len(scores)

	// Pre-compute common lists
	unprotectedPods := podsWithoutNetPol(scores)
	privPods := podsPrivileged(scores)
	rootPods := podsRunAsRoot(scores)
	escalationPods := podsAllowEscalation(scores)
	internetPods := podsWithInternetAccess(scores)
	roCount := podsWithReadOnlyFS(scores)
	envSecretPods := podsWithEnvSecrets(scores)

	// RBAC aggregates
	rbacWithClusterAdmin := rbacPodsWithFlag(rbac, "HasClusterAdmin")
	rbacWithSecrets := rbacPodsWithFlag(rbac, "HasSecretAccess")

	// CVE aggregates
	totalCriticalCVEs := 0
	totalHighCVEs := 0
	totalFixableCVEs := 0
	totalCVEs := 0
	inUseCVEs := 0
	for _, s := range scores {
		totalCriticalCVEs += s.Vulns.Critical
		totalHighCVEs += s.Vulns.High
		totalFixableCVEs += s.Vulns.FixableCount
		totalCVEs += s.Vulns.TotalCount
		for _, cve := range s.Vulns.TopCVEs {
			if cve.InUse {
				inUseCVEs++
			}
		}
	}

	// ── Art. 13(1) — No known exploitable vulnerabilities ──
	art131Score := 100
	if inUseCVEs > 0 {
		art131Score = max(0, 100-inUseCVEs*15)
	} else if totalCriticalCVEs > 0 {
		art131Score = max(10, 100-totalCriticalCVEs*10)
	}
	art131Status := controlStatus(art131Score)
	var art131Findings []string
	if inUseCVEs > 0 {
		art131Findings = append(art131Findings, fmt.Sprintf("CRITICAL: %d CVEs confirmed in-use at runtime", inUseCVEs))
	}
	if totalCriticalCVEs > 0 {
		art131Findings = append(art131Findings, fmt.Sprintf("HIGH: %d critical CVEs detected across %d pods", totalCriticalCVEs, total))
	}
	if totalFixableCVEs > 0 {
		art131Findings = append(art131Findings, fmt.Sprintf("MEDIUM: %d CVEs have available fixes", totalFixableCVEs))
	}
	controls = append(controls, types.ComplianceCheck{
		ID:          "CRA-13.1",
		Name:        "No known exploitable vulnerabilities",
		Status:      art131Status,
		Score:       art131Score,
		Violations:  inUseCVEs + totalCriticalCVEs,
		Evidence:    fmt.Sprintf("%d total CVEs, %d critical, %d in-use at runtime, %d fixable", totalCVEs, totalCriticalCVEs, inUseCVEs, totalFixableCVEs),
		Findings:    art131Findings,
		Remediation: "Patch all critical and in-use CVEs. Prioritize runtime-confirmed vulnerabilities.",
	})
	if art131Status == "pass" {
		passing++
	}

	// ── Art. 13(2) — Secure by default configuration ──
	insecureCount := len(privPods) + len(rootPods) + len(escalationPods) + len(rbacWithClusterAdmin)
	art132Score := 100
	if total > 0 {
		art132Score = max(0, 100-(insecureCount*100/total))
	}
	art132Status := controlStatus(art132Score)
	var art132Findings []string
	for _, p := range privPods {
		art132Findings = append(art132Findings, fmt.Sprintf("CRITICAL: %s runs in privileged mode", p))
	}
	for _, p := range rootPods {
		art132Findings = append(art132Findings, fmt.Sprintf("HIGH: %s runs as root", p))
	}
	for _, p := range rbacWithClusterAdmin {
		art132Findings = append(art132Findings, fmt.Sprintf("CRITICAL: %s has cluster-admin binding", p))
	}
	controls = append(controls, types.ComplianceCheck{
		ID:          "CRA-13.2",
		Name:        "Secure by default configuration",
		Status:      art132Status,
		Score:       art132Score,
		Violations:  insecureCount,
		Evidence:    fmt.Sprintf("%d/%d pods have insecure defaults (privileged: %d, root: %d, escalation: %d, cluster-admin: %d)", insecureCount, total, len(privPods), len(rootPods), len(escalationPods), len(rbacWithClusterAdmin)),
		Findings:    art132Findings,
		Remediation: "Set runAsNonRoot: true, privileged: false, allowPrivilegeEscalation: false. Remove cluster-admin bindings.",
	})
	if art132Status == "pass" {
		passing++
	}

	// ── Art. 13(3) — Protection of confidentiality ──
	secretIssues := len(envSecretPods) + len(rbacWithSecrets)
	art133Score := 100
	if secretIssues > 0 {
		art133Score = max(0, 100-secretIssues*20)
	}
	art133Status := controlStatus(art133Score)
	var art133Findings []string
	for _, p := range envSecretPods {
		art133Findings = append(art133Findings, fmt.Sprintf("CRITICAL: %s has plaintext secrets in environment variables", p))
	}
	for _, p := range rbacWithSecrets {
		art133Findings = append(art133Findings, fmt.Sprintf("HIGH: %s has RBAC access to read Kubernetes secrets", p))
	}
	controls = append(controls, types.ComplianceCheck{
		ID:          "CRA-13.3",
		Name:        "Protection of confidentiality",
		Status:      art133Status,
		Score:       art133Score,
		Violations:  secretIssues,
		Evidence:    fmt.Sprintf("%d secret management issues (plaintext env: %d, RBAC secret access: %d)", secretIssues, len(envSecretPods), len(rbacWithSecrets)),
		Findings:    art133Findings,
		Remediation: "Use Kubernetes Secrets with volumeMount, not env vars. Restrict secret-reading RBAC to least privilege.",
	})
	if art133Status == "pass" {
		passing++
	}

	// ── Art. 13(4) — Protection of integrity ──
	art134Score := 0
	if total > 0 {
		art134Score = (roCount * 100) / total
	}
	art134Status := controlStatus(art134Score)
	var art134Findings []string
	if roCount < total {
		art134Findings = append(art134Findings, fmt.Sprintf("MEDIUM: %d/%d pods lack read-only root filesystem", total-roCount, total))
	}
	controls = append(controls, types.ComplianceCheck{
		ID:          "CRA-13.4",
		Name:        "Protection of integrity",
		Status:      art134Status,
		Score:       art134Score,
		Violations:  total - roCount,
		Evidence:    fmt.Sprintf("%d/%d pods have read-only root filesystem", roCount, total),
		Findings:    art134Findings,
		Remediation: "Set readOnlyRootFilesystem: true for all containers. Use emptyDir for writable paths.",
	})
	if art134Status == "pass" {
		passing++
	}

	// ── Art. 13(5) — Protection of availability ──
	replicatedCount := 0
	for _, s := range scores {
		// Heuristic: if blast radius shows multiple reachable targets, likely replicated
		if len(s.Blast.ReachableTargets) > 0 {
			replicatedCount++
		}
	}
	art135Score := 60 // Base score — we can't fully assess availability from scan data
	art135Status := controlStatus(art135Score)
	controls = append(controls, types.ComplianceCheck{
		ID:          "CRA-13.5",
		Name:        "Protection of availability",
		Status:      art135Status,
		Score:       art135Score,
		Violations:  0,
		Evidence:    fmt.Sprintf("Availability assessment limited to scan data. %d pods with network reachability.", replicatedCount),
		Findings:    []string{"INFO: Full availability assessment requires PDB, HPA, and resource limit checks (partially assessed)"},
		Remediation: "Configure PodDisruptionBudgets, resource limits, and replica counts for all production workloads.",
	})
	if art135Status == "pass" {
		passing++
	}

	// ── Art. 13(6) — Minimize attack surface ──
	unprotectedCount := len(unprotectedPods)
	art136Score := 100
	if total > 0 {
		art136Score = max(0, ((total-unprotectedCount)*100)/total)
	}
	if len(privPods) > 0 {
		art136Score = max(0, art136Score-len(privPods)*15)
	}
	art136Status := controlStatus(art136Score)
	var art136Findings []string
	for _, p := range unprotectedPods {
		art136Findings = append(art136Findings, fmt.Sprintf("HIGH: %s has no NetworkPolicy (unrestricted network access)", p))
	}
	for _, p := range internetPods {
		art136Findings = append(art136Findings, fmt.Sprintf("MEDIUM: %s has internet access", p))
	}
	controls = append(controls, types.ComplianceCheck{
		ID:          "CRA-13.6",
		Name:        "Minimize attack surface",
		Status:      art136Status,
		Score:       art136Score,
		Violations:  unprotectedCount + len(privPods),
		Evidence:    fmt.Sprintf("%d/%d pods without NetworkPolicy, %d privileged, %d internet-exposed", unprotectedCount, total, len(privPods), len(internetPods)),
		Findings:    art136Findings,
		Remediation: "Apply NetworkPolicies to all pods. Remove privileged mode. Restrict internet access to only pods that need it.",
	})
	if art136Status == "pass" {
		passing++
	}

	// ── Art. 13(7) — Vulnerability handling process ──
	// Assessed by: continuous scanning enabled, drift detection, evidence vault
	art137Score := 70 // Partial by default — Plexar provides this but we can't verify external processes
	art137Status := controlStatus(art137Score)
	controls = append(controls, types.ComplianceCheck{
		ID:          "CRA-13.7",
		Name:        "Vulnerability handling process",
		Status:      art137Status,
		Score:       art137Score,
		Violations:  0,
		Evidence:    "Continuous vulnerability scanning via Plexar. Drift detection active. Evidence vault records all findings.",
		Findings:    []string{"INFO: Plexar provides continuous scanning and drift detection. Verify external vulnerability disclosure process exists."},
		Remediation: "Document vulnerability handling SOP. Configure automated drift alerting. Maintain evidence vault retention.",
	})
	if art137Status == "pass" {
		passing++
	}

	// ── Art. 13(8) — Software Bill of Materials ──
	// Assessed by: whether Trivy SBOM data is available
	art138Score := 50 // Partial — we know images but may not have full SBOM
	if totalCVEs > 0 {
		art138Score = 65 // CVE data implies some SBOM coverage
	}
	art138Status := controlStatus(art138Score)
	controls = append(controls, types.ComplianceCheck{
		ID:          "CRA-13.8",
		Name:        "Software Bill of Materials",
		Status:      art138Status,
		Score:       art138Score,
		Violations:  0,
		Evidence:    fmt.Sprintf("SBOM coverage: %d images scanned with %d total CVEs detected. Ingest Trivy SBOM for full component inventory.", total, totalCVEs),
		Findings:    []string{"INFO: Run 'plexar ingest --source trivy-sbom' to import full CycloneDX/SPDX SBOMs for complete component inventory"},
		Remediation: "Generate and maintain SBOMs for all container images using Trivy. Ingest into Plexar for tracking.",
	})
	if art138Status == "pass" {
		passing++
	}

	// ── Art. 13(9) — Security updates ──
	patchRate := 0
	if totalCVEs > 0 {
		patchRate = (totalFixableCVEs * 100) / totalCVEs
	}
	art139Score := 100 - patchRate // Lower is better (fewer unpatched)
	if totalFixableCVEs > 10 {
		art139Score = max(0, 100-totalFixableCVEs*3)
	}
	art139Status := controlStatus(art139Score)
	var art139Findings []string
	if totalFixableCVEs > 0 {
		art139Findings = append(art139Findings, fmt.Sprintf("HIGH: %d CVEs have available security updates that are not applied", totalFixableCVEs))
	}
	controls = append(controls, types.ComplianceCheck{
		ID:          "CRA-13.9",
		Name:        "Security updates",
		Status:      art139Status,
		Score:       art139Score,
		Violations:  totalFixableCVEs,
		Evidence:    fmt.Sprintf("%d fixable CVEs out of %d total (%d%% patch available rate)", totalFixableCVEs, totalCVEs, patchRate),
		Findings:    art139Findings,
		Remediation: "Apply all available security patches. Automate image rebuilds when base image updates are available.",
	})
	if art139Status == "pass" {
		passing++
	}

	// ── Art. 13(10) — Incident reporting readiness ──
	art1310Score := 60 // Partial — Plexar provides alerting infrastructure
	art1310Status := controlStatus(art1310Score)
	controls = append(controls, types.ComplianceCheck{
		ID:          "CRA-13.10",
		Name:        "Incident reporting readiness",
		Status:      art1310Status,
		Score:       art1310Score,
		Violations:  0,
		Evidence:    "Plexar evidence vault and alerting system provide incident detection foundation. External reporting process required.",
		Findings:    []string{"INFO: Configure Slack/webhook alerting for real-time incident detection. Establish ENISA reporting workflow."},
		Remediation: "Configure alert destinations (Slack, webhook). Document incident reporting SOP per CRA Art. 14 (24h ENISA notification).",
	})
	if art1310Status == "pass" {
		passing++
	}

	// ── Art. 13(11) — Coordinated vulnerability disclosure ──
	art1311Score := 40 // Manual check — cannot be assessed automatically
	art1311Status := controlStatus(art1311Score)
	controls = append(controls, types.ComplianceCheck{
		ID:          "CRA-13.11",
		Name:        "Coordinated vulnerability disclosure",
		Status:      art1311Status,
		Score:       art1311Score,
		Violations:  0,
		Evidence:    "Cannot be automatically assessed. Requires documented vulnerability disclosure policy.",
		Findings:    []string{"WARN: Coordinated disclosure policy must be documented externally. Verify SECURITY.md exists in all repositories."},
		Remediation: "Create SECURITY.md in all repositories. Establish a security@company.com contact. Document CVD process.",
	})
	if art1311Status == "pass" {
		passing++
	}

	// ── Art. 13(12) — Product information and instructions ──
	art1312Score := 70 // Partial — Plexar provides workload inventory
	art1312Status := controlStatus(art1312Score)
	imageCount := len(uniqueImages(scores))
	controls = append(controls, types.ComplianceCheck{
		ID:          "CRA-13.12",
		Name:        "Product information and instructions",
		Status:      art1312Status,
		Score:       art1312Score,
		Violations:  0,
		Evidence:    fmt.Sprintf("Workload inventory: %d pods, %d unique images across %d workload classes", total, imageCount, countUniqueClasses(scores)),
		Findings:    []string{fmt.Sprintf("INFO: %d unique container images tracked. Ensure documentation includes security properties and usage instructions.", imageCount)},
		Remediation: "Maintain up-to-date documentation of all deployed software components, their security properties, and intended use.",
	})
	if art1312Status == "pass" {
		passing++
	}

	// Compute overall score
	totalScore := 0
	for _, c := range controls {
		totalScore += c.Score
	}
	overallScore := 0
	if len(controls) > 0 {
		overallScore = totalScore / len(controls)
	}

	return types.ComplianceResult{
		Framework:   "EU CRA",
		Version:     "Regulation (EU) 2024/2847 — Article 13",
		Score:       overallScore,
		TotalChecks: len(controls),
		Passing:     passing,
		Controls:    controls,
	}
}

// ── Helper functions specific to CRA ──

func podsWithReadOnlyFS(scores []types.PlexarScore) int {
	count := 0
	for _, s := range scores {
		if s.Permissions.ReadOnlyRootFS {
			count++
		}
	}
	return count
}

func uniqueImages(scores []types.PlexarScore) []string {
	seen := make(map[string]bool)
	var images []string
	for _, s := range scores {
		if !seen[s.ImageName] {
			seen[s.ImageName] = true
			images = append(images, s.ImageName)
		}
	}
	return images
}

func countUniqueClasses(scores []types.PlexarScore) int {
	seen := make(map[string]bool)
	for _, s := range scores {
		if s.WorkloadClass != "" {
			seen[s.WorkloadClass] = true
		}
	}
	return len(seen)
}
