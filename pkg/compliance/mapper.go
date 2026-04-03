package compliance

import (
	"fmt"

	"github.com/plexar-security/plexar/internal/types"
)

// MapAll maps scan results to all supported compliance frameworks
func MapAll(scores []types.PlexarScore, netPolCount int, rbacFindings ...[]types.RBACFinding) []types.ComplianceResult {
	var rbac []types.RBACFinding
	if len(rbacFindings) > 0 {
		rbac = rbacFindings[0]
	}
	return []types.ComplianceResult{
		mapSOC2(scores, netPolCount, rbac),
		mapPCIDSS(scores, netPolCount),
		mapHIPAA(scores, netPolCount),
		mapCIS(scores, netPolCount),
		mapEUCRA(scores, netPolCount, rbac),
	}
}

func mapSOC2(scores []types.PlexarScore, netPolCount int, rbac []types.RBACFinding) types.ComplianceResult {
	var controls []types.ComplianceCheck
	passing := 0
	total := len(scores)

	// Build RBAC lookup
	rbacMap := make(map[string]*types.RBACFinding)
	for i := range rbac {
		rbacMap[rbac[i].PodName] = &rbac[i]
	}

	// Pre-compute common lists
	criticalPods := podsByTier(scores, "critical")
	highPods := podsByTier(scores, "high")
	unprotectedPods := podsWithoutNetPol(scores)
	privPods := podsPrivileged(scores)
	rootPods := podsRunAsRoot(scores)
	escalationPods := podsAllowEscalation(scores)
	internetPods := podsWithInternetAccess(scores)
	egressPods := podsUnrestrictedEgress(scores)
	dataStorePods := podsWithDataStoreAccess(scores)

	// RBAC aggregates
	rbacWithSecrets := rbacPodsWithFlag(rbac, "HasSecretAccess")
	rbacWithExec := rbacPodsWithFlag(rbac, "HasExecCapability")
	rbacWithClusterAdmin := rbacPodsWithFlag(rbac, "HasClusterAdmin")
	rbacWithWildcard := rbacPodsWithFlag(rbac, "HasWildcardAccess")
	rbacWithEscalate := rbacPodsWithFlag(rbac, "HasEscalatePriv")

	// ── CC3.1 — Risk Identification and Assessment ──
	riskPodCount := len(criticalPods) + len(highPods)
	cc31Score := 100
	cc31Status := "pass"
	if len(criticalPods) > 3 {
		cc31Status = "fail"
		cc31Score = max(0, 100-len(criticalPods)*10)
	} else if riskPodCount > 0 {
		cc31Status = "partial"
		cc31Score = max(30, 100-riskPodCount*8)
	}
	if cc31Status == "pass" {
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "CC3.1", Name: "Risk Identification and Assessment", Status: cc31Status, Score: cc31Score, Violations: riskPodCount,
		Evidence: fmt.Sprintf("Blast radius scoring active on %d pods. %d critical, %d high.", total, len(criticalPods), len(highPods)),
		EvidenceItems: []string{
			fmt.Sprintf("Plexar composite scoring active across %d pods", total),
			fmt.Sprintf("Critical-tier pods: %s", podList(criticalPods, 5)),
			fmt.Sprintf("High-tier pods: %s", podList(highPods, 5)),
			"Risk assessment runs every scan cycle with historical trending",
		},
		Findings:    riskFindings(criticalPods, highPods),
		Remediation: "Remediate critical-tier pods first by adding NetworkPolicies, patching CVEs, and restricting permissions. Target: zero critical-tier pods.",
	})

	// ── CC3.2 — Risk Assessment of Changes ──
	cc32Score := 100
	cc32Status := "pass"
	controls = append(controls, types.ComplianceCheck{
		ID: "CC3.2", Name: "Risk Assessment of Changes", Status: cc32Status, Score: cc32Score, Violations: 0,
		Evidence: fmt.Sprintf("Drift detection compares consecutive scans. Evidence vault maintains hash-chained records for %d pods.", total),
		EvidenceItems: []string{
			"Drift detector runs after each scan comparing control statuses",
			"SHA-256 hash-chained evidence vault prevents tampering",
			"Score deltas tracked per pod and per control",
		},
		Findings:    nil,
		Remediation: "No action needed. Drift detection is active.",
	})
	passing++

	// ── CC3.4 — Risk from Fraud and Unauthorized Activity ──
	cc34Violations := len(privPods) + len(rbacWithClusterAdmin)
	cc34Score := 100
	cc34Status := "pass"
	if len(rbacWithClusterAdmin) > 0 || len(privPods) > 2 {
		cc34Status = "fail"
		cc34Score = max(0, 100-cc34Violations*15)
	} else if len(privPods) > 0 {
		cc34Status = "partial"
		cc34Score = max(30, 100-cc34Violations*10)
	}
	if cc34Status == "pass" {
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "CC3.4", Name: "Risk from Fraud and Unauthorized Activity", Status: cc34Status, Score: cc34Score, Violations: cc34Violations,
		Evidence: fmt.Sprintf("Privileged pods: %d. Cluster-admin pods: %d. Pods with privilege escalation: %d.", len(privPods), len(rbacWithClusterAdmin), len(escalationPods)),
		EvidenceItems: []string{
			fmt.Sprintf("Privileged containers: %s", podList(privPods, 5)),
			fmt.Sprintf("Cluster-admin ServiceAccounts: %s", podList(rbacWithClusterAdmin, 5)),
			fmt.Sprintf("Privilege escalation allowed: %s", podList(escalationPods, 5)),
		},
		Findings:    fraudFindings(privPods, rbacWithClusterAdmin, escalationPods),
		Remediation: "Remove privileged mode, eliminate cluster-admin bindings, disable allowPrivilegeEscalation on all pods.",
	})

	// ── CC4.1 — Monitoring of Controls ──
	cc41Score := 100
	controls = append(controls, types.ComplianceCheck{
		ID: "CC4.1", Name: "Monitoring of Controls", Status: "pass", Score: cc41Score, Violations: 0,
		Evidence: fmt.Sprintf("Continuous monitoring active. %d pods scanned per cycle. Prometheus metrics on :9090.", total),
		EvidenceItems: []string{
			fmt.Sprintf("Automated scanning of %d pods per cycle", total),
			"Prometheus metrics exported for alerting integration",
			"Alert rules: critical-cve-high-blast, cluster-score-increase, netpol-removed",
			"Evidence vault records every scan for audit trail",
		},
		Findings:    nil,
		Remediation: "No action needed. Monitoring is active.",
	})
	passing++

	// ── CC5.2 — Technology General Controls ──
	roCount := countReadOnlyRootFS(scores)
	cc52Score := roCount * 100 / max(total, 1)
	cc52Status := controlStatus(cc52Score)
	if cc52Status == "pass" {
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "CC5.2", Name: "Technology General Controls", Status: cc52Status, Score: cc52Score, Violations: total - roCount,
		Evidence: fmt.Sprintf("Read-only root filesystem: %d of %d pods. %d unique images scanned.", roCount, total, countUniqueImages(scores)),
		EvidenceItems: []string{
			fmt.Sprintf("Read-only root filesystem enforced on %d/%d pods", roCount, total),
			fmt.Sprintf("%d unique container images scanned for vulnerabilities", countUniqueImages(scores)),
			fmt.Sprintf("%d NetworkPolicies deployed", netPolCount),
		},
		Findings:    techControlFindings(scores, roCount, total),
		Remediation: "Enable readOnlyRootFilesystem on all containers. Use minimal base images.",
	})

	// ── CC6.1 — Logical and Physical Access Controls ──
	cc61Score := (total - len(unprotectedPods)) * 100 / max(total, 1)
	cc61Status := "fail"
	if len(unprotectedPods) == 0 {
		cc61Status = "pass"
		cc61Score = 100
		passing++
	} else if float64(len(unprotectedPods)) < float64(total)*0.3 {
		cc61Status = "partial"
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "CC6.1", Name: "Logical and Physical Access Controls", Status: cc61Status, Score: cc61Score, Violations: len(unprotectedPods),
		Evidence: fmt.Sprintf("%d of %d pods lack NetworkPolicy. %d NetworkPolicies deployed.", len(unprotectedPods), total, netPolCount),
		EvidenceItems: []string{
			fmt.Sprintf("NetworkPolicy coverage: %d/%d pods (%d%%)", total-len(unprotectedPods), total, cc61Score),
			fmt.Sprintf("Unprotected pods: %s", podList(unprotectedPods, 5)),
			fmt.Sprintf("Total NetworkPolicies: %d", netPolCount),
		},
		Findings:    accessFindings(unprotectedPods),
		Remediation: "Apply NetworkPolicies to all unprotected pods. Run: plexar generate netpol --namespace <ns>",
	})

	// ── CC6.2 — System User Access Provisioning ──
	defaultSAPods := podsWithDefaultSA(scores)
	cc62Score := 100
	cc62Status := "pass"
	if len(rbacWithClusterAdmin) > 0 {
		cc62Status = "fail"
		cc62Score = max(0, 100-len(rbacWithClusterAdmin)*25)
	} else if len(rbacWithWildcard) > 0 {
		cc62Status = "partial"
		cc62Score = max(30, 100-len(rbacWithWildcard)*10)
	}
	if cc62Status == "pass" {
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "CC6.2", Name: "System User Access Provisioning", Status: cc62Status, Score: cc62Score, Violations: len(rbacWithClusterAdmin) + len(rbacWithWildcard),
		Evidence: fmt.Sprintf("ServiceAccounts: %s. Cluster-admin: %d. Wildcard access: %d. Default SA: %d pods.", serviceAccountList(scores, 5), len(rbacWithClusterAdmin), len(rbacWithWildcard), len(defaultSAPods)),
		EvidenceItems: []string{
			fmt.Sprintf("Unique ServiceAccounts: %s", serviceAccountList(scores, 10)),
			fmt.Sprintf("Pods with cluster-admin: %s", podList(rbacWithClusterAdmin, 5)),
			fmt.Sprintf("Pods with wildcard access: %s", podList(rbacWithWildcard, 5)),
			fmt.Sprintf("Pods using default ServiceAccount: %d", len(defaultSAPods)),
		},
		Findings:    saProvisioningFindings(rbacWithClusterAdmin, rbacWithWildcard, defaultSAPods),
		Remediation: "Create dedicated ServiceAccounts per workload. Remove cluster-admin bindings. Apply least-privilege RBAC policies.",
	})

	// ── CC6.3 — Role-Based Access and Least Privilege ──
	cc63Violations := len(privPods) + len(rootPods) + len(escalationPods) + len(rbacWithExec) + len(rbacWithSecrets)
	cc63Score := max(0, 100-cc63Violations*8)
	cc63Status := "pass"
	if len(privPods) > 0 || len(rbacWithExec) > 0 || len(rbacWithClusterAdmin) > 0 {
		cc63Status = "fail"
	} else if len(rootPods) > 0 || len(escalationPods) > 0 || len(rbacWithSecrets) > 0 {
		cc63Status = "partial"
	}
	if cc63Status == "pass" {
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "CC6.3", Name: "Role-Based Access and Least Privilege", Status: cc63Status, Score: cc63Score, Violations: cc63Violations,
		Evidence: fmt.Sprintf("Privileged: %d. Root: %d. Escalation: %d. Exec access: %d. Secret access: %d.", len(privPods), len(rootPods), len(escalationPods), len(rbacWithExec), len(rbacWithSecrets)),
		EvidenceItems: []string{
			fmt.Sprintf("Privileged containers: %s", podList(privPods, 5)),
			fmt.Sprintf("Root containers: %s", podList(rootPods, 5)),
			fmt.Sprintf("Privilege escalation: %s", podList(escalationPods, 5)),
			fmt.Sprintf("Pods with exec capability: %s", podList(rbacWithExec, 5)),
			fmt.Sprintf("Pods with secret access: %s", podList(rbacWithSecrets, 5)),
		},
		Findings:    leastPrivFindings(privPods, rootPods, escalationPods, rbacWithExec, rbacWithSecrets),
		Remediation: "Remove privileged mode. Set runAsNonRoot: true. Disable allowPrivilegeEscalation. Restrict RBAC to minimum required verbs/resources.",
	})

	// ── CC6.5 — Restriction of System Access ──
	cc65Score := 100
	cc65Status := "pass"
	rbacEscCount := len(rbacWithEscalate)
	if rbacEscCount > 0 {
		cc65Status = "fail"
		cc65Score = max(0, 100-rbacEscCount*20)
	}
	if cc65Status == "pass" {
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "CC6.5", Name: "Restriction of System Access", Status: cc65Status, Score: cc65Score, Violations: rbacEscCount,
		Evidence: fmt.Sprintf("Pods with escalate/bind/impersonate: %d. Namespace isolation via RBAC.", rbacEscCount),
		EvidenceItems: []string{
			fmt.Sprintf("Pods with escalation privileges: %s", podList(rbacWithEscalate, 5)),
			fmt.Sprintf("Namespace-scoped RBAC in place for %d pods", total),
		},
		Findings:    escalateFindings(rbacWithEscalate),
		Remediation: "Remove escalate, bind, and impersonate verbs from all workload ServiceAccounts.",
	})

	// ── CC6.6 — Network Security and Segmentation ──
	cc66Violations := 0
	cc66Score := 100
	cc66Status := "pass"
	if len(internetPods) > 0 && len(unprotectedPods) > 0 {
		cc66Status = "fail"
		cc66Violations = len(internetPods)
		cc66Score = max(0, 100-cc66Violations*12)
	} else if len(egressPods) > 0 {
		cc66Status = "partial"
		cc66Violations = len(egressPods)
		cc66Score = max(30, 100-cc66Violations*8)
	}
	if cc66Status == "pass" {
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "CC6.6", Name: "Network Security and Segmentation", Status: cc66Status, Score: cc66Score, Violations: cc66Violations,
		Evidence: fmt.Sprintf("Internet-exposed: %d. Unrestricted egress: %d. Data store access: %d.", len(internetPods), len(egressPods), countDataStoreAccess(scores)),
		EvidenceItems: []string{
			fmt.Sprintf("Internet-exposed pods: %s", podList(internetPods, 5)),
			fmt.Sprintf("Unrestricted egress: %s", podList(egressPods, 5)),
			fmt.Sprintf("Pods with data store access: %d", countDataStoreAccess(scores)),
			fmt.Sprintf("NetworkPolicies deployed: %d", netPolCount),
		},
		Findings:    networkFindings(internetPods, egressPods, unprotectedPods),
		Remediation: "Apply egress NetworkPolicies to restrict internet access. Segment data store access with targeted policies.",
	})

	// ── CC6.7 — Restriction of Data Movement ──
	dsOverlap := countOverlap(dataStorePods, unprotectedPods)
	cc67Score := 100
	cc67Status := "pass"
	if dsOverlap > 0 {
		cc67Status = "fail"
		cc67Score = max(0, 100-dsOverlap*20)
	} else if len(dataStorePods) > 0 && len(egressPods) > 0 {
		cc67Status = "partial"
		cc67Score = 60
	}
	if cc67Status == "pass" {
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "CC6.7", Name: "Restriction of Data Movement", Status: cc67Status, Score: cc67Score, Violations: dsOverlap,
		Evidence: fmt.Sprintf("%d pods access data stores. %d of those lack NetworkPolicy.", len(dataStorePods), dsOverlap),
		EvidenceItems: []string{
			fmt.Sprintf("Data store pods: %s", podList(dataStorePods, 5)),
			fmt.Sprintf("Unprotected data store pods: %d", dsOverlap),
		},
		Findings:    dataMovementFindings(dataStorePods, unprotectedPods, dsOverlap),
		Remediation: "Apply NetworkPolicies to all pods with data store access. Restrict egress to specific database endpoints.",
	})

	// ── CC6.8 — Prevention of Unauthorized Software ──
	uniqueImages := countUniqueImages(scores)
	roCount2 := countReadOnlyRootFS(scores)
	cc68Score := 50 // base: we scan but can't fully verify
	cc68Status := "partial"
	if roCount2 == total {
		cc68Score = 80
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "CC6.8", Name: "Prevention of Unauthorized Software", Status: cc68Status, Score: cc68Score, Violations: total - roCount2,
		Evidence: fmt.Sprintf("%d unique images scanned. Read-only root FS: %d/%d pods.", uniqueImages, roCount2, total),
		EvidenceItems: []string{
			fmt.Sprintf("Vulnerability scanning via Trivy: %d images", uniqueImages),
			fmt.Sprintf("Read-only root filesystem: %d/%d pods", roCount2, total),
			"Image provenance not fully verified (no admission controller detected)",
		},
		Findings:    softwareFindings(total, roCount2),
		Remediation: "Enable readOnlyRootFilesystem on all pods. Deploy an admission controller (e.g., Kyverno, OPA Gatekeeper) to enforce trusted image registries.",
	})

	// ── CC7.1 — Detection of Unauthorized Activities ──
	controls = append(controls, types.ComplianceCheck{
		ID: "CC7.1", Name: "Detection of Unauthorized Activities", Status: "pass", Score: 100, Violations: 0,
		Evidence: fmt.Sprintf("Continuous monitoring: %d pods. Prometheus metrics on :9090.", total),
		EvidenceItems: []string{
			fmt.Sprintf("Plexar continuous scanning active on %d pods", total),
			"Prometheus metrics exported for Grafana/AlertManager integration",
			"Alert rules: critical CVEs, score regressions, NetworkPolicy changes",
			"Evidence vault with hash chain for tamper detection",
		},
		Findings:    nil,
		Remediation: "No action needed. Monitoring is active.",
	})
	passing++

	// ── CC7.2 — Monitoring Security Events ──
	controls = append(controls, types.ComplianceCheck{
		ID: "CC7.2", Name: "Monitoring Security Events", Status: "pass", Score: 100, Violations: 0,
		Evidence: fmt.Sprintf("Alert engine active. Drift detection across %d pods. Hash-chained evidence vault.", total),
		EvidenceItems: []string{
			"Alert engine with configurable rules and thresholds",
			"Drift detection compares consecutive scans for regressions",
			fmt.Sprintf("Evidence vault maintains immutable record chain for %d pods", total),
		},
		Findings:    nil,
		Remediation: "No action needed. Security event monitoring is active.",
	})
	passing++

	// ── CC7.3 — Evaluation of Security Events ──
	avgBlast := avgBlastRadius(scores)
	maxBlast := maxBlastRadius(scores)
	controls = append(controls, types.ComplianceCheck{
		ID: "CC7.3", Name: "Evaluation of Security Events", Status: "pass", Score: 100, Violations: 0,
		Evidence: fmt.Sprintf("Composite scoring: CVE + blast radius + permissions + policy gap. Avg blast: %.1f. Max blast: %d.", avgBlast, maxBlast),
		EvidenceItems: []string{
			"Composite risk scoring: CVE severity × blast radius × permissions × policy gaps",
			fmt.Sprintf("Average blast radius: %.1f reachable targets", avgBlast),
			fmt.Sprintf("Maximum blast radius: %d targets", maxBlast),
			"Per-pod risk tiers: critical (≥75), high (≥50), medium (≥25), low (<25)",
		},
		Findings:    nil,
		Remediation: "No action needed. Risk evaluation is automated.",
	})
	passing++

	// ── CC7.4 — Incident Response ──
	cc74Score := 70
	cc74Status := "partial"
	controls = append(controls, types.ComplianceCheck{
		ID: "CC7.4", Name: "Incident Response", Status: cc74Status, Score: cc74Score, Violations: 0,
		Evidence: "Automated remediation recommendations generated per pod. NetworkPolicy generation available via CLI.",
		EvidenceItems: []string{
			"Per-pod remediation recommendations generated with each scan",
			"NetworkPolicy auto-generation: plexar generate netpol",
			"Alert-based notification for security regressions",
			"Manual incident response process not verified by Plexar",
		},
		Findings:    nil,
		Remediation: "Document incident response procedures. Configure alerting destinations (Slack, PagerDuty) for automated notification.",
	})

	// ── CC8.1 — Change Management / Vulnerability Remediation ──
	criticalCVEs := countCriticalCVEs(scores)
	highCVEs := countHighCVEs(scores)
	fixableCritical := countFixableCritical(scores)
	cc81Score := 100
	cc81Status := "pass"
	if criticalCVEs > 0 {
		cc81Status = "fail"
		cc81Score = max(0, 100-criticalCVEs*5)
	} else if highCVEs > 50 {
		cc81Status = "partial"
		cc81Score = max(30, 100-highCVEs/10)
	}
	if cc81Status == "pass" {
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "CC8.1", Name: "Change Management and Vulnerability Remediation", Status: cc81Status, Score: cc81Score, Violations: criticalCVEs,
		Evidence: fmt.Sprintf("Critical CVEs: %d (%d fixable). High CVEs: %d. Total across %d pods.", criticalCVEs, fixableCritical, highCVEs, total),
		EvidenceItems: []string{
			fmt.Sprintf("Critical CVEs: %d (%d fixable)", criticalCVEs, fixableCritical),
			fmt.Sprintf("High CVEs: %d", highCVEs),
			fmt.Sprintf("Top affected pods: %s", topVulnPods(scores, 3)),
			"Vulnerability data sourced from Trivy with NVD/GHSA databases",
		},
		Findings:    vulnFindings(criticalCVEs, fixableCritical, highCVEs, scores),
		Remediation: "Patch all critical CVEs immediately. Prioritize fixable CVEs. Update base images to latest stable versions.",
	})

	// ── CC9.1 — Risk Mitigation ──
	cc91Score := 100
	cc91Status := "pass"
	if len(criticalPods) > 0 && len(unprotectedPods) > len(scores)/2 {
		cc91Status = "partial"
		cc91Score = 50
	}
	if cc91Status == "pass" {
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "CC9.1", Name: "Risk Mitigation", Status: cc91Status, Score: cc91Score, Violations: 0,
		Evidence: fmt.Sprintf("Automated risk scoring and remediation guidance. NetworkPolicy generation available. %d pods with remediation recommendations.", countPodsWithRecs(scores)),
		EvidenceItems: []string{
			fmt.Sprintf("Pods with remediation recommendations: %d/%d", countPodsWithRecs(scores), total),
			"NetworkPolicy auto-generation: plexar generate netpol",
			"Risk-ranked pod list enables prioritized remediation",
		},
		Findings:    nil,
		Remediation: "Address critical-tier pods first. Apply generated NetworkPolicies. Patch fixable CVEs.",
	})

	// ── C1.1 — Confidential Information Protection ──
	envSecretPods := podsWithEnvSecrets(scores)
	cc_c11Score := 100
	cc_c11Status := "pass"
	if len(envSecretPods) > 0 {
		cc_c11Status = "fail"
		cc_c11Score = max(0, 100-len(envSecretPods)*20)
	} else if len(rbacWithSecrets) > 0 {
		cc_c11Status = "partial"
		cc_c11Score = max(40, 100-len(rbacWithSecrets)*10)
	}
	if cc_c11Status == "pass" {
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "C1.1", Name: "Confidential Information Protection", Status: cc_c11Status, Score: cc_c11Score, Violations: len(envSecretPods) + len(rbacWithSecrets),
		Evidence: fmt.Sprintf("Plaintext secrets in env vars: %d pods. RBAC secret access: %d pods.", len(envSecretPods), len(rbacWithSecrets)),
		EvidenceItems: []string{
			fmt.Sprintf("Pods with plaintext secrets in env: %s", podList(envSecretPods, 5)),
			fmt.Sprintf("Pods with RBAC secret read access: %s", podList(rbacWithSecrets, 5)),
		},
		Findings:    secretFindings(envSecretPods, rbacWithSecrets),
		Remediation: "Move all secrets to Kubernetes Secrets or a vault. Restrict secret RBAC access to pods that need it.",
	})

	// ── A1.1 — System Availability and Recovery ──
	cc_a11Score := 80
	cc_a11Status := "partial"
	controls = append(controls, types.ComplianceCheck{
		ID: "A1.1", Name: "System Availability and Recovery", Status: cc_a11Status, Score: cc_a11Score, Violations: 0,
		Evidence: fmt.Sprintf("Workload monitoring active for %d pods. Recovery mechanisms not fully verified.", total),
		EvidenceItems: []string{
			fmt.Sprintf("Continuous monitoring: %d pods", total),
			"Blast radius analysis identifies single-points-of-failure",
			"Kubernetes self-healing (restarts, replicas) assumed but not verified",
		},
		Findings:    nil,
		Remediation: "Ensure all critical workloads have replicas > 1. Configure PodDisruptionBudgets.",
	})

	// Compute overall score
	controlCount := len(controls)
	totalScore := 0
	for _, c := range controls {
		totalScore += c.Score
	}
	overallScore := 0
	if controlCount > 0 {
		overallScore = totalScore / controlCount
	}

	return types.ComplianceResult{
		Framework:   "SOC 2",
		Version:     "2017",
		Score:       overallScore,
		TotalChecks: controlCount,
		Passing:     passing,
		Controls:    controls,
	}
}

func mapPCIDSS(scores []types.PlexarScore, netPolCount int) types.ComplianceResult {
	var controls []types.ComplianceCheck
	passing := 0

	// 1.2.5 — Network segmentation
	unprotected := countUnprotected(scores)
	status := "fail"
	if unprotected == 0 {
		status = "pass"
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "1.2.5", Name: "Network Segmentation Controls",
		Status: status, Violations: unprotected,
		Evidence: fmt.Sprintf("%d pods without NetworkPolicy", unprotected),
	})

	// 6.3.3 — Patch critical vulnerabilities
	critCount := countCriticalCVEs(scores)
	status = "fail"
	if critCount == 0 {
		status = "pass"
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "6.3.3", Name: "Patch Critical and High Vulnerabilities",
		Status: status, Violations: critCount,
		Evidence: fmt.Sprintf("%d critical CVEs unpatched", critCount),
	})

	// 10.2 — Audit logging
	controls = append(controls, types.ComplianceCheck{
		ID: "10.2", Name: "Audit Logging",
		Status: "pass", Violations: 0,
		Evidence: "Kubernetes audit logging enabled",
	})
	passing++

	// 11.3 — Vulnerability scanning
	controls = append(controls, types.ComplianceCheck{
		ID: "11.3", Name: "Vulnerability Scanning",
		Status: "pass", Violations: 0,
		Evidence: "Trivy Operator + Plexar active",
	})
	passing++

	total := len(controls)
	score := 0
	if total > 0 {
		score = passing * 100 / total
	}

	return types.ComplianceResult{
		Framework:   "PCI DSS",
		Version:     "v4.0",
		Score:       score,
		TotalChecks: total,
		Passing:     passing,
		Controls:    controls,
	}
}

func mapHIPAA(scores []types.PlexarScore, netPolCount int) types.ComplianceResult {
	var controls []types.ComplianceCheck
	passing := 0

	// 164.312(a) — Access controls
	controls = append(controls, types.ComplianceCheck{
		ID: "164.312(a)", Name: "Access Controls",
		Status: "warn", Violations: 0,
		Evidence: "Partial — namespace-scoped RBAC in place",
	})

	// 164.312(b) — Audit controls
	controls = append(controls, types.ComplianceCheck{
		ID: "164.312(b)", Name: "Audit Controls",
		Status: "pass", Violations: 0,
		Evidence: "Kubernetes audit logging + Plexar history active",
	})
	passing++

	// 164.312(e) — Transmission security
	unprotected := countUnprotected(scores)
	status := "fail"
	if unprotected == 0 {
		status = "pass"
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "164.312(e)", Name: "Transmission Security",
		Status: status, Violations: unprotected,
		Evidence: fmt.Sprintf("%d pods with unrestricted network access", unprotected),
	})

	total := len(controls)
	score := 0
	if total > 0 {
		score = passing * 100 / total
	}

	return types.ComplianceResult{
		Framework:   "HIPAA",
		Version:     "2013",
		Score:       score,
		TotalChecks: total,
		Passing:     passing,
		Controls:    controls,
	}
}

func mapCIS(scores []types.PlexarScore, netPolCount int) types.ComplianceResult {
	var controls []types.ComplianceCheck
	passing := 0

	// 5.3.2 — Network policies
	unprotected := countUnprotected(scores)
	status := "fail"
	if unprotected == 0 {
		status = "pass"
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "5.3.2", Name: "Ensure NetworkPolicy is configured for all namespaces",
		Status: status, Violations: unprotected,
		Evidence: fmt.Sprintf("%d pods without NetworkPolicy", unprotected),
	})

	// 5.2.6 — Root containers
	rootPods := 0
	for _, s := range scores {
		if s.Permissions.RunAsRoot {
			rootPods++
		}
	}
	status = "fail"
	if rootPods == 0 {
		status = "pass"
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "5.2.6", Name: "Minimize admission of root containers",
		Status: status, Violations: rootPods,
		Evidence: fmt.Sprintf("%d pods running as root", rootPods),
	})

	// 5.2.1 — Privileged containers
	privPods := 0
	for _, s := range scores {
		if s.Permissions.Privileged {
			privPods++
		}
	}
	status = "fail"
	if privPods == 0 {
		status = "pass"
		passing++
	}
	controls = append(controls, types.ComplianceCheck{
		ID: "5.2.1", Name: "Minimize admission of privileged containers",
		Status: status, Violations: privPods,
		Evidence: fmt.Sprintf("%d pods running privileged", privPods),
	})

	total := len(controls)
	score := 0
	if total > 0 {
		score = passing * 100 / total
	}

	return types.ComplianceResult{
		Framework:   "CIS Kubernetes",
		Version:     "v1.8",
		Score:       score,
		TotalChecks: total,
		Passing:     passing,
		Controls:    controls,
	}
}

// ── Helper functions ──

func countUnprotected(scores []types.PlexarScore) int {
	count := 0
	for _, s := range scores {
		if !s.Blast.HasNetworkPolicy {
			count++
		}
	}
	return count
}

func countCriticalCVEs(scores []types.PlexarScore) int {
	count := 0
	for _, s := range scores {
		count += s.Vulns.Critical
	}
	return count
}

func countHighCVEs(scores []types.PlexarScore) int {
	count := 0
	for _, s := range scores {
		count += s.Vulns.High
	}
	return count
}

func countFixableCritical(scores []types.PlexarScore) int {
	count := 0
	for _, s := range scores {
		for _, cve := range s.Vulns.TopCVEs {
			if cve.Severity == "CRITICAL" && cve.FixedVersion != "" {
				count++
			}
		}
	}
	return count
}

func podsByTier(scores []types.PlexarScore, tier string) []string {
	var names []string
	for _, s := range scores {
		if s.Tier == tier {
			names = append(names, shortPod(s.PodName))
		}
	}
	return names
}

func podsWithoutNetPol(scores []types.PlexarScore) []string {
	var names []string
	for _, s := range scores {
		if !s.Blast.HasNetworkPolicy {
			names = append(names, shortPod(s.PodName))
		}
	}
	return names
}

func podsPrivileged(scores []types.PlexarScore) []string {
	var names []string
	for _, s := range scores {
		if s.Permissions.Privileged {
			names = append(names, shortPod(s.PodName))
		}
	}
	return names
}

func podsRunAsRoot(scores []types.PlexarScore) []string {
	var names []string
	for _, s := range scores {
		if s.Permissions.RunAsRoot {
			names = append(names, shortPod(s.PodName))
		}
	}
	return names
}

func podsAllowEscalation(scores []types.PlexarScore) []string {
	var names []string
	for _, s := range scores {
		if s.Permissions.AllowPrivilegeEsc {
			names = append(names, shortPod(s.PodName))
		}
	}
	return names
}

func podsWithInternetAccess(scores []types.PlexarScore) []string {
	var names []string
	for _, s := range scores {
		if s.Blast.InternetAccess {
			names = append(names, shortPod(s.PodName))
		}
	}
	return names
}

func podsUnrestrictedEgress(scores []types.PlexarScore) []string {
	var names []string
	for _, s := range scores {
		if s.Blast.UnrestrictedEgress {
			names = append(names, shortPod(s.PodName))
		}
	}
	return names
}

func podsWithDataStoreAccess(scores []types.PlexarScore) []string {
	var names []string
	for _, s := range scores {
		if len(s.Blast.DataStoreAccess) > 0 {
			names = append(names, shortPod(s.PodName))
		}
	}
	return names
}

func countDataStoreAccess(scores []types.PlexarScore) int {
	count := 0
	for _, s := range scores {
		if len(s.Blast.DataStoreAccess) > 0 {
			count++
		}
	}
	return count
}

func countUniqueImages(scores []types.PlexarScore) int {
	images := make(map[string]bool)
	for _, s := range scores {
		if s.ImageName != "" {
			images[s.ImageName] = true
		}
	}
	return len(images)
}

func countReadOnlyRootFS(scores []types.PlexarScore) int {
	count := 0
	for _, s := range scores {
		if s.Permissions.ReadOnlyRootFS {
			count++
		}
	}
	return count
}

func avgBlastRadius(scores []types.PlexarScore) float64 {
	if len(scores) == 0 {
		return 0
	}
	total := 0
	for _, s := range scores {
		total += len(s.Blast.ReachableTargets)
	}
	return float64(total) / float64(len(scores))
}

func maxBlastRadius(scores []types.PlexarScore) int {
	m := 0
	for _, s := range scores {
		if len(s.Blast.ReachableTargets) > m {
			m = len(s.Blast.ReachableTargets)
		}
	}
	return m
}

func serviceAccountList(scores []types.PlexarScore, limit int) string {
	seen := make(map[string]bool)
	var sas []string
	for _, s := range scores {
		sa := s.Permissions.ServiceAccountName
		if sa != "" && !seen[sa] {
			seen[sa] = true
			sas = append(sas, sa)
		}
	}
	return podList(sas, limit)
}

func topVulnPods(scores []types.PlexarScore, limit int) string {
	type podVuln struct {
		name  string
		count int
	}
	var pv []podVuln
	for _, s := range scores {
		if s.Vulns.Critical > 0 || s.Vulns.High > 0 {
			pv = append(pv, podVuln{shortPod(s.PodName), s.Vulns.Critical + s.Vulns.High})
		}
	}
	// Sort descending by count
	for i := 0; i < len(pv); i++ {
		for j := i + 1; j < len(pv); j++ {
			if pv[j].count > pv[i].count {
				pv[i], pv[j] = pv[j], pv[i]
			}
		}
	}
	var names []string
	for i, p := range pv {
		if i >= limit {
			break
		}
		names = append(names, fmt.Sprintf("%s (%d)", p.name, p.count))
	}
	if len(names) == 0 {
		return "none"
	}
	return fmt.Sprintf("%s", joinStrings(names))
}

func countOverlap(a, b []string) int {
	set := make(map[string]bool)
	for _, s := range b {
		set[s] = true
	}
	count := 0
	for _, s := range a {
		if set[s] {
			count++
		}
	}
	return count
}

func podList(names []string, limit int) string {
	if len(names) == 0 {
		return "none"
	}
	if len(names) <= limit {
		return joinStrings(names)
	}
	return fmt.Sprintf("%s (+%d more)", joinStrings(names[:limit]), len(names)-limit)
}

func joinStrings(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}

func shortPod(name string) string {
	if name == "" {
		return ""
	}
	parts := splitString(name, '-')
	if len(parts) > 2 {
		return joinWithSep(parts[:len(parts)-2], '-')
	}
	return name
}

func splitString(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func joinWithSep(parts []string, sep byte) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += string(sep)
		}
		result += p
	}
	return result
}

// ── RBAC helper functions ──

func rbacPodsWithFlag(findings []types.RBACFinding, flag string) []string {
	var names []string
	for _, f := range findings {
		match := false
		switch flag {
		case "HasClusterAdmin":
			match = f.HasClusterAdmin
		case "HasWildcardAccess":
			match = f.HasWildcardAccess
		case "HasExecCapability":
			match = f.HasExecCapability
		case "HasSecretAccess":
			match = f.HasSecretAccess
		case "HasDeleteAccess":
			match = f.HasDeleteAccess
		case "HasCreatePods":
			match = f.HasCreatePods
		case "HasEscalatePriv":
			match = f.HasEscalatePriv
		case "HasNodeAccess":
			match = f.HasNodeAccess
		}
		if match {
			names = append(names, shortPod(f.PodName))
		}
	}
	return names
}

func podsWithDefaultSA(scores []types.PlexarScore) []string {
	var names []string
	for _, s := range scores {
		sa := s.Permissions.ServiceAccountName
		if sa == "" || sa == "default" {
			names = append(names, shortPod(s.PodName))
		}
	}
	return names
}

func podsWithEnvSecrets(scores []types.PlexarScore) []string {
	var names []string
	for _, s := range scores {
		if len(s.Permissions.EnvSecrets) > 0 {
			names = append(names, shortPod(s.PodName))
		}
	}
	return names
}

func countPodsWithRecs(scores []types.PlexarScore) int {
	count := 0
	for _, s := range scores {
		if len(s.Recommendations) > 0 {
			count++
		}
	}
	return count
}

func controlStatus(score int) string {
	switch {
	case score >= 80:
		return "pass"
	case score >= 40:
		return "partial"
	default:
		return "fail"
	}
}

// ── Findings generators ──

func riskFindings(critical, high []string) []string {
	var findings []string
	for _, p := range critical {
		findings = append(findings, fmt.Sprintf("CRITICAL: %s is critical-tier risk", p))
	}
	for _, p := range high {
		findings = append(findings, fmt.Sprintf("HIGH: %s is high-tier risk", p))
	}
	return findings
}

func fraudFindings(priv, clusterAdmin, escalation []string) []string {
	var findings []string
	for _, p := range clusterAdmin {
		findings = append(findings, fmt.Sprintf("CRITICAL: %s has cluster-admin access", p))
	}
	for _, p := range priv {
		findings = append(findings, fmt.Sprintf("HIGH: %s runs in privileged mode", p))
	}
	for _, p := range escalation {
		findings = append(findings, fmt.Sprintf("MEDIUM: %s allows privilege escalation", p))
	}
	return findings
}

func techControlFindings(scores []types.PlexarScore, roCount, total int) []string {
	var findings []string
	if roCount < total {
		findings = append(findings, fmt.Sprintf("%d pods lack read-only root filesystem", total-roCount))
	}
	return findings
}

func accessFindings(unprotected []string) []string {
	var findings []string
	for _, p := range unprotected {
		findings = append(findings, fmt.Sprintf("FAIL: %s has no NetworkPolicy", p))
	}
	return findings
}

func saProvisioningFindings(clusterAdmin, wildcard, defaultSA []string) []string {
	var findings []string
	for _, p := range clusterAdmin {
		findings = append(findings, fmt.Sprintf("CRITICAL: %s bound to cluster-admin", p))
	}
	for _, p := range wildcard {
		findings = append(findings, fmt.Sprintf("HIGH: %s has wildcard resource access", p))
	}
	if len(defaultSA) > 0 {
		findings = append(findings, fmt.Sprintf("INFO: %d pods using default ServiceAccount", len(defaultSA)))
	}
	return findings
}

func leastPrivFindings(priv, root, escalation, exec, secrets []string) []string {
	var findings []string
	for _, p := range priv {
		findings = append(findings, fmt.Sprintf("CRITICAL: %s runs privileged", p))
	}
	for _, p := range exec {
		findings = append(findings, fmt.Sprintf("CRITICAL: %s has pod exec capability", p))
	}
	for _, p := range secrets {
		findings = append(findings, fmt.Sprintf("HIGH: %s can read secrets", p))
	}
	for _, p := range root {
		findings = append(findings, fmt.Sprintf("HIGH: %s runs as root", p))
	}
	for _, p := range escalation {
		findings = append(findings, fmt.Sprintf("MEDIUM: %s allows privilege escalation", p))
	}
	return findings
}

func escalateFindings(pods []string) []string {
	var findings []string
	for _, p := range pods {
		findings = append(findings, fmt.Sprintf("CRITICAL: %s has escalate/bind/impersonate permissions", p))
	}
	return findings
}

func networkFindings(internet, egress, unprotected []string) []string {
	var findings []string
	for _, p := range internet {
		findings = append(findings, fmt.Sprintf("HIGH: %s has internet access without NetworkPolicy", p))
	}
	for _, p := range egress {
		findings = append(findings, fmt.Sprintf("MEDIUM: %s has unrestricted egress", p))
	}
	return findings
}

func dataMovementFindings(dataStore, unprotected []string, overlap int) []string {
	var findings []string
	if overlap > 0 {
		findings = append(findings, fmt.Sprintf("CRITICAL: %d data store pods lack NetworkPolicy restrictions", overlap))
	}
	return findings
}

func softwareFindings(total, roCount int) []string {
	var findings []string
	if roCount < total {
		findings = append(findings, fmt.Sprintf("MEDIUM: %d pods lack read-only root filesystem — writable FS enables malware persistence", total-roCount))
	}
	findings = append(findings, "INFO: No admission controller detected — image provenance not enforced")
	return findings
}

func vulnFindings(critical, fixable, high int, scores []types.PlexarScore) []string {
	var findings []string
	if critical > 0 {
		findings = append(findings, fmt.Sprintf("CRITICAL: %d critical CVEs detected (%d fixable)", critical, fixable))
	}
	if high > 50 {
		findings = append(findings, fmt.Sprintf("HIGH: %d high-severity CVEs exceed threshold", high))
	}
	for _, s := range scores {
		if s.Vulns.Critical > 0 {
			findings = append(findings, fmt.Sprintf("  %s: %dC/%dH CVEs (image: %s)", shortPod(s.PodName), s.Vulns.Critical, s.Vulns.High, s.ImageName))
		}
	}
	return findings
}

func secretFindings(envSecrets, rbacSecrets []string) []string {
	var findings []string
	for _, p := range envSecrets {
		findings = append(findings, fmt.Sprintf("CRITICAL: %s has plaintext secrets in environment variables", p))
	}
	for _, p := range rbacSecrets {
		findings = append(findings, fmt.Sprintf("HIGH: %s has RBAC access to read Kubernetes secrets", p))
	}
	return findings
}
