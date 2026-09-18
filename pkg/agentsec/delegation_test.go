package agentsec

import (
	"testing"

	"github.com/plexar-io/plexar/internal/types"
)

// buildNDFCScores returns a realistic set of scores based on NDFC production data
func buildNDFCScores() []types.PlexarScore {
	return []types.PlexarScore{
		{
			PodName:       "agentmgr-7c6ccbb9b4-tt9qx",
			Namespace:     "cisco-ndfc",
			ImageName:     "apps/cisco-ndfc/agentmgr:v12_6_0_267",
			WorkloadClass: "AI Agent Runtime",
			Vulns: types.VulnSummary{
				Critical: 4, High: 72, TotalCount: 387,
				AllCVEs: makeCVEs(78, 387),
			},
			Blast: types.BlastRadius{
				PodName: "agentmgr-7c6ccbb9b4-tt9qx",
				ReachableTargets: makeTargets(107, []string{
					"mcpserver.mcp", "cockroachdb.cdb", "mongodb.mongodb",
					"authy.authy", "securitymgr.securitymgr",
					"sensei.cisco-nir", "es-data.opensearch",
				}),
				HasNetworkPolicy: false,
				InternetAccess:   true,
			},
			Permissions: types.PodPermissions{ServiceAccountName: "default"},
		},
		{
			PodName:       "mcpserver-5cbd97ff59-85rgm",
			Namespace:     "mcp",
			ImageName:     "infra/mcp/mcpserver:1.0.0",
			WorkloadClass: "MCP Server",
			Vulns: types.VulnSummary{
				Critical: 0, High: 20, TotalCount: 182,
				AllCVEs: makeCVEs(39, 182),
			},
			Blast: types.BlastRadius{
				PodName: "mcpserver-5cbd97ff59-85rgm",
				ReachableTargets: makeTargets(107, []string{
					"cockroachdb.cdb", "mongodb.mongodb", "es-data.opensearch",
					"authy.authy", "authy-oidc.authy-oidc", "securitymgr.securitymgr",
					"sensei.cisco-nir", "beaver.cisco-nir", "horcrux.cisco-nir",
					"dcnm-admin.cisco-ndfc", "kafka.kafka",
				}),
				HasNetworkPolicy: false,
				InternetAccess:   true,
			},
			Permissions: types.PodPermissions{ServiceAccountName: "default"},
		},
		{
			PodName:       "sensei-7dc5bf9f6b-qvxx8",
			Namespace:     "cisco-nir",
			ImageName:     "apps/cisco-nir/telemetry/sensei:6.9.1.21",
			WorkloadClass: "ML / AI Workload",
			Vulns: types.VulnSummary{
				Critical: 2, High: 40, TotalCount: 291,
				AllCVEs: makeCVEs(46, 291),
			},
			Blast: types.BlastRadius{
				PodName: "sensei-7dc5bf9f6b-qvxx8",
				ReachableTargets: makeTargets(107, []string{
					"mcpserver.mcp", "cockroachdb.cdb", "mongodb.mongodb",
				}),
				HasNetworkPolicy: false,
				InternetAccess:   true,
			},
			Permissions: types.PodPermissions{ServiceAccountName: "nir-admin"},
		},
		{
			PodName:       "beaver-5ffb56b94d-dpn6v",
			Namespace:     "cisco-nir",
			ImageName:     "apps/cisco-nir/telemetry/beaver:6.9.1.21",
			WorkloadClass: "General Application",
			Vulns: types.VulnSummary{
				Critical: 1, High: 30, TotalCount: 250,
				AllCVEs: makeCVEs(40, 250),
			},
			Blast: types.BlastRadius{
				PodName: "beaver-5ffb56b94d-dpn6v",
				ReachableTargets: makeTargets(107, []string{
					"cockroachdb.cdb", "mongodb.mongodb",
				}),
				HasNetworkPolicy: false,
				InternetAccess:   true,
			},
			Permissions: types.PodPermissions{ServiceAccountName: "nir-admin"},
		},
		{
			PodName:       "dcnm-admin-67864f5ff-b46q5",
			Namespace:     "cisco-ndfc",
			ImageName:     "apps/cisco-ndfc/dcnm-admin:v12_6_0_267",
			WorkloadClass: "General Application",
			Vulns: types.VulnSummary{
				Critical: 3, High: 60, TotalCount: 400,
				AllCVEs: makeCVEs(80, 400),
			},
			Blast: types.BlastRadius{
				PodName: "dcnm-admin-67864f5ff-b46q5",
				ReachableTargets: makeTargets(107, []string{
					"cockroachdb.cdb",
				}),
				HasNetworkPolicy: false,
			},
			Permissions: types.PodPermissions{ServiceAccountName: "dcnm-admin"},
		},
		{
			PodName:       "cockroachdb-0",
			Namespace:     "cdb",
			ImageName:     "cockroachdb/cockroach:v23.1.0",
			WorkloadClass: "Database",
			Blast: types.BlastRadius{
				PodName:          "cockroachdb-0",
				HasNetworkPolicy: false,
			},
			Permissions: types.PodPermissions{ServiceAccountName: "default"},
		},
	}
}

func buildNDFCRBAC() []types.RBACFinding {
	return []types.RBACFinding{
		{
			PodName:            "agentmgr-7c6ccbb9b4-tt9qx",
			Namespace:          "cisco-ndfc",
			ServiceAccountName: "default",
			RiskScore:          5,
			RiskLevel:          "low",
		},
		{
			PodName:            "mcpserver-5cbd97ff59-85rgm",
			Namespace:          "mcp",
			ServiceAccountName: "default",
			RiskScore:          5,
			RiskLevel:          "low",
		},
		{
			PodName:            "sensei-7dc5bf9f6b-qvxx8",
			Namespace:          "cisco-nir",
			ServiceAccountName: "nir-admin",
			RiskScore:          35,
			RiskLevel:          "medium",
			HasSecretAccess:    true,
			HasDeleteAccess:    true,
			HasCreatePods:      true,
		},
		{
			PodName:            "beaver-5ffb56b94d-dpn6v",
			Namespace:          "cisco-nir",
			ServiceAccountName: "nir-admin",
			RiskScore:          35,
			RiskLevel:          "medium",
			HasSecretAccess:    true,
			HasDeleteAccess:    true,
			HasCreatePods:      true,
		},
		{
			PodName:            "dcnm-admin-67864f5ff-b46q5",
			Namespace:          "cisco-ndfc",
			ServiceAccountName: "dcnm-admin",
			RiskScore:          60,
			RiskLevel:          "high",
			HasWildcardAccess:  true,
			HasSecretAccess:    true,
			HasDeleteAccess:    true,
			HasCreatePods:      true,
		},
		{
			PodName:            "cockroachdb-0",
			Namespace:          "cdb",
			ServiceAccountName: "default",
			RiskScore:          5,
			RiskLevel:          "low",
		},
	}
}

func TestDelegationChainDetection(t *testing.T) {
	scores := buildNDFCScores()
	rbac := buildNDFCRBAC()

	chains, summary := AnalyzeDelegation(scores, rbac)

	if len(chains) == 0 {
		t.Fatal("expected at least 1 delegation chain")
	}
	if summary == nil {
		t.Fatal("expected delegation summary")
	}

	t.Logf("Chains: %d, Critical: %d, Scope violations: %d, Auth gaps: %d",
		summary.TotalChains, summary.CriticalChains, summary.ScopeViolations, summary.AuthGaps)

	// Should find chain: agentmgr -> mcpserver -> [elevated RBAC targets]
	foundAgentMCPChain := false
	for _, chain := range chains {
		if len(chain.Hops) >= 2 {
			if chain.Hops[0].PodName == "agentmgr-7c6ccbb9b4-tt9qx" &&
				chain.Hops[1].PodName == "mcpserver-5cbd97ff59-85rgm" {
				foundAgentMCPChain = true
				t.Logf("Chain: %s, Exposure: %s, Score: %d",
					chain.ID, chain.Exposure, chain.ExposureScore)
				for _, v := range chain.Violations {
					t.Logf("  Violation: %s", v)
				}
				for _, tt := range chain.TerminalTargets {
					t.Logf("  Terminal: %s", tt)
				}
				break
			}
		}
	}
	if !foundAgentMCPChain {
		t.Error("expected chain from agentmgr -> mcpserver")
	}
}

func TestScopeWidening(t *testing.T) {
	scores := buildNDFCScores()
	rbac := buildNDFCRBAC()

	chains, _ := AnalyzeDelegation(scores, rbac)

	// Check that scope violations are detected where RBAC privilege increases
	foundRBACViolation := false
	for _, chain := range chains {
		for _, v := range chain.Violations {
			if containsStr(v, "RBAC") && containsStr(v, "INCREASES") {
				foundRBACViolation = true
				t.Logf("Found RBAC scope violation: %s", v)
			}
		}
	}
	if !foundRBACViolation {
		t.Error("expected RBAC scope violation (MCP reaches sensei/dcnm-admin with elevated RBAC)")
	}

	// Check auth gap detection
	foundAuthGap := false
	for _, chain := range chains {
		for _, v := range chain.Violations {
			if containsStr(v, "No auth boundary") {
				foundAuthGap = true
				break
			}
		}
	}
	if !foundAuthGap {
		t.Error("expected auth gap violation (no NetworkPolicy between hops)")
	}
}

func TestScopeNarrowing(t *testing.T) {
	// Create a scenario where scope properly narrows
	scores := []types.PlexarScore{
		{
			PodName:       "agent-aaa-bbb",
			Namespace:     "default",
			WorkloadClass: "AI Agent Runtime",
			Blast: types.BlastRadius{
				PodName:          "agent-aaa-bbb",
				ReachableTargets: makeTargets(50, []string{"mcpserver.mcp"}),
				HasNetworkPolicy: true,
			},
			Permissions: types.PodPermissions{ServiceAccountName: "agent-sa"},
		},
		{
			PodName:       "mcpserver-ccc-ddd",
			Namespace:     "mcp",
			ImageName:     "mcp/server:1.0",
			WorkloadClass: "MCP Server",
			Blast: types.BlastRadius{
				PodName:          "mcpserver-ccc-ddd",
				ReachableTargets: makeTargets(10, []string{"db.data"}),
				HasNetworkPolicy: true,
			},
			Permissions: types.PodPermissions{ServiceAccountName: "mcp-sa"},
		},
	}
	rbac := []types.RBACFinding{
		{PodName: "agent-aaa-bbb", ServiceAccountName: "agent-sa", RiskScore: 20, RiskLevel: "low"},
		{PodName: "mcpserver-ccc-ddd", ServiceAccountName: "mcp-sa", RiskScore: 5, RiskLevel: "low"},
	}

	chains, summary := AnalyzeDelegation(scores, rbac)

	if len(chains) == 0 {
		t.Fatal("expected at least 1 chain")
	}

	// In this scenario, blast narrows (50 -> 10) and RBAC narrows (20 -> 5)
	// So scope violations should be 0
	if summary.ScopeViolations > 0 {
		t.Errorf("expected 0 scope violations for narrowing chain, got %d", summary.ScopeViolations)
	}

	// Check the chain has lower exposure
	chain := chains[0]
	if chain.Exposure == "critical" {
		t.Errorf("expected non-critical exposure for narrowing chain, got %s", chain.Exposure)
	}
	t.Logf("Narrowing chain: exposure=%s score=%d", chain.Exposure, chain.ExposureScore)
}

func TestTerminalTargetDetection(t *testing.T) {
	scores := buildNDFCScores()
	rbac := buildNDFCRBAC()

	chains, summary := AnalyzeDelegation(scores, rbac)

	// Should detect secrets reachable through elevated-RBAC pods
	if summary.SecretsReachable == 0 {
		t.Error("expected secrets to be reachable through delegation chains (sensei/dcnm-admin have secret access)")
	}

	// Should detect data stores
	if summary.DataStores == 0 {
		t.Error("expected data stores reachable through chains (cockroachdb, mongodb, opensearch)")
	}

	// Check terminal targets include secrets
	foundSecrets := false
	for _, chain := range chains {
		for _, tt := range chain.TerminalTargets {
			if containsStr(tt, "secrets") {
				foundSecrets = true
				break
			}
		}
	}
	if !foundSecrets {
		t.Error("expected 'secrets' in terminal targets")
	}
}

func TestAnalyzeWithRBAC(t *testing.T) {
	scores := buildNDFCScores()
	rbac := buildNDFCRBAC()

	summary := AnalyzeWithRBAC(scores, rbac)

	// Should have both agent analysis and delegation chains
	if summary.TotalAgentPods == 0 {
		t.Error("expected agent pods")
	}
	if summary.DelegationSummary == nil {
		t.Error("expected delegation summary")
	}
	if len(summary.DelegationChains) == 0 {
		t.Error("expected delegation chains")
	}

	t.Logf("Agent pods: %d, MCP: %d, Delegation chains: %d, Critical: %d",
		summary.TotalAgentPods, summary.MCPServers,
		summary.DelegationSummary.TotalChains, summary.DelegationSummary.CriticalChains)
}

func TestFixRecommendation(t *testing.T) {
	scores := buildNDFCScores()
	rbac := buildNDFCRBAC()

	chains, _ := AnalyzeDelegation(scores, rbac)

	for _, chain := range chains {
		if chain.Fix == "" {
			t.Errorf("chain %s should have a fix recommendation", chain.ID)
		}
		t.Logf("Chain %s fix: %s", chain.ID, chain.Fix)
	}
}

// Helpers

func makeCVEs(inUse, total int) []types.CVEInfo {
	cves := make([]types.CVEInfo, total)
	for i := range cves {
		cves[i] = types.CVEInfo{
			ID:       "CVE-2026-" + itoa(10000+i),
			Severity: "HIGH",
			CVSS:     7.5,
			InUse:    i < inUse,
		}
	}
	return cves
}

func makeTargets(count int, named []string) []string {
	targets := make([]string, 0, count)
	targets = append(targets, named...)
	for i := len(named); i < count; i++ {
		targets = append(targets, "svc-"+itoa(i)+".ns-"+itoa(i%5))
	}
	return targets
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
