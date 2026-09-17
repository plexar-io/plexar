package agentsec

import (
	"testing"

	"github.com/plexar-io/plexar/internal/types"
)

func TestAnalyzeNDFCLike(t *testing.T) {
	// Simulate NDFC-like scan with MCP server + agent pods
	scores := []types.PlexarScore{
		{
			PodName:       "mcpserver-5cbd97ff59-85rgm",
			ImageName:     "infra/mcp/mcpserver:1.0.0",
			WorkloadClass: "MCP Server",
			Blast: types.BlastRadius{
				PodName:          "mcpserver-5cbd97ff59-85rgm",
				HasNetworkPolicy: false,
				InternetAccess:   true,
				ReachableTargets: []string{
					"agentmgr.cisco-ndfc",
					"cockroachdb.cdb",
					"mongodb.mongodb",
					"authy-oidc-svc.authy-oidc",
					"securitymgr-svc.securitymgr",
					"elasticsearch-data.opensearch",
				},
			},
			Permissions: types.PodPermissions{ServiceAccountName: "default"},
		},
		{
			PodName:       "agentmgr-7c6ccbb9b4-tt9qx",
			ImageName:     "apps/cisco-ndfc/agentmgr:v12_6_0_267",
			WorkloadClass: "AI Agent Runtime",
			RiskMultiplier: 1.55,
			Blast: types.BlastRadius{
				PodName:          "agentmgr-7c6ccbb9b4-tt9qx",
				HasNetworkPolicy: false,
				InternetAccess:   true,
				ReachableTargets: []string{
					"mcpserver.mcp",
					"cockroachdb.cdb",
					"mongodb.mongodb",
				},
			},
			Permissions: types.PodPermissions{ServiceAccountName: "default"},
		},
		{
			PodName:       "sensei-7dc5bf9f6b-qvxx8",
			ImageName:     "apps/cisco-nir/telemetry/sensei:6.9.1.21",
			WorkloadClass: "ML / AI Workload",
			Blast: types.BlastRadius{
				PodName:          "sensei-7dc5bf9f6b-qvxx8",
				HasNetworkPolicy: false,
				InternetAccess:   true,
				ReachableTargets: []string{"mcpserver.mcp", "palantir.cisco-nir"},
			},
			Permissions: types.PodPermissions{ServiceAccountName: "nir-admin"},
		},
		{
			PodName:       "cockroachdb-0",
			ImageName:     "cockroachdb/cockroach:v23.1.0",
			WorkloadClass: "Database",
			Blast: types.BlastRadius{
				PodName:          "cockroachdb-0",
				HasNetworkPolicy: false,
				ReachableTargets: []string{},
			},
			Permissions: types.PodPermissions{ServiceAccountName: "default"},
		},
	}

	summary := Analyze(scores)

	// Should find 1 MCP server
	if summary.MCPServers != 1 {
		t.Errorf("MCPServers = %d, want 1", summary.MCPServers)
	}

	// Should find 2 agent pods total (MCP + agentmgr; sensei is ML not agent class)
	// Actually: MCP Server, AI Agent Runtime, ML/AI Workload are all checked via IsAgentClass
	// ML/AI Workload is NOT in IsAgentClass, so total should be 2
	if summary.TotalAgentPods < 2 {
		t.Errorf("TotalAgentPods = %d, want >= 2", summary.TotalAgentPods)
	}

	// All agent pods lack NetworkPolicy
	if summary.UnprotectedAgents < 2 {
		t.Errorf("UnprotectedAgents = %d, want >= 2", summary.UnprotectedAgents)
	}

	// MCP server should have agent context
	mcpScore := &scores[0]
	if mcpScore.AgentContext == nil {
		t.Fatal("mcpserver should have AgentContext")
	}
	if !mcpScore.AgentContext.IsAgentWorkload {
		t.Error("mcpserver should be marked as agent workload")
	}
	if len(mcpScore.AgentContext.Warnings) == 0 {
		t.Error("mcpserver should have security warnings")
	}
	if mcpScore.AgentContext.AgentBlastRadius < 5 {
		t.Errorf("mcpserver agent blast radius = %d, want >= 5", mcpScore.AgentContext.AgentBlastRadius)
	}

	// Agent should have connected MCPs
	agentScore := &scores[1]
	if agentScore.AgentContext == nil {
		t.Fatal("agentmgr should have AgentContext")
	}
	if len(agentScore.AgentContext.ConnectedMCPs) == 0 {
		t.Error("agentmgr should have connected MCP servers")
	}

	// Should have high-risk findings
	if len(summary.HighRiskFindings) == 0 {
		t.Error("should have high-risk findings for unprotected MCP server")
	}

	// Should have dependency edges
	if len(summary.AgentDependencies) == 0 {
		t.Error("should have agent dependency edges")
	}

	// Check that agent_to_mcp edge exists
	foundAgentToMCP := false
	for _, edge := range summary.AgentDependencies {
		if edge.EdgeType == "agent_to_mcp" && edge.From == "agentmgr-7c6ccbb9b4-tt9qx" {
			foundAgentToMCP = true
		}
	}
	if !foundAgentToMCP {
		t.Error("should have agent_to_mcp edge from agentmgr to mcpserver")
	}

	// Database should NOT have agent context
	dbScore := &scores[3]
	if dbScore.AgentContext != nil {
		t.Error("cockroachdb should NOT have AgentContext")
	}
}
