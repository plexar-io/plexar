package attackpath

import (
	"testing"

	"github.com/plexar-io/plexar/internal/types"
)

func TestFindExploitChains_SSRFToRCE(t *testing.T) {
	g := NewGraph()

	// internet -> web (SSRF) -> api (RCE) -> secrets
	g.addNode("internet", "internet", "Internet", 0, nil)
	g.Nodes["internet"].CVEs = nil

	g.addNode("pod:web", "pod", "web", 70, map[string]string{"class": "api-gateway"})
	g.Nodes["pod:web"].CVEs = []types.CVEInfo{
		{ID: "CVE-2021-26855", CVSS: 9.8, ExploitType: ExploitSSRF, InUse: true, Package: "proxy-lib"},
	}

	g.addNode("pod:api", "pod", "api", 60, map[string]string{"class": "backend"})
	g.Nodes["pod:api"].CVEs = []types.CVEInfo{
		{ID: "CVE-2021-44228", CVSS: 10.0, ExploitType: ExploitRCE, InUse: true, Package: "log4j-core"},
	}

	g.addNode("secrets", "secret", "Kubernetes Secrets", 80, nil)

	g.addEdge("internet", "pod:web", "network_reach", "Internet to web", 1)
	g.addEdge("pod:web", "pod:api", "network_reach", "Web to API", 3)
	g.addEdge("pod:api", "secrets", "secret_access", "API reads secrets", 2)

	chains, summary := FindExploitChains(g)

	if len(chains) == 0 {
		t.Fatal("Expected at least one exploit chain")
	}

	if summary.TotalChains == 0 {
		t.Error("Expected TotalChains > 0")
	}

	// Verify chains have CVE hops (search across all chains)
	foundSSRF := false
	foundRCE := false
	for _, chain := range chains {
		for _, hop := range chain.Hops {
			if hop.ExploitType == ExploitSSRF {
				foundSSRF = true
			}
			if hop.ExploitType == ExploitRCE {
				foundRCE = true
			}
		}
		if chain.ChainScore <= 0 {
			t.Errorf("Chain %s has non-positive score", chain.ID)
		}
	}
	if !foundSSRF {
		t.Error("Expected SSRF hop in at least one chain")
	}
	if !foundRCE {
		t.Error("Expected RCE hop in at least one chain")
	}
}

func TestFindExploitChains_BlockedByMissingCVE(t *testing.T) {
	g := NewGraph()

	// internet -> web (no CVEs) -> api -> secrets
	// Chain should NOT form because web has no enabling CVE
	g.addNode("internet", "internet", "Internet", 0, nil)

	g.addNode("pod:web", "pod", "web", 40, nil)
	g.Nodes["pod:web"].CVEs = nil // No CVEs

	g.addNode("pod:api", "pod", "api", 30, nil)
	g.Nodes["pod:api"].CVEs = []types.CVEInfo{
		{ID: "CVE-2021-44228", CVSS: 10.0, ExploitType: ExploitRCE, Package: "log4j-core"},
	}

	g.addNode("secrets", "secret", "Kubernetes Secrets", 80, nil)

	g.addEdge("internet", "pod:web", "network_reach", "Internet to web", 1)
	g.addEdge("pod:web", "pod:api", "network_reach", "Web to API", 3)
	g.addEdge("pod:api", "secrets", "secret_access", "API reads secrets", 2)

	chains, _ := FindExploitChains(g)

	// Chains should be empty or not contain a full CVE-validated network hop chain
	for _, chain := range chains {
		for _, hop := range chain.Hops {
			if hop.NodeID == "pod:web" && hop.CVE.ID != "" {
				t.Error("web node should not have a CVE hop — it has no CVEs")
			}
		}
	}
}

func TestFindExploitChains_AgentBoost(t *testing.T) {
	g := NewGraph()

	g.addNode("internet", "internet", "Internet", 0, nil)

	g.addNode("pod:gateway", "pod", "gateway", 60, map[string]string{"class": "api-gateway"})
	g.Nodes["pod:gateway"].CVEs = []types.CVEInfo{
		{ID: "CVE-2099-0001", CVSS: 8.0, ExploitType: ExploitSSRF, Package: "http-proxy"},
	}

	g.addNode("pod:agent", "pod", "agent", 70, map[string]string{"class": "ai-agent"})
	g.Nodes["pod:agent"].IsAgent = true
	g.Nodes["pod:agent"].CVEs = []types.CVEInfo{
		{ID: "CVE-2099-0002", CVSS: 9.0, ExploitType: ExploitRCE, Package: "langchain"},
	}

	g.addNode("secrets", "secret", "Kubernetes Secrets", 80, nil)

	g.addEdge("internet", "pod:gateway", "network_reach", "Internet to gateway", 1)
	g.addEdge("pod:gateway", "pod:agent", "network_reach", "Gateway to agent", 3)
	g.addEdge("pod:agent", "secrets", "secret_access", "Agent reads secrets", 2)

	chains, summary := FindExploitChains(g)

	if len(chains) == 0 {
		t.Fatal("Expected at least one exploit chain")
	}

	// Find chain through agent
	foundAgentChain := false
	for _, chain := range chains {
		if chain.HasAgentNode {
			foundAgentChain = true
			if len(chain.AgentNodes) == 0 {
				t.Error("Expected agent nodes list to be populated")
			}
			break
		}
	}

	if !foundAgentChain {
		t.Error("Expected at least one agent-boosted chain")
	}

	if summary.AgentChains == 0 {
		t.Error("Expected AgentChains > 0 in summary")
	}
}

func TestFindExploitChains_BreakFix(t *testing.T) {
	g := NewGraph()

	g.addNode("internet", "internet", "Internet", 0, nil)

	g.addNode("pod:web", "pod", "web", 70, nil)
	g.Nodes["pod:web"].CVEs = []types.CVEInfo{
		{ID: "CVE-PIVOT-001", CVSS: 9.0, ExploitType: ExploitSSRF, Package: "http-client"},
	}

	g.addNode("pod:db", "pod", "db", 60, nil)
	g.Nodes["pod:db"].CVEs = []types.CVEInfo{
		{ID: "CVE-DB-001", CVSS: 8.5, ExploitType: ExploitSQLi, Package: "mysql-driver"},
	}

	g.addNode("secrets", "secret", "Kubernetes Secrets", 80, nil)
	g.addNode("cluster-admin", "cluster-admin", "Cluster Admin", 100, nil)

	g.addEdge("internet", "pod:web", "network_reach", "Internet to web", 1)
	g.addEdge("pod:web", "pod:db", "network_reach", "Web to DB", 3)
	g.addEdge("pod:db", "secrets", "secret_access", "DB reads secrets", 2)
	g.addEdge("pod:web", "cluster-admin", "rbac_escalate", "Web has admin RBAC", 2)

	chains, summary := FindExploitChains(g)

	if len(chains) == 0 {
		t.Fatal("Expected at least one exploit chain")
	}

	// The break fix should identify a CVE that appears in the most chains
	if summary.TopBreakFix.CVEID == "" {
		t.Error("Expected a top break fix CVE ID")
	}

	if summary.TopBreakFix.ChainsEliminated == 0 {
		t.Error("Expected break fix to eliminate at least 1 chain")
	}
}

func TestChainSeverity(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{80, "critical"},
		{70, "critical"},
		{50, "high"},
		{45, "high"},
		{30, "medium"},
		{10, "low"},
		{0, "low"},
	}

	for _, tt := range tests {
		result := chainSeverity(tt.score)
		if result != tt.expected {
			t.Errorf("chainSeverity(%.0f) = %s, want %s", tt.score, result, tt.expected)
		}
	}
}
