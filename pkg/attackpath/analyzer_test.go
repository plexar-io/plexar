package attackpath

import (
	"testing"

	"github.com/plexar-io/plexar/internal/types"
)

func TestAnalyze_FindsPath(t *testing.T) {
	scores := []types.PlexarScore{
		{
			PodName: "web-abc-123",
			Total:   80,
			Tier:    "critical",
			Blast: types.BlastRadius{
				PodName:          "web-abc-123",
				InternetAccess:   true,
				ReachableTargets: []string{"api-xyz-456"},
			},
			Permissions: types.PodPermissions{PodName: "web-abc-123"},
		},
		{
			PodName: "api-xyz-456",
			Total:   60,
			Tier:    "high",
			Blast: types.BlastRadius{
				PodName:          "api-xyz-456",
				ReachableTargets: []string{},
			},
			Permissions: types.PodPermissions{
				PodName:    "api-xyz-456",
				Privileged: true,
			},
		},
	}

	rbac := []types.RBACFinding{
		{
			PodName:         "api-xyz-456",
			HasSecretAccess: true,
		},
	}

	g := Build(scores, rbac)
	summary := Analyze(g)

	if summary.TotalPaths == 0 {
		t.Error("Expected at least one attack path")
	}

	// Should find: internet -> web -> api -> cluster-admin (via container escape)
	// And: internet -> web -> api -> secrets
	foundClusterAdmin := false
	foundSecrets := false
	for _, p := range summary.Paths {
		if p.Target == "Cluster Admin" {
			foundClusterAdmin = true
		}
		if p.Target == "Kubernetes Secrets" {
			foundSecrets = true
		}
	}

	if !foundClusterAdmin {
		t.Error("Expected path to cluster-admin via container escape")
	}
	if !foundSecrets {
		t.Error("Expected path to secrets via secret_access")
	}

	if summary.ShortestHops == 0 {
		t.Error("ShortestHops should be > 0")
	}
}

func TestAnalyze_NoPaths(t *testing.T) {
	// Pod with no internet access, no dangerous perms
	scores := []types.PlexarScore{
		{
			PodName: "safe-pod-123",
			Total:   10,
			Tier:    "low",
			Blast: types.BlastRadius{
				PodName:          "safe-pod-123",
				InternetAccess:   false,
				HasNetworkPolicy: true,
			},
			Permissions: types.PodPermissions{
				PodName:       "safe-pod-123",
				ReadOnlyRootFS: true,
			},
		},
	}

	g := Build(scores, nil)
	summary := Analyze(g)

	if summary.TotalPaths != 0 {
		t.Errorf("Expected 0 attack paths for safe cluster, got %d", summary.TotalPaths)
	}
}

func TestDijkstra_ShortestPath(t *testing.T) {
	g := NewGraph()
	g.addNode("A", "test", "A", 0, nil)
	g.addNode("B", "test", "B", 0, nil)
	g.addNode("C", "test", "C", 0, nil)
	g.addNode("D", "test", "D", 0, nil)

	g.addEdge("A", "B", "test", "A to B", 1)
	g.addEdge("B", "D", "test", "B to D", 1)
	g.addEdge("A", "C", "test", "A to C", 5)
	g.addEdge("C", "D", "test", "C to D", 1)

	path, cost := dijkstra(g, "A", "D")

	if cost != 2 {
		t.Errorf("Expected cost 2 (A->B->D), got %d", cost)
	}

	if len(path) != 3 {
		t.Errorf("Expected 3 nodes in path, got %d: %v", len(path), path)
	}

	if path[0] != "A" || path[1] != "B" || path[2] != "D" {
		t.Errorf("Expected path [A B D], got %v", path)
	}
}

func TestDijkstra_NoPath(t *testing.T) {
	g := NewGraph()
	g.addNode("A", "test", "A", 0, nil)
	g.addNode("B", "test", "B", 0, nil)
	// No edges

	path, _ := dijkstra(g, "A", "B")
	if len(path) > 0 {
		t.Errorf("Expected no path, got %v", path)
	}
}
