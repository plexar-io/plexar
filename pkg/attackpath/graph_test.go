package attackpath

import (
	"testing"

	"github.com/plexar-security/plexar/internal/types"
)

func TestBuild_BasicGraph(t *testing.T) {
	scores := []types.PlexarScore{
		{
			PodName:   "web-abc-123",
			ImageName: "nginx:1.25",
			Total:     75,
			Tier:      "critical",
			Blast: types.BlastRadius{
				PodName:          "web-abc-123",
				InternetAccess:   true,
				ReachableTargets: []string{"api-xyz-456"},
				HasNetworkPolicy: false,
			},
			Permissions: types.PodPermissions{
				PodName:    "web-abc-123",
				RunAsRoot:  true,
				Privileged: false,
			},
		},
		{
			PodName:   "api-xyz-456",
			ImageName: "myapp:latest",
			Total:     50,
			Tier:      "high",
			Blast: types.BlastRadius{
				PodName:          "api-xyz-456",
				InternetAccess:   false,
				ReachableTargets: []string{},
				HasNetworkPolicy: true,
			},
			Permissions: types.PodPermissions{
				PodName:    "api-xyz-456",
				Privileged: true,
			},
		},
	}

	rbacFindings := []types.RBACFinding{
		{
			PodName:         "api-xyz-456",
			HasSecretAccess: true,
			HasClusterAdmin: false,
		},
	}

	g := Build(scores, rbacFindings)

	// Should have nodes: internet, cluster-admin, secrets, pod:web-abc-123, pod:api-xyz-456
	if len(g.Nodes) < 5 {
		t.Errorf("Expected at least 5 nodes, got %d", len(g.Nodes))
	}

	// Should have internet -> pod:web-abc-123 edge
	internetEdges := g.Neighbors("internet")
	found := false
	for _, e := range internetEdges {
		if e.To == "pod:web-abc-123" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected edge from internet to pod:web-abc-123")
	}

	// api-xyz-456 is privileged -> should have container_escape edge to cluster-admin
	apiEdges := g.Neighbors("pod:api-xyz-456")
	foundEscape := false
	foundSecret := false
	for _, e := range apiEdges {
		if e.To == "cluster-admin" && e.AttackType == "container_escape" {
			foundEscape = true
		}
		if e.To == "secrets" && e.AttackType == "secret_access" {
			foundSecret = true
		}
	}
	if !foundEscape {
		t.Error("Expected container_escape edge from api-xyz-456 to cluster-admin (privileged)")
	}
	if !foundSecret {
		t.Error("Expected secret_access edge from api-xyz-456 to secrets")
	}

	// Total edges should be > 0
	if len(g.Edges) == 0 {
		t.Error("Expected at least one edge in the graph")
	}
}

func TestBuild_NoDuplicateEdges(t *testing.T) {
	scores := []types.PlexarScore{
		{
			PodName: "pod-1",
			Blast: types.BlastRadius{
				PodName:          "pod-1",
				InternetAccess:   true,
				ReachableTargets: []string{"pod-2"},
			},
			Permissions: types.PodPermissions{PodName: "pod-1"},
		},
		{
			PodName: "pod-2",
			Blast: types.BlastRadius{
				PodName:          "pod-2",
				ReachableTargets: []string{},
			},
			Permissions: types.PodPermissions{PodName: "pod-2"},
		},
	}

	g := Build(scores, nil)

	// Count edges from internet to pod:pod-1
	count := 0
	for _, e := range g.Edges {
		if e.From == "internet" && e.To == "pod:pod-1" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("Expected at most 1 edge from internet to pod:pod-1, got %d", count)
	}
}

func TestBuild_NoSelfLoops(t *testing.T) {
	scores := []types.PlexarScore{
		{
			PodName: "pod-1",
			Blast: types.BlastRadius{
				PodName:          "pod-1",
				ReachableTargets: []string{"pod-1"}, // self-reference
			},
			Permissions: types.PodPermissions{PodName: "pod-1"},
		},
	}

	g := Build(scores, nil)

	for _, e := range g.Edges {
		if e.From == e.To {
			t.Errorf("Found self-loop: %s -> %s", e.From, e.To)
		}
	}
}
