package attackpath

import (
	"fmt"
	"strings"

	"github.com/plexar-security/plexar/internal/types"
)

// Graph is an in-memory attack graph built from scan results.
// Nodes are pods, roles, secrets, internet, and cluster-admin.
// Edges are attack steps: network reach, RBAC escalation, secret access, container escape.
type Graph struct {
	Nodes map[string]*types.AttackPathNode
	Edges []types.AttackPathEdge
	adj   map[string][]types.AttackPathEdge // adjacency list
}

// NewGraph creates an empty attack graph.
func NewGraph() *Graph {
	return &Graph{
		Nodes: make(map[string]*types.AttackPathNode),
		adj:   make(map[string][]types.AttackPathEdge),
	}
}

// Build constructs the attack graph from scan results.
// It creates nodes for each pod, internet entry points, roles with dangerous
// permissions, and the cluster-admin target. Edges represent attack vectors.
func Build(scores []types.PlexarScore, rbacFindings []types.RBACFinding) *Graph {
	g := NewGraph()

	// Build lookup maps
	rbacMap := make(map[string]*types.RBACFinding)
	for i := range rbacFindings {
		rbacMap[rbacFindings[i].PodName] = &rbacFindings[i]
	}

	// Add the ultimate target: cluster-admin
	g.addNode("cluster-admin", "cluster-admin", "Cluster Admin", 100, nil)

	// Add the internet entry point
	g.addNode("internet", "internet", "Internet", 0, nil)

	// Add secret store node
	g.addNode("secrets", "secret", "Kubernetes Secrets", 80, nil)

	for _, score := range scores {
		podID := "pod:" + score.PodName

		meta := map[string]string{
			"image": score.ImageName,
			"tier":  score.Tier,
			"class": score.WorkloadClass,
		}

		g.addNode(podID, "pod", score.PodName, score.Total, meta)

		// Edge: internet -> pod (if internet-exposed)
		if score.Blast.InternetAccess {
			g.addEdge("internet", podID, "network_reach",
				fmt.Sprintf("Internet-exposed pod (no egress restriction)"),
				1) // weight 1 = trivially reachable
		}

		// Edge: pod -> pod (network reachability)
		for _, target := range score.Blast.ReachableTargets {
			targetID := "pod:" + target
			g.addEdge(podID, targetID, "network_reach",
				fmt.Sprintf("Network path from %s to %s", shortPod(score.PodName), shortPod(target)),
				3)
		}

		// Edge: pod -> secrets (if has secret access via RBAC or env vars)
		if rbac, ok := rbacMap[score.PodName]; ok {
			if rbac.HasSecretAccess {
				g.addEdge(podID, "secrets", "secret_access",
					fmt.Sprintf("%s can read Kubernetes secrets via RBAC", shortPod(score.PodName)),
					2)
			}

			// Edge: pod -> cluster-admin (if has cluster-admin role)
			if rbac.HasClusterAdmin {
				g.addEdge(podID, "cluster-admin", "rbac_escalate",
					fmt.Sprintf("%s has cluster-admin role binding", shortPod(score.PodName)),
					1)
			}

			// Edge: pod -> cluster-admin (via wildcard access)
			if rbac.HasWildcardAccess && !rbac.HasClusterAdmin {
				g.addEdge(podID, "cluster-admin", "rbac_escalate",
					fmt.Sprintf("%s has wildcard (*) API access — equivalent to cluster-admin", shortPod(score.PodName)),
					2)
			}

			// Edge: pod -> other pods (via exec capability)
			if rbac.HasExecCapability {
				for _, target := range score.Blast.ReachableTargets {
					targetID := "pod:" + target
					g.addEdge(podID, targetID, "exec_into",
						fmt.Sprintf("%s can exec into %s via RBAC", shortPod(score.PodName), shortPod(target)),
						2)
				}
			}

			// Edge: pod -> cluster-admin (via privilege escalation)
			if rbac.HasEscalatePriv {
				g.addEdge(podID, "cluster-admin", "rbac_escalate",
					fmt.Sprintf("%s can escalate privileges via RBAC bind/escalate", shortPod(score.PodName)),
					3)
			}
		}

		// Edge: container escape (privileged + host access)
		if score.Permissions.Privileged {
			g.addEdge(podID, "cluster-admin", "container_escape",
				fmt.Sprintf("%s runs privileged — container escape to host", shortPod(score.PodName)),
				2)
		} else if score.Permissions.HostNetwork && score.Permissions.RunAsRoot {
			g.addEdge(podID, "cluster-admin", "container_escape",
				fmt.Sprintf("%s has hostNetwork + root — potential container escape", shortPod(score.PodName)),
				4)
		}

		// Edge: pod -> secrets (via env var secrets)
		if len(score.Permissions.EnvSecrets) > 0 {
			g.addEdge(podID, "secrets", "secret_access",
				fmt.Sprintf("%s has %d secrets in environment variables", shortPod(score.PodName), len(score.Permissions.EnvSecrets)),
				1)
		}
	}

	return g
}

func (g *Graph) addNode(id, nodeType, label string, risk int, meta map[string]string) {
	if _, exists := g.Nodes[id]; exists {
		return
	}
	g.Nodes[id] = &types.AttackPathNode{
		ID:       id,
		Type:     nodeType,
		Label:    label,
		Risk:     risk,
		Metadata: meta,
	}
}

func (g *Graph) addEdge(from, to, attackType, description string, weight int) {
	// Don't create self-loops
	if from == to {
		return
	}
	// Don't create duplicate edges
	for _, e := range g.adj[from] {
		if e.To == to && e.AttackType == attackType {
			return
		}
	}

	edge := types.AttackPathEdge{
		From:        from,
		To:          to,
		AttackType:  attackType,
		Description: description,
		Weight:      weight,
	}
	g.Edges = append(g.Edges, edge)
	g.adj[from] = append(g.adj[from], edge)
}

// Neighbors returns outgoing edges from a node.
func (g *Graph) Neighbors(nodeID string) []types.AttackPathEdge {
	return g.adj[nodeID]
}

// NodeList returns all nodes as a slice.
func (g *Graph) NodeList() []types.AttackPathNode {
	nodes := make([]types.AttackPathNode, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		nodes = append(nodes, *n)
	}
	return nodes
}

func shortPod(name string) string {
	parts := strings.Split(name, "-")
	if len(parts) > 2 {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return name
}
