package attackpath

import (
	"container/heap"
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/plexar-security/plexar/internal/types"
)

// Analyze computes attack paths from the graph.
// It finds all paths from internet-exposed pods to critical assets (cluster-admin, secrets)
// using Dijkstra's shortest path, then ranks them by severity.
func Analyze(g *Graph) *types.AttackPathSummary {
	targets := []string{"cluster-admin", "secrets"}
	entryPoints := findEntryPoints(g)

	var allPaths []types.AttackPath
	pathCount := make(map[string]int) // pod -> number of attack paths through it

	for _, entry := range entryPoints {
		for _, target := range targets {
			if _, exists := g.Nodes[target]; !exists {
				continue
			}

			path, cost := dijkstra(g, entry, target)
			if len(path) < 2 {
				continue // no path found
			}

			// Build the attack path with nodes and edges
			ap := buildAttackPath(g, path, cost, entry, target)
			allPaths = append(allPaths, ap)

			// Track exposure per pod
			for _, nodeID := range path {
				pathCount[nodeID]++
			}
		}
	}

	// Sort by score descending (most critical first)
	sort.Slice(allPaths, func(i, j int) bool {
		return allPaths[i].Score > allPaths[j].Score
	})

	// Cap at 20 paths
	if len(allPaths) > 20 {
		allPaths = allPaths[:20]
	}

	criticalPaths := 0
	shortestHops := 0
	for _, p := range allPaths {
		if p.Severity == "critical" {
			criticalPaths++
		}
		if shortestHops == 0 || p.HopCount < shortestHops {
			shortestHops = p.HopCount
		}
	}

	// Find most exposed pod
	mostExposed := ""
	maxCount := 0
	for nodeID, count := range pathCount {
		if count > maxCount && g.Nodes[nodeID] != nil && g.Nodes[nodeID].Type == "pod" {
			maxCount = count
			mostExposed = g.Nodes[nodeID].Label
		}
	}

	return &types.AttackPathSummary{
		TotalPaths:     len(allPaths),
		CriticalPaths:  criticalPaths,
		ShortestHops:   shortestHops,
		MostExposedPod: mostExposed,
		Paths:          allPaths,
	}
}

// findEntryPoints returns all nodes reachable from the internet (1 hop).
func findEntryPoints(g *Graph) []string {
	var entries []string
	// Direct internet edges
	for _, edge := range g.Neighbors("internet") {
		entries = append(entries, edge.To)
	}
	// Also include internet node itself
	if len(entries) > 0 {
		entries = append([]string{"internet"}, entries...)
	}
	return entries
}

// buildAttackPath constructs a typed AttackPath from the raw node path.
func buildAttackPath(g *Graph, path []string, cost int, entry, target string) types.AttackPath {
	var nodes []types.AttackPathNode
	var edges []types.AttackPathEdge

	for i, nodeID := range path {
		if n, ok := g.Nodes[nodeID]; ok {
			nodes = append(nodes, *n)
		}
		if i < len(path)-1 {
			// Find the edge used in this hop
			for _, e := range g.Neighbors(nodeID) {
				if e.To == path[i+1] {
					// Annotate with remediation suggestion
					e.Remediation = remediationForEdge(e, g)
					edges = append(edges, e)
					break
				}
			}
		}
	}

	// Score: lower cost = easier to exploit = higher severity score
	// Normalize: 1-hop cluster-admin = 100, 5+ hops = lower
	score := 100.0
	if cost > 0 {
		score = 100.0 / float64(cost)
		if score > 100 {
			score = 100
		}
	}

	severity := "low"
	switch {
	case score >= 50:
		severity = "critical"
	case score >= 25:
		severity = "high"
	case score >= 10:
		severity = "medium"
	}

	entryLabel := entry
	if n, ok := g.Nodes[entry]; ok {
		entryLabel = n.Label
	}
	targetLabel := target
	if n, ok := g.Nodes[target]; ok {
		targetLabel = n.Label
	}

	// Build description
	desc := fmt.Sprintf("%s → %s (%d hops)", entryLabel, targetLabel, len(path)-1)

	// Generate deterministic ID
	h := sha256.Sum256([]byte(entry + ":" + target + ":" + fmt.Sprint(path)))
	id := fmt.Sprintf("ap-%x", h[:6])

	// Compute risk reduction estimate
	riskReduction := estimateRiskReduction(severity, edges)

	return types.AttackPath{
		ID:            id,
		Severity:      severity,
		Score:         score,
		Description:   desc,
		Nodes:         nodes,
		Edges:         edges,
		EntryPoint:    entryLabel,
		Target:        targetLabel,
		HopCount:      len(path) - 1,
		RiskReduction: riskReduction,
	}
}

// remediationForEdge returns a specific remediation suggestion for a given attack edge.
func remediationForEdge(edge types.AttackPathEdge, g *Graph) string {
	fromLabel := edge.From
	toLabel := edge.To
	if n, ok := g.Nodes[edge.From]; ok {
		fromLabel = n.Label
	}
	if n, ok := g.Nodes[edge.To]; ok {
		toLabel = n.Label
	}

	switch edge.AttackType {
	case "network_reach":
		return fmt.Sprintf("Add a NetworkPolicy to restrict egress from %s to %s", fromLabel, toLabel)
	case "rbac_escalate":
		return fmt.Sprintf("Remove cluster-admin ClusterRoleBinding from %s; use namespace-scoped Role instead", fromLabel)
	case "secret_access":
		return fmt.Sprintf("Restrict RBAC secret read permissions for %s to only required secrets", fromLabel)
	case "container_escape":
		return fmt.Sprintf("Remove privileged: true and set allowPrivilegeEscalation: false on %s", fromLabel)
	case "exec_into":
		return fmt.Sprintf("Remove pods/exec permission from ServiceAccount used by %s", fromLabel)
	default:
		return fmt.Sprintf("Harden the connection between %s and %s", fromLabel, toLabel)
	}
}

// estimateRiskReduction computes the severity after fixing the weakest (lowest weight) edge.
func estimateRiskReduction(currentSeverity string, edges []types.AttackPathEdge) string {
	if len(edges) == 0 {
		return ""
	}

	// Find the easiest-to-exploit edge (lowest weight = weakest link)
	minWeight := edges[0].Weight
	weakestEdge := edges[0]
	for _, e := range edges[1:] {
		if e.Weight < minWeight {
			minWeight = e.Weight
			weakestEdge = e
		}
	}

	// Estimate new severity if this edge were removed/hardened
	newSeverity := reducedSeverity(currentSeverity)

	if newSeverity == currentSeverity {
		return ""
	}

	fixDesc := weakestEdge.Remediation
	if fixDesc == "" {
		fixDesc = fmt.Sprintf("Harden %s → %s edge", weakestEdge.From, weakestEdge.To)
	}

	return fmt.Sprintf("Fixing weakest link (%s) drops path severity from %s to %s",
		fixDesc, currentSeverity, newSeverity)
}

// reducedSeverity returns the next lower severity level.
func reducedSeverity(sev string) string {
	switch sev {
	case "critical":
		return "medium"
	case "high":
		return "low"
	default:
		return sev
	}
}

// --- Dijkstra's shortest path ---

type dijkstraItem struct {
	nodeID string
	cost   int
	index  int
}

type priorityQueue []*dijkstraItem

func (pq priorityQueue) Len() int           { return len(pq) }
func (pq priorityQueue) Less(i, j int) bool { return pq[i].cost < pq[j].cost }
func (pq priorityQueue) Swap(i, j int)      { pq[i], pq[j] = pq[j], pq[i]; pq[i].index = i; pq[j].index = j }
func (pq *priorityQueue) Push(x interface{}) {
	item := x.(*dijkstraItem)
	item.index = len(*pq)
	*pq = append(*pq, item)
}
func (pq *priorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*pq = old[:n-1]
	return item
}

// dijkstra finds the shortest weighted path from src to dst in the graph.
// Returns the path as a slice of node IDs and the total cost.
func dijkstra(g *Graph, src, dst string) ([]string, int) {
	dist := make(map[string]int)
	prev := make(map[string]string)
	visited := make(map[string]bool)

	for id := range g.Nodes {
		dist[id] = 1<<31 - 1 // max int
	}
	dist[src] = 0

	pq := &priorityQueue{}
	heap.Init(pq)
	heap.Push(pq, &dijkstraItem{nodeID: src, cost: 0})

	for pq.Len() > 0 {
		current := heap.Pop(pq).(*dijkstraItem)
		if visited[current.nodeID] {
			continue
		}
		visited[current.nodeID] = true

		if current.nodeID == dst {
			break
		}

		for _, edge := range g.Neighbors(current.nodeID) {
			if visited[edge.To] {
				continue
			}
			newCost := dist[current.nodeID] + edge.Weight
			if newCost < dist[edge.To] {
				dist[edge.To] = newCost
				prev[edge.To] = current.nodeID
				heap.Push(pq, &dijkstraItem{nodeID: edge.To, cost: newCost})
			}
		}
	}

	// Reconstruct path
	if dist[dst] >= 1<<31-1 {
		return nil, 0 // no path
	}

	var path []string
	for at := dst; at != ""; at = prev[at] {
		path = append([]string{at}, path...)
		if at == src {
			break
		}
	}

	return path, dist[dst]
}
