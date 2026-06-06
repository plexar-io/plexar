package attackpath

import (
	"fmt"
	"sort"
	"strings"

	"github.com/plexar-io/plexar/internal/types"
)

// agentClasses are workload classes that represent AI agent workloads
var agentClasses = map[string]bool{
	"ai-agent":      true,
	"llm-inference": true,
	"ai-gateway":    true,
	"rag-pipeline":  true,
	"ml-ai":         true,
}

// agentChainMultiplier boosts chain scores for chains involving agent nodes
const agentChainMultiplier = 1.5

// FindExploitChains performs DFS-based traversal of the attack graph to find
// exploit chains where each hop requires a CVE of the right exploit type to
// enable the transition. Returns ranked chains with break-the-chain fixes.
func FindExploitChains(g *Graph) ([]types.ExploitChain, *types.ExploitChainSummary) {
	entryPoints := findEntryPoints(g)
	targets := []string{"cluster-admin", "secrets"}

	var allChains []types.ExploitChain
	chainID := 0

	for _, entry := range entryPoints {
		for _, target := range targets {
			if _, exists := g.Nodes[target]; !exists {
				continue
			}

			// DFS to find all CVE-validated chains from entry to target
			visited := make(map[string]bool)
			var currentPath []chainStep
			findChainsDF(g, entry, target, visited, currentPath, &allChains, &chainID)
		}
	}

	// Apply agent-aware scoring
	for i := range allChains {
		applyAgentScoring(g, &allChains[i])
	}

	// Sort by chain score descending
	sort.Slice(allChains, func(i, j int) bool {
		return allChains[i].ChainScore > allChains[j].ChainScore
	})

	// Cap at 30 chains
	if len(allChains) > 30 {
		allChains = allChains[:30]
	}

	// Compute break-the-chain fixes
	breakFixes := computeBreakFixes(allChains)

	// Build summary
	summary := buildChainSummary(allChains, breakFixes)

	// Attach top break fix to each chain
	for i := range allChains {
		allChains[i].BreakFix = findBestBreakFix(allChains[i], breakFixes)
	}

	return allChains, summary
}

// chainStep tracks state during DFS traversal
type chainStep struct {
	nodeID    string
	cve       types.CVEInfo
	edgeType  string
}

// findChainsDF performs depth-first search to find CVE-validated exploit chains
func findChainsDF(g *Graph, current, target string, visited map[string]bool, path []chainStep, results *[]types.ExploitChain, chainID *int) {
	if current == target {
		// We reached the target — build the chain
		if len(path) >= 2 {
			chain := buildExploitChain(g, path, chainID)
			*results = append(*results, chain)
		}
		return
	}

	if visited[current] {
		return
	}

	// Limit chain depth to prevent combinatorial explosion
	if len(path) > 8 {
		return
	}

	visited[current] = true

	for _, edge := range g.Neighbors(current) {
		nextNode := g.Nodes[edge.To]
		if nextNode == nil {
			continue
		}

		// For non-pod nodes (internet, cluster-admin, secrets), no CVE required
		if nextNode.Type != "pod" {
			step := chainStep{
				nodeID:   edge.To,
				edgeType: edge.AttackType,
			}
			findChainsDF(g, edge.To, target, visited, append(path, step), results, chainID)
			continue
		}

		// For pod nodes, find a CVE that enables this transition type
		enabledCVE, found := findEnablingCVE(nextNode, edge.AttackType)
		if !found {
			// Also check source node CVEs — SSRF on source enables pivoting
			srcNode := g.Nodes[current]
			if srcNode != nil {
				enabledCVE, found = findEnablingCVE(srcNode, edge.AttackType)
			}
		}

		if !found {
			// No enabling CVE — this hop is not exploitable via CVE chain
			// Still allow the hop if the edge is non-network (RBAC, container escape)
			// as those don't require a CVE on the target
			if edge.AttackType == "rbac_escalate" || edge.AttackType == "container_escape" || edge.AttackType == "exec_into" {
				step := chainStep{
					nodeID:   edge.To,
					edgeType: edge.AttackType,
				}
				findChainsDF(g, edge.To, target, visited, append(path, step), results, chainID)
			}
			continue
		}

		step := chainStep{
			nodeID:   edge.To,
			cve:      enabledCVE,
			edgeType: edge.AttackType,
		}
		findChainsDF(g, edge.To, target, visited, append(path, step), results, chainID)
	}

	visited[current] = false
}

// findEnablingCVE looks for a CVE on a node that enables the given edge type transition
func findEnablingCVE(node *types.AttackPathNode, edgeType string) (types.CVEInfo, bool) {
	if node == nil || len(node.CVEs) == 0 {
		return types.CVEInfo{}, false
	}

	// Prefer in-use CVEs with higher CVSS
	var bestCVE types.CVEInfo
	bestScore := -1.0

	for _, cve := range node.CVEs {
		exploitType := cve.ExploitType
		if exploitType == "" {
			exploitType = ClassifyCVE(cve)
		}

		if !exploitTypeEnablesTransition(exploitType, edgeType) {
			continue
		}

		score := cve.CVSS
		if cve.InUse {
			score += 2.0 // Boost in-use CVEs
		}
		if score > bestScore {
			bestScore = score
			bestCVE = cve
			bestCVE.ExploitType = exploitType
		}
	}

	if bestScore < 0 {
		return types.CVEInfo{}, false
	}
	return bestCVE, true
}

// buildExploitChain constructs an ExploitChain from a completed DFS path
func buildExploitChain(g *Graph, path []chainStep, chainID *int) types.ExploitChain {
	*chainID++

	var hops []types.ChainHop
	compositeRisk := 1.0
	var descriptions []string

	for _, step := range path {
		node := g.Nodes[step.nodeID]
		label := step.nodeID
		if node != nil {
			label = node.Label
		}

		hop := types.ChainHop{
			PodName:          label,
			NodeID:           step.nodeID,
			CVE:              step.cve,
			ExploitType:      step.cve.ExploitType,
			TransitionReason: transitionReason(step.edgeType, step.cve),
		}
		hops = append(hops, hop)

		if step.cve.CVSS > 0 {
			compositeRisk *= step.cve.CVSS / 10.0
		}

		if step.cve.ID != "" {
			descriptions = append(descriptions, fmt.Sprintf("%s via %s (%s)", label, step.cve.ID, step.cve.ExploitType))
		} else {
			descriptions = append(descriptions, fmt.Sprintf("%s via %s", label, step.edgeType))
		}
	}

	// Scale composite risk to 0-100
	chainScore := compositeRisk * 100.0
	if chainScore > 100 {
		chainScore = 100
	}

	entryPoint := ""
	finalTarget := ""
	if len(path) > 0 {
		if node := g.Nodes[path[0].nodeID]; node != nil {
			entryPoint = node.Label
		}
		if node := g.Nodes[path[len(path)-1].nodeID]; node != nil {
			finalTarget = node.Label
		}
	}

	severity := chainSeverity(chainScore)

	dataTarget := ""
	if len(path) > 0 {
		lastNode := path[len(path)-1].nodeID
		if lastNode == "secrets" {
			dataTarget = "Kubernetes Secrets"
		} else if lastNode == "cluster-admin" {
			dataTarget = "Cluster Admin"
		}
	}

	return types.ExploitChain{
		ID:            fmt.Sprintf("chain-%d", *chainID),
		ChainScore:    chainScore,
		CompositeRisk: compositeRisk,
		Severity:      severity,
		Description:   strings.Join(descriptions, " → "),
		Hops:          hops,
		DataTarget:    dataTarget,
		EntryPoint:    entryPoint,
		FinalTarget:   finalTarget,
		HopCount:      len(hops),
	}
}

// applyAgentScoring boosts the score of chains that pass through agent nodes
func applyAgentScoring(g *Graph, chain *types.ExploitChain) {
	var agentNodes []string

	for _, hop := range chain.Hops {
		node := g.Nodes[hop.NodeID]
		if node == nil {
			continue
		}

		// Check if this node is an agent via metadata or IsAgent flag
		if node.IsAgent {
			agentNodes = append(agentNodes, node.Label)
			continue
		}
		if class, ok := node.Metadata["class"]; ok && agentClasses[class] {
			agentNodes = append(agentNodes, node.Label)
		}
	}

	if len(agentNodes) > 0 {
		chain.HasAgentNode = true
		chain.AgentNodes = agentNodes
		chain.ChainScore *= agentChainMultiplier
		if chain.ChainScore > 100 {
			chain.ChainScore = 100
		}
		chain.Description += fmt.Sprintf(" [AGENT CHAIN: %s — non-deterministic communication pattern increases risk]",
			strings.Join(agentNodes, ", "))
		// Re-calculate severity after boost
		chain.Severity = chainSeverity(chain.ChainScore)
	}
}

// transitionReason generates a human-readable reason for a chain hop
func transitionReason(edgeType string, cve types.CVEInfo) string {
	if cve.ID == "" {
		switch edgeType {
		case "rbac_escalate":
			return "RBAC privilege escalation"
		case "container_escape":
			return "Container escape via privileged mode"
		case "exec_into":
			return "Exec into container via RBAC"
		case "secret_access":
			return "Secret access via RBAC binding"
		default:
			return "Network reachability"
		}
	}

	switch cve.ExploitType {
	case ExploitSSRF:
		return fmt.Sprintf("SSRF via %s enables pivot to internal service", cve.ID)
	case ExploitRCE:
		return fmt.Sprintf("RCE via %s enables code execution on target", cve.ID)
	case ExploitDeserialization:
		return fmt.Sprintf("Deserialization via %s enables arbitrary object injection", cve.ID)
	case ExploitSQLi:
		return fmt.Sprintf("SQL injection via %s enables data extraction", cve.ID)
	case ExploitPathTraversal:
		return fmt.Sprintf("Path traversal via %s enables filesystem access", cve.ID)
	case ExploitAuthBypass:
		return fmt.Sprintf("Auth bypass via %s enables unauthorized access", cve.ID)
	case ExploitLFI:
		return fmt.Sprintf("Local file inclusion via %s enables config/credential theft", cve.ID)
	case ExploitInfoDisclosure:
		return fmt.Sprintf("Info disclosure via %s leaks sensitive data", cve.ID)
	default:
		return fmt.Sprintf("Exploitable via %s (CVSS %.1f)", cve.ID, cve.CVSS)
	}
}

// chainSeverity maps a chain score to a severity label
func chainSeverity(score float64) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 45:
		return "high"
	case score >= 20:
		return "medium"
	default:
		return "low"
	}
}

// computeBreakFixes finds which CVE patches would eliminate the most chains
func computeBreakFixes(chains []types.ExploitChain) map[string]*types.BreakChainFix {
	fixes := make(map[string]*types.BreakChainFix)

	for _, chain := range chains {
		for _, hop := range chain.Hops {
			if hop.CVE.ID == "" {
				continue
			}
			key := hop.CVE.ID + ":" + hop.PodName
			if fix, ok := fixes[key]; ok {
				fix.ChainsEliminated++
			} else {
				fixes[key] = &types.BreakChainFix{
					CVEID:            hop.CVE.ID,
					PodName:          hop.PodName,
					ChainsEliminated: 1,
					Recommendation: fmt.Sprintf("Patch %s on %s (%s) to break %s chain",
						hop.CVE.ID, hop.PodName, hop.CVE.Package, hop.ExploitType),
				}
			}
		}
	}

	return fixes
}

// findBestBreakFix returns the break fix that eliminates the most chains for a given chain
func findBestBreakFix(chain types.ExploitChain, allFixes map[string]*types.BreakChainFix) types.BreakChainFix {
	var best types.BreakChainFix

	for _, hop := range chain.Hops {
		if hop.CVE.ID == "" {
			continue
		}
		key := hop.CVE.ID + ":" + hop.PodName
		if fix, ok := allFixes[key]; ok {
			if fix.ChainsEliminated > best.ChainsEliminated {
				best = *fix
			}
		}
	}

	return best
}

// buildChainSummary constructs the ExploitChainSummary from analyzed chains
func buildChainSummary(chains []types.ExploitChain, breakFixes map[string]*types.BreakChainFix) *types.ExploitChainSummary {
	if len(chains) == 0 {
		return &types.ExploitChainSummary{}
	}

	critCount := 0
	agentCount := 0
	exploitTypes := make(map[string]bool)

	for _, c := range chains {
		if c.Severity == "critical" {
			critCount++
		}
		if c.HasAgentNode {
			agentCount++
		}
		for _, hop := range c.Hops {
			if hop.ExploitType != "" {
				exploitTypes[hop.ExploitType] = true
			}
		}
	}

	// Find top break fix across all chains
	var topFix types.BreakChainFix
	for _, fix := range breakFixes {
		if fix.ChainsEliminated > topFix.ChainsEliminated {
			topFix = *fix
		}
	}

	var uniqueTypes []string
	for t := range exploitTypes {
		uniqueTypes = append(uniqueTypes, t)
	}
	sort.Strings(uniqueTypes)

	return &types.ExploitChainSummary{
		TotalChains:        len(chains),
		CriticalChains:     critCount,
		AgentChains:        agentCount,
		TopBreakFix:        topFix,
		UniqueExploitTypes: uniqueTypes,
	}
}
