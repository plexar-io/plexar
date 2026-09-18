package agentsec

import (
	"fmt"
	"strings"

	"github.com/plexar-io/plexar/internal/types"
	"github.com/plexar-io/plexar/pkg/classifier"
)

// AnalyzeDelegation traces agent -> MCP -> service chains and measures
// scope attenuation at each hop. The Bounded Agents theorem (2608.15888)
// proves: if scope narrows at every delegation step, total blast radius
// can only shrink. If scope WIDENS, the system is exposed.
func AnalyzeDelegation(scores []types.PlexarScore, rbacFindings []types.RBACFinding) ([]types.DelegationChain, *types.DelegationSummary) {
	// Index pods by name
	podIndex := make(map[string]*types.PlexarScore, len(scores))
	for i := range scores {
		podIndex[scores[i].PodName] = &scores[i]
	}

	// Index RBAC by pod name
	rbacIndex := make(map[string]*types.RBACFinding, len(rbacFindings))
	for i := range rbacFindings {
		rbacIndex[rbacFindings[i].PodName] = &rbacFindings[i]
	}

	// Find MCP servers and agent pods
	var mcpPods, agentPods []*types.PlexarScore
	for i := range scores {
		if !classifier.IsAgentClass(scores[i].WorkloadClass) {
			continue
		}
		if isMCPServer(&scores[i]) {
			mcpPods = append(mcpPods, &scores[i])
		} else {
			agentPods = append(agentPods, &scores[i])
		}
	}

	if len(mcpPods) == 0 && len(agentPods) == 0 {
		return nil, nil
	}

	var chains []types.DelegationChain
	chainID := 0

	// Build chains: agent -> MCP -> high-value targets
	for _, agent := range agentPods {
		for _, mcp := range mcpPods {
			// Check if agent can reach this MCP server
			mcpServiceNames := inferServiceNames(mcp.PodName, mcp.Namespace)
			canReach := false
			for _, target := range agent.Blast.ReachableTargets {
				if matchesService(target, mcpServiceNames) {
					canReach = true
					break
				}
			}
			if !canReach {
				continue
			}

			// Find high-value targets reachable through MCP
			highValueTargets := classifyTargets(mcp.Blast.ReachableTargets, podIndex, rbacIndex)

			// Build the chain: agent -> MCP -> [high-value services]
			chain := buildChain(chainID, agent, mcp, highValueTargets, podIndex, rbacIndex)
			if chain != nil {
				chains = append(chains, *chain)
				chainID++
			}
		}
	}

	// Also check: MCP server -> high-value targets directly (no agent entry point)
	// These represent exposure even without an agent compromise
	for _, mcp := range mcpPods {
		highValueTargets := classifyTargets(mcp.Blast.ReachableTargets, podIndex, rbacIndex)
		if len(highValueTargets.secrets) > 0 || len(highValueTargets.databases) > 0 || len(highValueTargets.authServices) > 0 || len(highValueTargets.elevatedRBAC) > 0 {
			// Only if no agent chains already cover this MCP
			alreadyCovered := false
			for _, c := range chains {
				if len(c.Hops) > 1 && c.Hops[1].PodName == mcp.PodName {
					alreadyCovered = true
					break
				}
			}
			if !alreadyCovered {
				chain := buildMCPDirectChain(chainID, mcp, highValueTargets, rbacIndex)
				if chain != nil {
					chains = append(chains, *chain)
					chainID++
				}
			}
		}
	}

	summary := summarizeChains(chains)
	return chains, summary
}

// highValueTargets groups reachable services by risk category
type highValueTargets struct {
	secrets      []string // pods/services that hold secrets
	databases    []string // data stores
	authServices []string // auth/security services
	elevatedRBAC []targetWithRBAC // pods with elevated RBAC that the chain can reach
}

type targetWithRBAC struct {
	podName  string
	sa       string
	riskScore int
	flags    []string
}

func classifyTargets(reachableTargets []string, podIndex map[string]*types.PlexarScore, rbacIndex map[string]*types.RBACFinding) highValueTargets {
	var targets highValueTargets
	seen := make(map[string]bool)

	for _, target := range reachableTargets {
		tl := strings.ToLower(target)

		// Databases
		if isDataStore(tl) && !seen["db:"+tl] {
			targets.databases = append(targets.databases, target)
			seen["db:"+tl] = true
		}

		// Auth services
		if isAuthService(tl) && !seen["auth:"+tl] {
			targets.authServices = append(targets.authServices, target)
			seen["auth:"+tl] = true
		}

		// Find pods with elevated RBAC reachable from here
		pod := findPodByService(target, podIndex)
		if pod != nil {
			rbac := rbacIndex[pod.PodName]
			if rbac != nil && rbac.RiskScore >= 35 {
				if !seen["rbac:"+pod.PodName] {
					t := targetWithRBAC{
						podName:   pod.PodName,
						sa:        rbac.ServiceAccountName,
						riskScore: rbac.RiskScore,
					}
					if rbac.HasSecretAccess {
						t.flags = append(t.flags, "secrets")
						targets.secrets = append(targets.secrets, pod.PodName+" (via "+rbac.ServiceAccountName+" SA)")
					}
					if rbac.HasClusterAdmin {
						t.flags = append(t.flags, "cluster-admin")
					}
					if rbac.HasCreatePods {
						t.flags = append(t.flags, "create-pods")
					}
					if rbac.HasWildcardAccess {
						t.flags = append(t.flags, "wildcard")
					}
					if rbac.HasDeleteAccess {
						t.flags = append(t.flags, "delete")
					}
					targets.elevatedRBAC = append(targets.elevatedRBAC, t)
					seen["rbac:"+pod.PodName] = true
				}
			}
		}
	}
	return targets
}

func buildChain(id int, agent, mcp *types.PlexarScore, targets highValueTargets, podIndex map[string]*types.PlexarScore, rbacIndex map[string]*types.RBACFinding) *types.DelegationChain {
	agentRBAC := rbacIndex[agent.PodName]
	mcpRBAC := rbacIndex[mcp.PodName]

	agentRBACScore := 0
	agentSA := agent.Permissions.ServiceAccountName
	if agentRBAC != nil {
		agentRBACScore = agentRBAC.RiskScore
	}

	mcpRBACScore := 0
	mcpSA := mcp.Permissions.ServiceAccountName
	if mcpRBAC != nil {
		mcpRBACScore = mcpRBAC.RiskScore
	}

	agentBlast := len(agent.Blast.ReachableTargets)
	mcpBlast := len(mcp.Blast.ReachableTargets)

	// Hop 1: Agent
	hop1 := types.DelegationHop{
		PodName:        agent.PodName,
		Namespace:      agent.Namespace,
		WorkloadClass:  agent.WorkloadClass,
		BlastRadius:    agentBlast,
		RBACRisk:       agentRBACScore,
		RBACSA:         agentSA,
		HasNetPolicy:   agent.Blast.HasNetworkPolicy,
		InternetAccess: agent.Blast.InternetAccess,
		InUseCVEs:      countInUseCVEs(agent),
		CriticalCVEs:   agent.Vulns.Critical,
		BlastDelta:     0,
		RBACDelta:      0,
		AuthBoundary:   "entry",
	}

	// Hop 2: MCP Server
	blastDelta := mcpBlast - agentBlast
	rbacDelta := mcpRBACScore - agentRBACScore
	authBoundary := "none"
	if agent.Blast.HasNetworkPolicy || mcp.Blast.HasNetworkPolicy {
		authBoundary = "networkpolicy"
	}

	hop2 := types.DelegationHop{
		PodName:        mcp.PodName,
		Namespace:      mcp.Namespace,
		WorkloadClass:  mcp.WorkloadClass,
		BlastRadius:    mcpBlast,
		RBACRisk:       mcpRBACScore,
		RBACSA:         mcpSA,
		HasNetPolicy:   mcp.Blast.HasNetworkPolicy,
		InternetAccess: mcp.Blast.InternetAccess,
		InUseCVEs:      countInUseCVEs(mcp),
		CriticalCVEs:   mcp.Vulns.Critical,
		BlastDelta:     blastDelta,
		RBACDelta:      rbacDelta,
		AuthBoundary:   authBoundary,
	}

	hops := []types.DelegationHop{hop1, hop2}
	var violations []string
	var terminalTargets []string

	// Check scope violations at hop 2 (agent -> MCP)
	if blastDelta > 0 {
		violations = append(violations,
			fmt.Sprintf("Blast radius WIDENS at %s: %d -> %d services (+%d)",
				shortPodName(mcp.PodName), agentBlast, mcpBlast, blastDelta))
	}
	if rbacDelta > 0 {
		violations = append(violations,
			fmt.Sprintf("RBAC privilege INCREASES at %s: %s(%d) -> %s(%d)",
				shortPodName(mcp.PodName), agentSA, agentRBACScore, mcpSA, mcpRBACScore))
	}
	if authBoundary == "none" {
		violations = append(violations,
			fmt.Sprintf("No auth boundary between %s and %s",
				shortPodName(agent.PodName), shortPodName(mcp.PodName)))
	}

	// Add hops for elevated-RBAC pods reachable through MCP
	for _, t := range targets.elevatedRBAC {
		pod := podIndex[t.podName]
		if pod == nil {
			continue
		}
		podBlast := len(pod.Blast.ReachableTargets)
		podAuthBoundary := "none"
		if mcp.Blast.HasNetworkPolicy || pod.Blast.HasNetworkPolicy {
			podAuthBoundary = "networkpolicy"
		}

		hop3 := types.DelegationHop{
			PodName:        pod.PodName,
			Namespace:      pod.Namespace,
			WorkloadClass:  pod.WorkloadClass,
			BlastRadius:    podBlast,
			RBACRisk:       t.riskScore,
			RBACSA:         t.sa,
			HasNetPolicy:   pod.Blast.HasNetworkPolicy,
			InternetAccess: pod.Blast.InternetAccess,
			InUseCVEs:      countInUseCVEs(pod),
			CriticalCVEs:   pod.Vulns.Critical,
			BlastDelta:     podBlast - mcpBlast,
			RBACDelta:      t.riskScore - mcpRBACScore,
			AuthBoundary:   podAuthBoundary,
		}
		hops = append(hops, hop3)

		if t.riskScore > mcpRBACScore {
			violations = append(violations,
				fmt.Sprintf("RBAC privilege INCREASES at %s: %s(%d) -> %s(%d) [%s]",
					shortPodName(pod.PodName), mcpSA, mcpRBACScore, t.sa, t.riskScore,
					strings.Join(t.flags, ", ")))
		}
		if podAuthBoundary == "none" {
			violations = append(violations,
				fmt.Sprintf("No auth boundary between %s and %s",
					shortPodName(mcp.PodName), shortPodName(pod.PodName)))
		}

		for _, flag := range t.flags {
			switch flag {
			case "secrets":
				terminalTargets = append(terminalTargets, "secrets (via "+t.sa+")")
			case "cluster-admin":
				terminalTargets = append(terminalTargets, "cluster-admin (via "+t.sa+")")
			}
		}
	}

	// Add terminal targets from classified services
	for _, db := range targets.databases {
		terminalTargets = append(terminalTargets, "datastore:"+db)
	}
	for _, auth := range targets.authServices {
		terminalTargets = append(terminalTargets, "auth:"+auth)
	}

	// Deduplicate terminal targets
	terminalTargets = dedup(terminalTargets)

	// Score the chain
	exposure, score := scoreChain(hops, violations, terminalTargets)

	// Generate fix recommendation
	fix := recommendFix(hops, violations, terminalTargets)

	return &types.DelegationChain{
		ID:              fmt.Sprintf("chain-%d", id),
		Hops:            hops,
		TerminalTargets: terminalTargets,
		Exposure:        exposure,
		ExposureScore:   score,
		Violations:      violations,
		Fix:             fix,
	}
}

func buildMCPDirectChain(id int, mcp *types.PlexarScore, targets highValueTargets, rbacIndex map[string]*types.RBACFinding) *types.DelegationChain {
	mcpRBAC := rbacIndex[mcp.PodName]
	mcpRBACScore := 0
	if mcpRBAC != nil {
		mcpRBACScore = mcpRBAC.RiskScore
	}

	hop := types.DelegationHop{
		PodName:        mcp.PodName,
		Namespace:      mcp.Namespace,
		WorkloadClass:  mcp.WorkloadClass,
		BlastRadius:    len(mcp.Blast.ReachableTargets),
		RBACRisk:       mcpRBACScore,
		RBACSA:         mcp.Permissions.ServiceAccountName,
		HasNetPolicy:   mcp.Blast.HasNetworkPolicy,
		InternetAccess: mcp.Blast.InternetAccess,
		InUseCVEs:      countInUseCVEs(mcp),
		CriticalCVEs:   mcp.Vulns.Critical,
		AuthBoundary:   "entry",
	}

	var violations []string
	var terminalTargets []string

	if !mcp.Blast.HasNetworkPolicy {
		violations = append(violations, fmt.Sprintf("MCP server %s has no NetworkPolicy — any pod can invoke tools", shortPodName(mcp.PodName)))
	}

	for _, db := range targets.databases {
		terminalTargets = append(terminalTargets, "datastore:"+db)
	}
	for _, auth := range targets.authServices {
		terminalTargets = append(terminalTargets, "auth:"+auth)
	}
	for _, t := range targets.elevatedRBAC {
		for _, flag := range t.flags {
			if flag == "secrets" {
				terminalTargets = append(terminalTargets, "secrets (via "+t.sa+")")
			}
		}
	}

	terminalTargets = dedup(terminalTargets)
	exposure, score := scoreChain([]types.DelegationHop{hop}, violations, terminalTargets)
	fix := recommendFix([]types.DelegationHop{hop}, violations, terminalTargets)

	return &types.DelegationChain{
		ID:              fmt.Sprintf("chain-%d", id),
		Hops:            []types.DelegationHop{hop},
		TerminalTargets: terminalTargets,
		Exposure:        exposure,
		ExposureScore:   score,
		Violations:      violations,
		Fix:             fix,
	}
}

func scoreChain(hops []types.DelegationHop, violations []string, terminalTargets []string) (string, int) {
	score := 0

	// Base score from chain length (longer = more exposure)
	score += len(hops) * 10

	// Scope violations are the primary signal
	for _, hop := range hops[1:] {
		if hop.BlastDelta > 0 {
			score += 15 // blast radius widens
		}
		if hop.RBACDelta > 0 {
			score += 20 // privilege escalates
		}
		if hop.AuthBoundary == "none" {
			score += 10 // no auth between hops
		}
	}

	// Terminal target severity
	for _, t := range terminalTargets {
		tl := strings.ToLower(t)
		if strings.Contains(tl, "cluster-admin") {
			score += 30
		} else if strings.Contains(tl, "secrets") {
			score += 25
		} else if strings.Contains(tl, "datastore") || strings.Contains(tl, "auth") {
			score += 15
		}
	}

	// Internet access at any hop
	for _, hop := range hops {
		if hop.InternetAccess {
			score += 5
		}
	}

	// In-use CVEs on critical hops
	for _, hop := range hops {
		if hop.CriticalCVEs > 0 {
			score += 10
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	exposure := "low"
	if score >= 75 {
		exposure = "critical"
	} else if score >= 50 {
		exposure = "high"
	} else if score >= 25 {
		exposure = "medium"
	}

	return exposure, score
}

func recommendFix(hops []types.DelegationHop, violations []string, terminalTargets []string) string {
	var fixes []string

	// Priority 1: Add NetworkPolicy to MCP servers
	for _, hop := range hops {
		if strings.Contains(strings.ToLower(hop.WorkloadClass), "mcp") && !hop.HasNetPolicy {
			fixes = append(fixes, "Add NetworkPolicy to "+shortPodName(hop.PodName)+" (restrict ingress to known agents only)")
			break
		}
	}

	// Priority 2: Reduce RBAC on elevated pods
	for i := 1; i < len(hops); i++ {
		if hops[i].RBACDelta > 0 {
			fixes = append(fixes, "Restrict SA '"+hops[i].RBACSA+"' on "+shortPodName(hops[i].PodName)+" (remove secret/create-pod permissions)")
			break
		}
	}

	// Priority 3: Add auth between hops
	authGap := false
	for _, hop := range hops[1:] {
		if hop.AuthBoundary == "none" {
			authGap = true
			break
		}
	}
	if authGap {
		fixes = append(fixes, "Add NetworkPolicy between agent and MCP hops to enforce boundaries")
	}

	if len(fixes) == 0 {
		return ""
	}
	return strings.Join(fixes, " + ")
}

func summarizeChains(chains []types.DelegationChain) *types.DelegationSummary {
	if len(chains) == 0 {
		return nil
	}

	summary := &types.DelegationSummary{
		TotalChains: len(chains),
	}

	for _, chain := range chains {
		if chain.Exposure == "critical" {
			summary.CriticalChains++
		}
		if len(chain.Hops) > summary.MaxChainDepth {
			summary.MaxChainDepth = len(chain.Hops)
		}

		// Count violations across all chains
		for _, hop := range chain.Hops[1:] {
			if hop.BlastDelta > 0 || hop.RBACDelta > 0 {
				summary.ScopeViolations++
			}
			if hop.AuthBoundary == "none" {
				summary.AuthGaps++
			}
		}

		for _, t := range chain.TerminalTargets {
			tl := strings.ToLower(t)
			if strings.Contains(tl, "secrets") || strings.Contains(tl, "cluster-admin") {
				summary.SecretsReachable++
			}
			if strings.Contains(tl, "datastore") {
				summary.DataStores++
			}
		}
	}

	return summary
}

func countInUseCVEs(score *types.PlexarScore) int {
	count := 0
	cves := score.Vulns.AllCVEs
	if len(cves) == 0 {
		cves = score.Vulns.TopCVEs
	}
	for _, c := range cves {
		if c.InUse {
			count++
		}
	}
	return count
}

func shortPodName(podName string) string {
	parts := strings.Split(podName, "-")
	if len(parts) > 2 {
		// Drop the last 2 segments (replicaset hash + pod hash)
		for i := len(parts) - 1; i >= 1; i-- {
			if looksLikeHash(parts[i]) {
				parts = parts[:i]
			} else {
				break
			}
		}
	}
	return strings.Join(parts, "-")
}

func isDataStore(s string) bool {
	return strings.Contains(s, "db") || strings.Contains(s, "mongo") ||
		strings.Contains(s, "cockroach") || strings.Contains(s, "postgres") ||
		strings.Contains(s, "elasticsearch") || strings.Contains(s, "opensearch") ||
		strings.Contains(s, "redis") || strings.Contains(s, "kafka")
}

func isAuthService(s string) bool {
	return strings.Contains(s, "auth") || strings.Contains(s, "oidc") ||
		strings.Contains(s, "security") || strings.Contains(s, "securitymgr")
}

func dedup(items []string) []string {
	seen := make(map[string]bool, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
