package agentsec

import (
	"strings"

	"github.com/plexar-io/plexar/internal/types"
	"github.com/plexar-io/plexar/pkg/classifier"
)

// Analyze inspects scan results for AI agent security signals:
// - Identifies MCP servers, AI agents, and their relationships
// - Maps agent-to-MCP-to-service dependency chains
// - Detects unprotected agent workloads and high-risk tool access
// - Computes agent-specific blast radius
func Analyze(scores []types.PlexarScore) *types.AgentSecuritySummary {
	summary := &types.AgentSecuritySummary{}

	// Index: pod name -> score for cross-referencing
	podIndex := make(map[string]*types.PlexarScore, len(scores))
	for i := range scores {
		podIndex[scores[i].PodName] = &scores[i]
	}

	// Phase 1: Identify MCP servers and agent pods
	var mcpPods, agentPods []*types.PlexarScore
	for i := range scores {
		if !classifier.IsAgentClass(scores[i].WorkloadClass) {
			continue
		}
		summary.TotalAgentPods++

		// Check if this is specifically an MCP server
		if isMCPServer(&scores[i]) {
			mcpPods = append(mcpPods, &scores[i])
			summary.MCPServers++
		} else {
			agentPods = append(agentPods, &scores[i])
		}

		if !scores[i].Blast.HasNetworkPolicy {
			summary.UnprotectedAgents++
		}
	}

	// Phase 2: Map agent dependencies from blast radius data
	// For each MCP server, find which agent pods can reach it
	for _, mcp := range mcpPods {
		mcpServiceNames := inferServiceNames(mcp.PodName, mcp.Namespace)
		ctx := buildAgentContext(mcp, true)

		// Find agents that can reach this MCP server
		for _, agent := range agentPods {
			for _, target := range agent.Blast.ReachableTargets {
				if matchesService(target, mcpServiceNames) {
					ctx.ConnectedAgents = append(ctx.ConnectedAgents, agent.PodName)
					summary.AgentDependencies = append(summary.AgentDependencies, types.AgentDependencyEdge{
						From:     agent.PodName,
						To:       mcp.PodName,
						EdgeType: "agent_to_mcp",
						Protocol: "mcp",
					})
					break
				}
			}
		}

		// Map what services the MCP server can reach (tool-reachable services)
		for _, target := range mcp.Blast.ReachableTargets {
			// Classify the reachable target
			targetPod := findPodByService(target, podIndex)
			if targetPod != nil {
				edgeType := "mcp_to_service"
				if classifier.IsAgentClass(targetPod.WorkloadClass) {
					edgeType = "agent_to_agent"
				}
				summary.AgentDependencies = append(summary.AgentDependencies, types.AgentDependencyEdge{
					From:     mcp.PodName,
					To:       targetPod.PodName,
					EdgeType: edgeType,
				})
			}
			ctx.ToolReachableServices = append(ctx.ToolReachableServices, target)
		}

		ctx.AgentBlastRadius = len(ctx.ToolReachableServices)
		mcp.AgentContext = ctx
	}

	// Phase 3: For agent pods, find which MCP servers they connect to
	for _, agent := range agentPods {
		ctx := buildAgentContext(agent, false)

		for _, mcp := range mcpPods {
			mcpServiceNames := inferServiceNames(mcp.PodName, mcp.Namespace)
			for _, target := range agent.Blast.ReachableTargets {
				if matchesService(target, mcpServiceNames) {
					ctx.ConnectedMCPs = append(ctx.ConnectedMCPs, mcp.PodName)
					break
				}
			}
		}

		ctx.AgentBlastRadius = len(agent.Blast.ReachableTargets)
		agent.AgentContext = ctx
	}

	// Phase 4: Generate high-risk findings
	summary.HighRiskFindings = generateFindings(mcpPods, agentPods, scores)

	return summary
}

// AnalyzeWithRBAC runs the full agent analysis including delegation chains.
// Call this when RBAC data is available for scope attenuation checks.
func AnalyzeWithRBAC(scores []types.PlexarScore, rbacFindings []types.RBACFinding) *types.AgentSecuritySummary {
	summary := Analyze(scores)
	chains, delSummary := AnalyzeDelegation(scores, rbacFindings)
	summary.DelegationChains = chains
	summary.DelegationSummary = delSummary
	return summary
}

// buildAgentContext creates the base AgentContext for a pod
func buildAgentContext(score *types.PlexarScore, isMCP bool) *types.AgentContext {
	ctx := &types.AgentContext{
		IsAgentWorkload: true,
		AgentClass:      score.WorkloadClass,
	}

	var warnings []string

	if !score.Blast.HasNetworkPolicy {
		if isMCP {
			warnings = append(warnings, "MCP server has no NetworkPolicy — any pod in the cluster can invoke its tools")
		} else {
			warnings = append(warnings, "Agent has no NetworkPolicy — can reach all services in the cluster")
		}
	}

	if score.Blast.InternetAccess {
		if isMCP {
			warnings = append(warnings, "MCP server has internet access — compromised tools could exfiltrate data")
		} else {
			warnings = append(warnings, "Agent has internet egress — prompt injection could exfiltrate data to external endpoints")
		}
	}

	if score.Permissions.ServiceAccountName != "default" && score.Permissions.ServiceAccountName != "" {
		warnings = append(warnings, "Uses custom ServiceAccount '"+score.Permissions.ServiceAccountName+"' — check RBAC for elevated privileges")
	}

	ctx.Warnings = warnings
	return ctx
}

// generateFindings produces human-readable high-risk findings
func generateFindings(mcpPods, agentPods []*types.PlexarScore, allScores []types.PlexarScore) []string {
	var findings []string

	for _, mcp := range mcpPods {
		reachable := len(mcp.Blast.ReachableTargets)

		if !mcp.Blast.HasNetworkPolicy && reachable > 10 {
			findings = append(findings,
				mcp.PodName+": MCP server with no NetworkPolicy can reach "+
					itoa(reachable)+" services + internet. Any compromised agent can use this as a pivot point.")
		}

		// Count high-value targets reachable through MCP
		var dbCount, authCount int
		for _, target := range mcp.Blast.ReachableTargets {
			tl := strings.ToLower(target)
			if strings.Contains(tl, "db") || strings.Contains(tl, "mongo") || strings.Contains(tl, "cockroach") || strings.Contains(tl, "postgres") || strings.Contains(tl, "elasticsearch") {
				dbCount++
			}
			if strings.Contains(tl, "auth") || strings.Contains(tl, "oidc") || strings.Contains(tl, "security") {
				authCount++
			}
		}
		if dbCount > 0 {
			findings = append(findings,
				mcp.PodName+": MCP server can reach "+itoa(dbCount)+" data stores (databases/search). "+
					"Agent tool calls through this MCP server could access or modify persistent data.")
		}
		if authCount > 0 {
			findings = append(findings,
				mcp.PodName+": MCP server can reach "+itoa(authCount)+" authentication/security services. "+
					"Compromised MCP tools could manipulate access controls.")
		}
	}

	for _, agent := range agentPods {
		if agent.AgentContext != nil && len(agent.AgentContext.ConnectedMCPs) > 0 && !agent.Blast.HasNetworkPolicy {
			findings = append(findings,
				agent.PodName+": Agent connects to "+itoa(len(agent.AgentContext.ConnectedMCPs))+
					" MCP server(s) with no NetworkPolicy. Prompt injection on this agent "+
					"could invoke any tool on the connected MCP servers.")
		}
	}

	return findings
}

// isMCPServer checks if a pod is an MCP server (vs other agent types)
func isMCPServer(score *types.PlexarScore) bool {
	name := strings.ToLower(score.PodName)
	image := strings.ToLower(score.ImageName)
	return strings.Contains(name, "mcp") || strings.Contains(image, "mcp")
}

// inferServiceNames returns likely K8s service names for a pod
// (e.g. pod "mcpserver-5cbd97ff59-85rgm" -> ["mcpserver", "mcp"])
func inferServiceNames(podName, namespace string) []string {
	// Strip replicaset/deployment hash suffixes
	parts := strings.Split(podName, "-")
	var names []string

	// Try progressively shorter prefixes
	for i := len(parts) - 1; i >= 1; i-- {
		// Skip if this segment looks like a hash (5+ hex chars or random chars)
		if len(parts[i]) >= 5 && looksLikeHash(parts[i]) {
			continue
		}
		candidate := strings.Join(parts[:i+1], "-")
		names = append(names, candidate)
	}
	if len(parts) > 0 {
		names = append(names, parts[0])
	}

	// Add namespace-qualified versions
	if namespace != "" {
		extra := make([]string, 0, len(names))
		for _, n := range names {
			extra = append(extra, n+"."+namespace)
		}
		names = append(names, extra...)
	}

	return names
}

// matchesService checks if a blast radius target matches any of the service names
func matchesService(target string, serviceNames []string) bool {
	tl := strings.ToLower(target)
	for _, svc := range serviceNames {
		if strings.Contains(tl, strings.ToLower(svc)) {
			return true
		}
	}
	return false
}

// findPodByService finds a pod whose name matches a service target
func findPodByService(target string, podIndex map[string]*types.PlexarScore) *types.PlexarScore {
	tl := strings.ToLower(target)
	// Direct name match (strip namespace suffix)
	baseName := tl
	if idx := strings.IndexByte(baseName, '.'); idx > 0 {
		baseName = baseName[:idx]
	}

	for podName, score := range podIndex {
		if strings.HasPrefix(strings.ToLower(podName), baseName) {
			return score
		}
	}
	return nil
}

func looksLikeHash(s string) bool {
	if len(s) < 5 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
