package api

import (
	"context"
	"fmt"
	"io"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/plexar-io/plexar/internal/types"
	"github.com/plexar-io/plexar/pkg/attackpath"
	"github.com/plexar-io/plexar/pkg/classifier"
	"github.com/plexar-io/plexar/pkg/compliance"
	"github.com/plexar-io/plexar/pkg/hubble"
	"github.com/plexar-io/plexar/pkg/k8s"
	"github.com/plexar-io/plexar/pkg/network"
	"github.com/plexar-io/plexar/pkg/permissions"
	"github.com/plexar-io/plexar/pkg/rbac"
	rt "github.com/plexar-io/plexar/pkg/runtime"
	"github.com/plexar-io/plexar/pkg/scanner"
	"github.com/plexar-io/plexar/pkg/scorer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ActiveVulnSource is the currently configured vulnerability source.
// Set this before calling RunScan to use a different scanner backend.
// Defaults to nil, which auto-selects trivy.
var ActiveVulnSource scanner.VulnSource

// HubbleRelayAddr is the optional explicit address for Hubble Relay.
// If empty, auto-detection via Kubernetes service lookup is used.
var HubbleRelayAddr string

// latestInsights holds the most recent runtime insights from a scan.
var (
	latestInsights   *types.RuntimeInsights
	latestAttackPath *types.AttackPathSummary
	insightsMu       sync.RWMutex
)

// LatestRuntimeInsights returns the most recent runtime insights.
func LatestRuntimeInsights() *types.RuntimeInsights {
	insightsMu.RLock()
	defer insightsMu.RUnlock()
	return latestInsights
}

// LatestAttackPaths returns the most recent attack path analysis.
func LatestAttackPaths() *types.AttackPathSummary {
	insightsMu.RLock()
	defer insightsMu.RUnlock()
	return latestAttackPath
}

// RunMultiNamespaceScan scans multiple namespaces and merges the results.
// Pass namespaces as a slice, or pass nil/empty to use the provided fallback.
func RunMultiNamespaceScan(kubeconfig string, namespaces []string, progress io.Writer) (*types.ScanResult, error) {
	if progress == nil {
		progress = io.Discard
	}

	if len(namespaces) == 0 {
		return nil, fmt.Errorf("no namespaces specified")
	}

	// Single namespace — fast path
	if len(namespaces) == 1 {
		return RunScan(kubeconfig, namespaces[0], progress)
	}

	fmt.Fprintf(progress, "📡 Scanning %d namespaces: %s\n", len(namespaces), strings.Join(namespaces, ", "))

	var allScores []types.PlexarScore
	var allWarnings []string
	var allCompliance []types.ComplianceResult
	totalPods := 0
	totalNetPol := 0
	clusterName := ""

	for i, ns := range namespaces {
		fmt.Fprintf(progress, "\n── Namespace %d/%d: %s ──\n", i+1, len(namespaces), ns)
		result, err := RunScan(kubeconfig, ns, progress)
		if err != nil {
			fmt.Fprintf(progress, "⚠  Skipping namespace %s: %v\n", ns, err)
			continue
		}

		if clusterName == "" {
			clusterName = result.ClusterName
		}

		allScores = append(allScores, result.Scores...)
		allWarnings = append(allWarnings, result.Warnings...)
		totalPods += result.TotalPods
		totalNetPol += result.NetworkPolicies

		if len(allCompliance) == 0 {
			allCompliance = result.Compliance
		}
	}

	// Re-sort all scores across namespaces
	sort.Slice(allScores, func(i, j int) bool {
		return allScores[i].Total > allScores[j].Total
	})

	clusterScore := 0
	if len(allScores) > 0 {
		total := 0
		for _, s := range allScores {
			total += s.Total
		}
		clusterScore = total / len(allScores)
	}

	// Re-compute compliance across all namespaces
	allCompliance = compliance.MapAll(allScores, totalNetPol)

	return &types.ScanResult{
		ClusterName:     clusterName,
		Namespace:       strings.Join(namespaces, ","),
		ScanTime:        time.Now(),
		TotalPods:       totalPods,
		Scores:          allScores,
		ClusterScore:    clusterScore,
		NetworkPolicies: totalNetPol,
		Warnings:        allWarnings,
		Compliance:      allCompliance,
	}, nil
}

// ListNamespaces returns all non-system namespace names in the cluster.
func ListNamespaces(kubeconfig string) ([]string, error) {
	client, err := k8s.NewClient(kubeconfig)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	nsList, err := client.Clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	systemNS := map[string]bool{
		"kube-system": true, "kube-public": true, "kube-node-lease": true,
	}

	var names []string
	for _, ns := range nsList.Items {
		if !systemNS[ns.Name] {
			names = append(names, ns.Name)
		}
	}
	return names, nil
}

// RunScan executes the full Plexar scan pipeline and returns a ScanResult.
// progress can be nil to suppress output (used by API/background scans).
func RunScan(kubeconfig, namespace string, progress io.Writer) (*types.ScanResult, error) {
	if progress == nil {
		progress = io.Discard
	}

	fmt.Fprintf(progress, "🛡  Connecting to cluster...\n")
	client, err := k8s.NewClient(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to cluster: %w", err)
	}

	clusterName := client.ClusterName()
	fmt.Fprintf(progress, "📡 Cluster: %s | Namespace: %s\n", clusterName, namespace)

	// Use configured vuln source, default to trivy
	vulnSource := ActiveVulnSource
	if vulnSource == nil {
		vulnSource, _ = scanner.NewSource(scanner.SourceTrivy)
	}

	// Vuln scanning gets a generous timeout (trivy subprocess can be slow)
	vulnCtx, vulnCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer vulnCancel()

	fmt.Fprintf(progress, "🔍 Scanning vulnerabilities (source: %s)...\n", vulnSource.Name())
	vulns, err := vulnSource.ScanNamespace(vulnCtx, client, namespace)
	if err != nil {
		return nil, fmt.Errorf("CVE scan failed: %w", err)
	}
	fmt.Fprintf(progress, "   Found %d pods with vulnerability data\n", len(vulns))

	// Network + permissions analysis uses a separate timeout
	analysisCtx, analysisCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer analysisCancel()

	fmt.Fprintf(progress, "🌐 Mapping network blast radius...\n")
	netAnalyzer := network.New(client)

	// Hubble dual-mode: prefer observed flows, fall back to inferred reachability
	hubbleAvailable := false
	flowSource := "inferred"
	var observedFlows []types.ObservedFlow

	var hubbleOpts []hubble.ClientOption
	if HubbleRelayAddr != "" {
		hubbleOpts = append(hubbleOpts, hubble.WithRelayAddress(HubbleRelayAddr))
	}
	hubbleClient := hubble.NewClient(client.Clientset, hubbleOpts...)
	if hubbleClient.Available(analysisCtx) {
		hubbleAvailable = true
		fmt.Fprintf(progress, "   ✅ Hubble Relay detected — using observed network flows\n")
		flows, flowErr := hubbleClient.CollectFlows(analysisCtx, namespace, 1*time.Hour)
		if flowErr != nil {
			log.Printf("[hubble] flow collection failed, falling back to inferred: %v", flowErr)
			fmt.Fprintf(progress, "   ⚠  Hubble flow collection failed: %v — falling back to inferred\n", flowErr)
		} else {
			observedFlows = flows
			flowSource = "hubble"
			fmt.Fprintf(progress, "   Collected %d observed flows\n", len(flows))
		}
	} else {
		fmt.Fprintf(progress, "   ℹ  Hubble not detected — using inferred reachability (install Cilium + Hubble for observed flows)\n")
	}

	var blasts []types.BlastRadius
	var netPolCount int
	if flowSource == "hubble" && len(observedFlows) > 0 {
		blasts, netPolCount, err = netAnalyzer.AnalyzeNamespaceWithFlows(analysisCtx, namespace, observedFlows)
	} else {
		blasts, netPolCount, err = netAnalyzer.AnalyzeNamespace(analysisCtx, namespace)
	}
	if err != nil {
		return nil, fmt.Errorf("network analysis failed: %w", err)
	}
	fmt.Fprintf(progress, "   Found %d pods, %d NetworkPolicies (source: %s)\n", len(blasts), netPolCount, flowSource)

	fmt.Fprintf(progress, "🔓 Checking permissions and security context...\n")
	permAnalyzer := permissions.New(client)
	perms, err := permAnalyzer.AnalyzeNamespace(analysisCtx, namespace)
	if err != nil {
		return nil, fmt.Errorf("permission analysis failed: %w", err)
	}

	fmt.Fprintf(progress, "� Auditing RBAC permissions...\n")
	rbacAuditor := rbac.New(client)
	rbacResult, err := rbacAuditor.AuditNamespace(analysisCtx, namespace)
	var rbacFindings []types.RBACFinding
	if err != nil {
		fmt.Fprintf(progress, "   ⚠  RBAC audit skipped: %v\n", err)
	} else {
		rbacFindings = rbacResult.Findings
		fmt.Fprintf(progress, "   %d pods audited, %d critical RBAC, %d high RBAC\n",
			rbacResult.TotalPods, rbacResult.CriticalCount, rbacResult.HighCount)
	}

	fmt.Fprintf(progress, "🛡  Computing Plexar scores...\n")

	blastMap := make(map[string]types.BlastRadius)
	for _, b := range blasts {
		blastMap[b.PodName] = b
	}
	permMap := make(map[string]types.PodPermissions)
	for _, p := range perms {
		permMap[p.PodName] = p
	}

	findBlast := func(prefix string) types.BlastRadius {
		if b, ok := blastMap[prefix]; ok {
			return b
		}
		for k, b := range blastMap {
			if strings.HasPrefix(k, prefix) {
				return b
			}
		}
		return types.BlastRadius{}
	}
	findPerm := func(prefix string) types.PodPermissions {
		if p, ok := permMap[prefix]; ok {
			return p
		}
		for k, p := range permMap {
			if strings.HasPrefix(k, prefix) {
				return p
			}
		}
		return types.PodPermissions{}
	}

	// Build pod labels map for topology grouping
	podLabelsMap := make(map[string]map[string]string)
	podList, podListErr := client.Clientset.CoreV1().Pods(namespace).List(analysisCtx, metav1.ListOptions{})
	if podListErr == nil {
		for _, p := range podList.Items {
			podLabelsMap[p.Name] = p.Labels
		}
	}

	var scores []types.PlexarScore
	for _, vuln := range vulns {
		blast := findBlast(vuln.PodName)
		perm := findPerm(vuln.PodName)
		score := scorer.Score(vuln, blast, perm)
		score.Namespace = namespace
		// Attach pod labels — try exact match then prefix match
		if labels, ok := podLabelsMap[vuln.PodName]; ok {
			score.Labels = labels
		} else {
			for k, labels := range podLabelsMap {
				if strings.HasPrefix(k, vuln.PodName) {
					score.Labels = labels
					break
				}
			}
		}
		scores = append(scores, score)
	}

	// Classify workloads and apply risk multipliers
	fmt.Fprintf(progress, "🧠 Classifying workloads...\n")
	scores = classifier.ClassifyAll(scores)
	for _, s := range scores {
		if s.RiskMultiplier != 1.0 {
			fmt.Fprintf(progress, "   %s → %s (×%.2f)\n", shortPod(s.PodName), s.WorkloadClass, s.RiskMultiplier)
		}
	}

	// Runtime profiling — tag CVEs that are actually "in use" at runtime
	fmt.Fprintf(progress, "🔬 Profiling runtime packages (In Use detection)...\n")
	profiler := rt.NewProfiler(client)
	profiles, profErr := profiler.ProfileNamespace(analysisCtx, namespace)
	if profErr != nil {
		fmt.Fprintf(progress, "   ⚠  Runtime profiling skipped: %v\n", profErr)
		// Fallback: count CVEs without runtime data so the page isn't stuck on "pending"
		var fallbackVulns []types.VulnSummary
		for _, s := range scores {
			fallbackVulns = append(fallbackVulns, s.Vulns)
		}
		_, fallbackInsights := rt.MatchInUse(fallbackVulns, nil)
		insightsMu.Lock()
		latestInsights = fallbackInsights
		insightsMu.Unlock()
	} else {
		var enrichedVulns []types.VulnSummary
		for _, s := range scores {
			enrichedVulns = append(enrichedVulns, s.Vulns)
		}
		enrichedVulns, insights := rt.MatchInUse(enrichedVulns, profiles)
		scores = rt.EnrichScoresWithRuntime(scores, enrichedVulns)
		fmt.Fprintf(progress, "   %d total CVEs, %d in-use (%.0f%% noise reduction)\n",
			insights.TotalCVEs, insights.InUseCVEs, insights.NoiseReduction)

		insightsMu.Lock()
		latestInsights = insights
		insightsMu.Unlock()
	}

	// Attack path analysis (includes exploit chain traversal)
	fmt.Fprintf(progress, "🗺  Computing attack paths + exploit chains...\n")
	graph := attackpath.Build(scores, rbacFindings)
	apSummary := attackpath.Analyze(graph)
	fmt.Fprintf(progress, "   %d attack paths found (%d critical, shortest: %d hops)\n",
		apSummary.TotalPaths, apSummary.CriticalPaths, apSummary.ShortestHops)
	if apSummary.ChainSummary != nil && apSummary.ChainSummary.TotalChains > 0 {
		fmt.Fprintf(progress, "   ⛓  %d exploit chains (%d critical, %d agent-involved)\n",
			apSummary.ChainSummary.TotalChains, apSummary.ChainSummary.CriticalChains, apSummary.ChainSummary.AgentChains)
		if apSummary.ChainSummary.TopBreakFix.CVEID != "" {
			fmt.Fprintf(progress, "   🔧 Top break-the-chain fix: patch %s on %s (eliminates %d chains)\n",
				apSummary.ChainSummary.TopBreakFix.CVEID, apSummary.ChainSummary.TopBreakFix.PodName, apSummary.ChainSummary.TopBreakFix.ChainsEliminated)
		}
	}

	insightsMu.Lock()
	latestAttackPath = apSummary
	insightsMu.Unlock()

	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Total > scores[j].Total
	})

	clusterScore := 0
	if len(scores) > 0 {
		total := 0
		for _, s := range scores {
			total += s.Total
		}
		clusterScore = total / len(scores)
	}

	var warnings []string
	if netPolCount == 0 {
		warnings = append(warnings, fmt.Sprintf("ZERO NetworkPolicies in namespace '%s'. Every pod can reach every other pod AND the internet.", namespace))
	}

	complianceResults := compliance.MapAll(scores, netPolCount, rbacFindings)

	result := &types.ScanResult{
		ClusterName:     clusterName,
		Namespace:       namespace,
		ScanTime:        time.Now(),
		TotalPods:       len(vulns),
		Scores:          scores,
		ClusterScore:    clusterScore,
		NetworkPolicies: netPolCount,
		Warnings:        warnings,
		Compliance:      complianceResults,
		RBACFindings:    rbacFindings,
		HubbleAvailable: hubbleAvailable,
		FlowSource:      flowSource,
	}

	return result, nil
}

// shortPod strips the replicaset hash suffix from a pod name for cleaner output
func shortPod(name string) string {
	parts := strings.Split(name, "-")
	if len(parts) > 2 {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return name
}
