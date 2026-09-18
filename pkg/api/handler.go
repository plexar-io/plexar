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
	"github.com/plexar-io/plexar/pkg/agentsec"
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

// ── ANSI helpers ──
const (
	ansiReset   = "\033[0m"
	ansiBold    = "\033[1m"
	ansiDim     = "\033[2m"
	ansiCyan    = "\033[36m"
	ansiGreen   = "\033[32m"
	ansiYellow  = "\033[33m"
	ansiMagenta = "\033[35m"
	ansiBlue    = "\033[34m"
	ansiRed     = "\033[31m"
	ansiClearLn = "\033[2K"
	ansiHideCur = "\033[?25l"
	ansiShowCur = "\033[?25h"
)

// ASCII art diagrams that cycle during scanning — each is 5 lines tall
// ASCII art diagrams — nature/journey scenes that tie to security phases.
// Each is 7 lines tall for visual impact.
var scanDiagrams = [][]string{
	{ // 0: Sunrise over mountains — "Starting the journey"
		"                 *                  ",
		"              .*' '*.               ",
		"           .*'       '*.            ",
		"     .  .*' Scanning... '*.  .      ",
		"    /|*'                   '*|\\    ",
		"   / |  .    .       .    .  | \\   ",
		"  /__|_________________________\\  ",
	},
	{ // 1: Telescope on peak — "Scanning vulnerabilities"
		"           ()                       ",
		"          /||\\                     ",
		"         / || \\                    ",
		"        /  ||  \\  Probing images   ",
		"     __/___||___\\___               ",
		"    /       ^^       \\             ",
		"   /   .  mountains  . \\           ",
	},
	{ // 2: Map with trails — "Mapping network"
		"    +--------+--------+             ",
		"    | ~ ~ ~  |  /   / |  Mapping    ",
		"    |   ~ ~  | /___/  |  network    ",
		"    +--------|--------|  topology   ",
		"    | /  /   | ~ ~ ~ |             ",
		"    |/  / X  |  ~ ~  |             ",
		"    +--------+--------+             ",
	},
	{ // 3: Compass — "Finding permissions"
		"         .---.                       ",
		"        /  N  \\      Checking       ",
		"       | W + E |     permissions     ",
		"        \\  S  /      & RBAC         ",
		"         '---'                       ",
		"           |                         ",
		"           *                         ",
	},
	{ // 4: Campfire — "Computing scores"
		"                                    ",
		"          )  (  )                    ",
		"         (  )  (   Scoring           ",
		"          ) ( ) (  blast radius      ",
		"         .-------.                   ",
		"        / ~ ~ ~ ~ \\                ",
		"       /~~~~~~~~~~~~\\               ",
	},
	{ // 5: Binoculars — "Classifying workloads"
		"        .---.  .---.                 ",
		"       / o  |  |  o \\  Classifying  ",
		"      |  .  |  |  .  |  workloads   ",
		"       \\ | /    \\ | /              ",
		"        '-'      '-'                 ",
		"         |   __   |                  ",
		"         '--'  '--'                  ",
	},
	{ // 6: Lighthouse — "Runtime profiling"
		"           /\\                       ",
		"          /  \\       Profiling       ",
		"         / ** \\      runtime         ",
		"        /  **  \\     packages        ",
		"       /________\\                    ",
		"       |  |  |  |                    ",
		"    ~~~|__|__|__|~~~                  ",
	},
	{ // 7: Summit flag — "Attack paths"
		"               |>                    ",
		"               |   Attack            ",
		"              /|\\  path              ",
		"             / | \\  analysis         ",
		"           _/  |  \\_                ",
		"         _/    |    \\_              ",
		"    ____/      |      \\____         ",
	},
	{ // 8: Eagle soaring — "Final analysis"
		"            .  __  .                 ",
		"          ---'    '---               ",
		"       --'    ◈◈    '--   Soaring    ",
		"     -'    ◈◈◈◈◈◈    '-   above     ",
		"         ◈◈◈◈◈◈◈◈◈◈       the noise ",
		"            ^^^^                     ",
		"        ~~~~    ~~~~                  ",
	},
	{ // 9: Constellation — "Connecting the dots"
		"       *           *                 ",
		"        \\  *      /     Mapping      ",
		"         \\/  *   /      exploit      ",
		"      *--◈------◈--*   chains       ",
		"         /\\     /                    ",
		"        /  *   /                     ",
		"       *      *                      ",
	},
}

// spinner draws a single animated line with cycling ASCII art diagrams above it.
type spinner struct {
	w         io.Writer
	phase     string
	phaseNum  int
	total     int
	done      chan struct{}
	startTime time.Time
	drawn     int    // lines drawn (for clearing)
	detail    string // current sub-step detail (e.g. "[export] 1432MB (3m)")
	mu        sync.Mutex
}

// SetDetail updates the sub-step detail shown below the progress bar.
func (s *spinner) SetDetail(detail string) {
	s.mu.Lock()
	s.detail = detail
	s.mu.Unlock()
}

var activeScanStart time.Time

func startSpinner(w io.Writer, msg string) *spinner {
	if w == nil || w == io.Discard {
		return &spinner{done: make(chan struct{})}
	}
	if activeScanStart.IsZero() {
		activeScanStart = time.Now()
		fmt.Fprintf(w, "%s", ansiHideCur) // hide cursor during animation
	}
	activeScanPhase++
	s := &spinner{
		w:         w,
		phase:     msg,
		phaseNum:  activeScanPhase,
		total:     7,
		done:      make(chan struct{}),
		startTime: time.Now(),
	}
	go s.run()
	return s
}

var activeScanPhase int

func (s *spinner) run() {
	if s.w == nil {
		return
	}
	tick := time.NewTicker(120 * time.Millisecond)
	defer tick.Stop()
	frame := 0
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			s.draw(frame)
			frame++
		}
	}
}

func (s *spinner) draw(frame int) {
	if s.w == nil {
		return
	}

	// Move cursor up to clear previous drawing
	if s.drawn > 0 {
		fmt.Fprintf(s.w, "\033[%dA", s.drawn)
	}

	lines := 0
	elapsed := time.Since(activeScanStart).Truncate(time.Second)
	phaseElapsed := time.Since(s.startTime).Truncate(time.Second)

	// Pick diagram — changes every ~3 seconds
	diagramIdx := (int(time.Since(activeScanStart).Seconds()) / 3) % len(scanDiagrams)
	diagram := scanDiagrams[diagramIdx]

	// Color for the diagram cycles subtly
	colors := []string{ansiCyan, ansiBlue, ansiMagenta, ansiCyan}
	dColor := colors[diagramIdx%len(colors)]

	// Draw diagram
	for _, line := range diagram {
		fmt.Fprintf(s.w, "%s  %s%s%s\n", ansiClearLn, dColor, line, ansiReset)
		lines++
	}

	// Blank spacer
	fmt.Fprintf(s.w, "%s\n", ansiClearLn)
	lines++

	// Progress bar
	barWidth := 30
	filled := (s.phaseNum * barWidth) / s.total
	if filled > barWidth {
		filled = barWidth
	}
	bar := ""
	for i := 0; i < barWidth; i++ {
		if i < filled {
			bar += "█"
		} else if i == filled {
			pulse := []string{"▓", "▒", "░", "▒"}
			bar += ansiCyan + pulse[frame%len(pulse)] + ansiGreen
		} else {
			bar += "░"
		}
	}

	// Braille spinner for extra motion
	braille := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	dot := braille[frame%len(braille)]

	fmt.Fprintf(s.w, "%s  %s%s%s %s%s%s  %sphase %d/%d%s  %s%s%s  %s%s%s\n",
		ansiClearLn,
		ansiGreen, bar, ansiReset,
		ansiCyan, dot, ansiReset,
		ansiDim, s.phaseNum, s.total, ansiReset,
		ansiBold, s.phase, ansiReset,
		ansiDim, phaseElapsed, ansiReset)
	lines++

	// Sub-step detail (e.g. current image export/scan progress)
	s.mu.Lock()
	detail := s.detail
	s.mu.Unlock()
	if detail != "" {
		fmt.Fprintf(s.w, "%s  %s%s%s\n", ansiClearLn, ansiDim, detail, ansiReset)
		lines++
	}

	// Overall elapsed
	fmt.Fprintf(s.w, "%s  %s◈ plexar scan%s  %selapsed: %s%s\n",
		ansiClearLn,
		ansiDim, ansiReset,
		ansiDim, elapsed, ansiReset)
	lines++

	s.drawn = lines
}

func (s *spinner) stop(result string) {
	if s.w == nil {
		return
	}
	close(s.done)
	time.Sleep(15 * time.Millisecond) // let animation goroutine exit

	// Clear the animated block
	if s.drawn > 0 {
		fmt.Fprintf(s.w, "\033[%dA", s.drawn)
		for i := 0; i < s.drawn; i++ {
			fmt.Fprintf(s.w, "%s\n", ansiClearLn)
		}
		fmt.Fprintf(s.w, "\033[%dA", s.drawn)
	}

	// Print the completed result as a single line
	phaseElapsed := time.Since(s.startTime).Truncate(time.Second)
	fmt.Fprintf(s.w, "  %s✓%s %s  %s(%s)%s\n", ansiGreen, ansiReset, result, ansiDim, phaseElapsed, ansiReset)
}

func resetScanProgress() {
	activeScanPhase = 0
	activeScanStart = time.Time{}
}

// spinnerWriter is an io.Writer that feeds scanner progress to the spinner's detail line.
// It captures the last non-empty line written and updates the spinner in real time,
// AND accumulates completed lines so they can be printed persistently after the
// spinner stops (otherwise they're lost when the spinner clears its drawn area).
type spinnerWriter struct {
	sp    *spinner
	lines []string // accumulated completed log lines
	buf   string   // partial line buffer (no newline yet)
}

func (sw *spinnerWriter) Write(p []byte) (n int, err error) {
	sw.buf += string(p)

	// Process complete lines (ending with \n)
	for {
		idx := strings.IndexByte(sw.buf, '\n')
		if idx < 0 {
			break
		}
		line := strings.TrimSpace(sw.buf[:idx])
		sw.buf = sw.buf[idx+1:]
		if line != "" {
			sw.lines = append(sw.lines, line)
		}
	}

	// Update spinner detail with the latest content (complete or partial)
	latest := strings.TrimSpace(sw.buf)
	if latest == "" && len(sw.lines) > 0 {
		latest = sw.lines[len(sw.lines)-1]
	}
	if latest != "" {
		sw.sp.SetDetail(latest)
	}

	return len(p), nil
}

// Flush prints all accumulated log lines to the given writer.
// Called after the spinner stops so the per-image progress persists in logs.
func (sw *spinnerWriter) Flush(w io.Writer) {
	for _, line := range sw.lines {
		fmt.Fprintf(w, "  %s\n", line)
	}
}

// finishScan prints the final summary after all phases complete.
func finishScan(w io.Writer, clusterScore, podCount int) {
	if w == nil || w == io.Discard {
		return
	}
	elapsed := time.Since(activeScanStart).Truncate(time.Second)
	fmt.Fprintf(w, "%s", ansiShowCur) // restore cursor
	fmt.Fprintf(w, "\n%s  ◈ Scan complete%s — %s%d pods%s scored in %s%s%s, cluster score: %s%d/100%s\n\n",
		ansiBold, ansiReset,
		ansiCyan, podCount, ansiReset,
		ansiGreen, elapsed, ansiReset,
		ansiYellow, clusterScore, ansiReset)
}

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

// RecomputeAttackPaths rebuilds the attack graph and chain analysis from
// an already-loaded ScanResult. Used by --load mode where RunScan is skipped.
// Also recomputes runtime insights from the CVE inUse flags in the scan data.
func RecomputeAttackPaths(result *types.ScanResult) *types.AttackPathSummary {
	graph := attackpath.Build(result.Scores, result.RBACFindings)
	summary := attackpath.Analyze(graph)

	// Compute runtime insights from the loaded scan's inUse flags
	totalCVEs := 0
	inUseCVEs := 0
	podInUseMap := make(map[string]int)
	for _, s := range result.Scores {
		cves := s.Vulns.AllCVEs
		if len(cves) == 0 {
			cves = s.Vulns.TopCVEs
		}

		inUseCount := 0
		for _, c := range cves {
			if c.InUse {
				inUseCount++
			}
		}

		// Use actual CVE list length when AllCVEs present; extrapolate from
		// TopCVEs sample otherwise
		if len(s.Vulns.AllCVEs) > 0 {
			totalCVEs += len(cves)
		} else if len(cves) > 0 && s.Vulns.TotalCount > len(cves) {
			ratio := float64(inUseCount) / float64(len(cves))
			inUseCount = int(ratio * float64(s.Vulns.TotalCount))
			totalCVEs += s.Vulns.TotalCount
		} else {
			totalCVEs += len(cves)
		}
		inUseCVEs += inUseCount
		podInUseMap[s.PodName] = inUseCount
	}
	noiseReduction := 0.0
	if totalCVEs > 0 {
		noiseReduction = float64(totalCVEs-inUseCVEs) / float64(totalCVEs) * 100
	}
	insights := &types.RuntimeInsights{
		TotalCVEs:      totalCVEs,
		InUseCVEs:      inUseCVEs,
		NoiseReduction: noiseReduction,
		PodInUseMap:    podInUseMap,
	}

	insightsMu.Lock()
	latestAttackPath = summary
	latestInsights = insights
	insightsMu.Unlock()

	// Recompute agent security with delegation chains
	if len(result.RBACFindings) > 0 {
		result.AgentSecurity = agentsec.AnalyzeWithRBAC(result.Scores, result.RBACFindings)
	} else {
		result.AgentSecurity = agentsec.Analyze(result.Scores)
	}

	// Attach to the result so JSON export includes them
	result.RuntimeInsights = insights
	result.AttackPaths = summary

	return summary
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
	var allRBACFindings []types.RBACFinding
	var allRuntimeProfiles []types.RuntimeProfile
	totalPods := 0
	totalNetPol := 0
	totalCVEs := 0
	inUseCVEs := 0
	clusterName := ""
	hubbleAvailable := false
	flowSource := ""

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

		// Merge RBAC findings across namespaces
		allRBACFindings = append(allRBACFindings, result.RBACFindings...)

		// Merge runtime insights across namespaces
		if result.RuntimeInsights != nil {
			totalCVEs += result.RuntimeInsights.TotalCVEs
			inUseCVEs += result.RuntimeInsights.InUseCVEs
			allRuntimeProfiles = append(allRuntimeProfiles, result.RuntimeInsights.Profiles...)
		}

		if result.HubbleAvailable {
			hubbleAvailable = true
			flowSource = result.FlowSource
		}

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

	// Re-compute compliance across all namespaces with merged RBAC data
	allCompliance = compliance.MapAll(allScores, totalNetPol, allRBACFindings)

	// Re-run agent security analysis across ALL namespaces so cross-namespace
	// dependencies are captured (e.g. agentmgr in cisco-ndfc → mcpserver in mcp).
	// Use AnalyzeWithRBAC when RBAC data is available for delegation chain analysis.
	var crossNSAgentSummary *types.AgentSecuritySummary
	if len(allRBACFindings) > 0 {
		crossNSAgentSummary = agentsec.AnalyzeWithRBAC(allScores, allRBACFindings)
	} else {
		crossNSAgentSummary = agentsec.Analyze(allScores)
	}

	// Merge runtime insights
	var mergedInsights *types.RuntimeInsights
	if totalCVEs > 0 || len(allRuntimeProfiles) > 0 {
		noiseReduction := 0.0
		if totalCVEs > 0 {
			noiseReduction = float64(totalCVEs-inUseCVEs) / float64(totalCVEs) * 100
		}
		podInUseMap := make(map[string]int)
		for _, s := range allScores {
			cves := s.Vulns.AllCVEs
			if len(cves) == 0 {
				cves = s.Vulns.TopCVEs
			}
			count := 0
			for _, c := range cves {
				if c.InUse {
					count++
				}
			}
			podInUseMap[s.PodName] = count
		}
		mergedInsights = &types.RuntimeInsights{
			TotalCVEs:      totalCVEs,
			InUseCVEs:      inUseCVEs,
			NoiseReduction: noiseReduction,
			Profiles:       allRuntimeProfiles,
			PodInUseMap:    podInUseMap,
		}
	}

	// Re-compute attack paths across all namespaces with merged RBAC
	graph := attackpath.Build(allScores, allRBACFindings)
	mergedAttackPaths := attackpath.Analyze(graph)

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
		RBACFindings:    allRBACFindings,
		HubbleAvailable: hubbleAvailable,
		FlowSource:      flowSource,
		RuntimeInsights: mergedInsights,
		AttackPaths:     mergedAttackPaths,
		AgentSecurity:   crossNSAgentSummary,
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

	// Reset scan progress for each namespace
	resetScanProgress()

	client, err := k8s.NewClient(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to cluster: %w", err)
	}

	clusterName := client.ClusterName()
	fmt.Fprintf(progress, "\n%s  ◈ PLEXAR%s — %s%s%s · %s%s%s\n\n",
		ansiBold, ansiReset,
		ansiCyan, clusterName, ansiReset,
		ansiDim, namespace, ansiReset)

	// Use configured vuln source, default to trivy
	vulnSource := ActiveVulnSource
	if vulnSource == nil {
		vulnSource, _ = scanner.NewSource(scanner.SourceTrivy)
	}

	// Vuln scanning gets a generous timeout — CRI-O clusters need extra time
	// because each image requires skopeo export (can be 1-2min per large image)
	// Large clusters (40+ unique images on CRI-O) can take 1-2 hours even with
	// parallel scanning. 3-hour ceiling prevents timeout on enterprise deployments.
	vulnCtx, vulnCancel := context.WithTimeout(context.Background(), 3*time.Hour)
	defer vulnCancel()

	sp := startSpinner(progress, fmt.Sprintf("Scanning vulnerabilities (source: %s)", vulnSource.Name()))

	// Route scanner's per-image progress into the spinner's detail line
	// so it appears inside the animated TUI instead of being overwritten.
	var sw *spinnerWriter
	if ts, ok := vulnSource.(*scanner.TrivyScanner); ok {
		sw = &spinnerWriter{sp: sp}
		ts.Progress = sw
	}

	vulns, err := vulnSource.ScanNamespace(vulnCtx, client, namespace)
	if err != nil {
		sp.stop(fmt.Sprintf("🔍 Scanning vulnerabilities ✗ %v", err))
		if sw != nil {
			sw.Flush(progress)
		}
		return nil, fmt.Errorf("CVE scan failed: %w", err)
	}
	sp.stop(fmt.Sprintf("🔍 Found %d pods with vulnerability data", len(vulns)))

	// Print per-image scan details so they persist in logs
	if sw != nil {
		sw.Flush(progress)
	}

	// Network + permissions analysis uses a separate timeout
	analysisCtx, analysisCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer analysisCancel()

	sp = startSpinner(progress, "Mapping network blast radius")
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
		flows, flowErr := hubbleClient.CollectFlows(analysisCtx, namespace, 1*time.Hour)
		if flowErr != nil {
			log.Printf("[hubble] flow collection failed, falling back to inferred: %v", flowErr)
		} else {
			observedFlows = flows
			flowSource = "hubble"
		}
	}

	var blasts []types.BlastRadius
	var netPolCount int
	if flowSource == "hubble" && len(observedFlows) > 0 {
		blasts, netPolCount, err = netAnalyzer.AnalyzeNamespaceWithFlows(analysisCtx, namespace, observedFlows)
	} else {
		blasts, netPolCount, err = netAnalyzer.AnalyzeNamespace(analysisCtx, namespace)
	}
	if err != nil {
		sp.stop(fmt.Sprintf("🌐 Network analysis partial: %v", err))
	} else {
		sp.stop(fmt.Sprintf("🌐 Found %d pods, %d NetworkPolicies (source: %s)", len(blasts), netPolCount, flowSource))
	}

	sp = startSpinner(progress, "Checking permissions and RBAC")
	permAnalyzer := permissions.New(client)
	perms, err := permAnalyzer.AnalyzeNamespace(analysisCtx, namespace)
	if err != nil {
		sp.stop(fmt.Sprintf("🔓 Permission analysis skipped: %v", err))
		sp = startSpinner(progress, "Auditing RBAC permissions")
	}

	rbacAuditor := rbac.New(client)
	rbacResult, err := rbacAuditor.AuditNamespace(analysisCtx, namespace)
	var rbacFindings []types.RBACFinding
	if err != nil {
		sp.stop(fmt.Sprintf("🔓 RBAC audit skipped: %v", err))
	} else {
		rbacFindings = rbacResult.Findings
		sp.stop(fmt.Sprintf("🔓 %d pods audited, %d critical RBAC, %d high RBAC",
			rbacResult.TotalPods, rbacResult.CriticalCount, rbacResult.HighCount))
	}

	sp = startSpinner(progress, "Computing Plexar scores")

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
	sp.stop(fmt.Sprintf("🛡  Scored %d pods", len(scores)))
	sp = startSpinner(progress, "Classifying workloads")
	scores = classifier.ClassifyAll(scores)

	// Runtime profiling — tag CVEs that are actually "in use" at runtime
	classified := 0
	for _, s := range scores {
		if s.RiskMultiplier != 1.0 {
			classified++
		}
	}
	sp.stop(fmt.Sprintf("🧠 Classified %d pods (%d with risk multipliers)", len(scores), classified))

	sp = startSpinner(progress, "Profiling runtime packages (In Use detection via kubectl exec)")
	profiler := rt.NewProfiler(client)
	profiles, profErr := profiler.ProfileNamespace(analysisCtx, namespace)
	if profErr != nil {
		sp.stop(fmt.Sprintf("🔬 Runtime profiling skipped: %v", profErr))
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
		sp.stop(fmt.Sprintf("🔬 %d total CVEs, %d in-use (%.0f%% noise reduction)",
			insights.TotalCVEs, insights.InUseCVEs, insights.NoiseReduction))

		insightsMu.Lock()
		latestInsights = insights
		insightsMu.Unlock()
	}

	// Attack path analysis (includes exploit chain traversal)
	sp = startSpinner(progress, "Computing attack paths + exploit chains")
	graph := attackpath.Build(scores, rbacFindings)
	apSummary := attackpath.Analyze(graph)
	apResult := fmt.Sprintf("🗺  %d attack paths (%d critical, shortest: %d hops)",
		apSummary.TotalPaths, apSummary.CriticalPaths, apSummary.ShortestHops)
	if apSummary.ChainSummary != nil && apSummary.ChainSummary.TotalChains > 0 {
		apResult += fmt.Sprintf("\n   ⛓  %d exploit chains (%d critical, %d agent-involved)",
			apSummary.ChainSummary.TotalChains, apSummary.ChainSummary.CriticalChains, apSummary.ChainSummary.AgentChains)
		if apSummary.ChainSummary.TopBreakFix.CVEID != "" {
			apResult += fmt.Sprintf("\n   🔧 Break chain: patch %s on %s (eliminates %d chains)",
				apSummary.ChainSummary.TopBreakFix.CVEID, apSummary.ChainSummary.TopBreakFix.PodName, apSummary.ChainSummary.TopBreakFix.ChainsEliminated)
		}
	}
	sp.stop(apResult)

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

	// Agent security analysis — identify MCP servers, agent pods, dependency chains
	var agentSummary *types.AgentSecuritySummary
	if len(rbacFindings) > 0 {
		agentSummary = agentsec.AnalyzeWithRBAC(scores, rbacFindings)
	} else {
		agentSummary = agentsec.Analyze(scores)
	}

	// Attach runtime insights to the result
	insightsMu.RLock()
	currentInsights := latestInsights
	currentAttackPaths := latestAttackPath
	insightsMu.RUnlock()

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
		RuntimeInsights: currentInsights,
		AttackPaths:     currentAttackPaths,
		AgentSecurity:   agentSummary,
	}

	finishScan(progress, clusterScore, len(scores))
	resetScanProgress()

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
