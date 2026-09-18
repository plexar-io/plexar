package cmd

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/plexar-io/plexar/internal/types"
	"github.com/plexar-io/plexar/pkg/alerting"
	"github.com/plexar-io/plexar/pkg/api"
	"github.com/plexar-io/plexar/pkg/auth"
	"github.com/plexar-io/plexar/pkg/evidence"
	"github.com/plexar-io/plexar/pkg/history"
	"github.com/plexar-io/plexar/pkg/ingest"
	"github.com/plexar-io/plexar/pkg/integrations"
	"github.com/plexar-io/plexar/pkg/metrics"
	"github.com/plexar-io/plexar/pkg/netpol"
	"github.com/plexar-io/plexar/pkg/reporter"
	"github.com/plexar-io/plexar/pkg/scanner"
	"github.com/plexar-io/plexar/pkg/scorer"
	"github.com/plexar-io/plexar/web"
	"github.com/spf13/cobra"
)

var (
	servePort       int
	serveBind       string
	scanInterval    time.Duration
	metricsPort     int
	enableUI        bool
	alertSlackURL   string
	oidcIssuer      string
	vantaToken      string
	drataKey        string
	evidenceSinks   []string
	hubbleRelayAddr string
	serveVulnSource string
	loadFile        string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run Plexar as a continuous operator with web dashboard",
	Long: `◈ Starts Plexar in operator mode: continuously watches the target namespace,
recalculates blast radius scores on changes, exposes Prometheus metrics,
serves the REST API, and the web dashboard.`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().IntVarP(&servePort, "port", "p", 8080, "API/UI server port")
	serveCmd.Flags().StringVar(&serveBind, "bind", "0.0.0.0", "Bind address")
	serveCmd.Flags().DurationVar(&scanInterval, "scan-interval", 24*time.Hour, "How often to recalculate blast radius")
	serveCmd.Flags().IntVar(&metricsPort, "metrics-port", 9090, "Prometheus metrics port")
	serveCmd.Flags().BoolVar(&enableUI, "ui", true, "Enable web dashboard")
	serveCmd.Flags().StringVar(&alertSlackURL, "alert-slack-url", "", "Slack webhook URL for alerts")
	serveCmd.Flags().StringVar(&oidcIssuer, "oidc-issuer", "", "OIDC issuer URL for authentication")
	serveCmd.Flags().StringVar(&vantaToken, "vanta-token", "", "Vanta API token for automated evidence push")
	serveCmd.Flags().StringVar(&drataKey, "drata-key", "", "Drata API key for automated evidence push")
	serveCmd.Flags().StringSliceVar(&evidenceSinks, "evidence-sink", nil, "Evidence sink DSN(s): s3://key:secret@host/bucket or webhook://url")
	serveCmd.Flags().StringVar(&hubbleRelayAddr, "hubble-relay", "", "Hubble Relay address (host:port); auto-detect if empty")
	serveCmd.Flags().StringVar(&serveVulnSource, "vuln-source", "trivy", "Vulnerability source: trivy, trivy-operator, none")
	serveCmd.Flags().StringVar(&loadFile, "load", "", "Load scan results from a JSON file (skip live scanning)")
}

// Scan cache — background loop writes, API handlers read
var (
	cachedResult   *types.ScanResult
	cachedResultMu sync.RWMutex
	scanning       bool
	scanningMu     sync.RWMutex
	lastScanTime   time.Time
	lastScanTimeMu sync.RWMutex
)

func getCachedResult() *types.ScanResult {
	cachedResultMu.RLock()
	defer cachedResultMu.RUnlock()
	return cachedResult
}

func setCachedResult(r *types.ScanResult) {
	cachedResultMu.Lock()
	defer cachedResultMu.Unlock()
	cachedResult = r
}

func setScanning(v bool) {
	scanningMu.Lock()
	defer scanningMu.Unlock()
	scanning = v
}

func isScanning() bool {
	scanningMu.RLock()
	defer scanningMu.RUnlock()
	return scanning
}

func setLastScanTime(t time.Time) {
	lastScanTimeMu.Lock()
	defer lastScanTimeMu.Unlock()
	lastScanTime = t
}

func getLastScanTime() time.Time {
	lastScanTimeMu.RLock()
	defer lastScanTimeMu.RUnlock()
	return lastScanTime
}

func runServe(cmd *cobra.Command, args []string) error {
	store := history.NewStore(history.DefaultPath())
	vault := evidence.NewVault(evidence.DefaultDir())
	alertEngine := alerting.NewEngine()
	metricsCollector := metrics.NewCollector()
	intMgr := integrations.NewManager()

	// Configure alert destinations
	if alertSlackURL != "" {
		alertEngine.AddDestination(alerting.NewSlackDestination(alertSlackURL))
	}

	// Configure compliance platform integrations
	if vantaToken != "" {
		intMgr.AddVanta(vantaToken)
		fmt.Fprintf(os.Stderr, "🔗 Vanta integration enabled\n")
	}
	if drataKey != "" {
		intMgr.AddDrata(drataKey)
		fmt.Fprintf(os.Stderr, "🔗 Drata integration enabled\n")
	}

	// Configure evidence sinks (S3, webhook)
	sinkMgr := evidence.NewSinkManager()
	for _, dsn := range evidenceSinks {
		cfg, err := evidence.ParseSinkDSN(dsn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠  Invalid evidence sink DSN %q: %v\n", dsn, err)
			continue
		}
		sink, err := evidence.NewSinkFromConfig(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠  Failed to create evidence sink %q: %v\n", dsn, err)
			continue
		}
		sinkMgr.Add(sink)
		fmt.Fprintf(os.Stderr, "📦 Evidence sink enabled: %s\n", sink.Name())
	}

	// Auth middleware
	var authMiddleware func(http.Handler) http.Handler
	var err error
	if oidcIssuer != "" {
		authMiddleware, err = auth.NewOIDCMiddleware(oidcIssuer)
		if err != nil {
			return fmt.Errorf("OIDC setup failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "🔐 OIDC auth enabled (%s)\n", oidcIssuer)
	} else {
		authMiddleware = auth.NoopMiddleware()
	}

	// Configure vulnerability source
	if serveVulnSource != "" {
		source, err := scanner.NewSource(serveVulnSource)
		if err != nil {
			return fmt.Errorf("invalid vuln-source %q: %w", serveVulnSource, err)
		}
		api.ActiveVulnSource = source
		fmt.Fprintf(os.Stderr, "🔍 Vulnerability source: %s\n", source.Name())
	}

	// Wire Hubble relay address into scan pipeline
	if hubbleRelayAddr != "" {
		api.HubbleRelayAddr = hubbleRelayAddr
		fmt.Fprintf(os.Stderr, "\U0001f310 Hubble Relay: %s\n", hubbleRelayAddr)
	}

	mux := http.NewServeMux()

	// API endpoints — serve cached scan results (never trigger a live scan)
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		result := getCachedResult()
		if result == nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "pending", "message": "Initial scan in progress"})
			return
		}
		// Return a lightweight copy: replace blast.reachableTargets with just the count.
		// The full list is 300KB+ and the dashboard only uses the count.
		type lightBlast struct {
			ReachableCount     int      `json:"reachableCount"`
			ConfiguredTargets  []string `json:"configuredTargets,omitempty"`
			InternetAccess     bool     `json:"internetAccess"`
			HasNetworkPolicy   bool     `json:"hasNetworkPolicy"`
			UnrestrictedEgress bool     `json:"unrestrictedEgress"`
			DataStoreAccess    []string `json:"dataStoreAccess,omitempty"`
		}
		type lightScore struct {
			PodName          string                 `json:"podName"`
			Namespace        string                 `json:"namespace"`
			ImageName        string                 `json:"imageName"`
			Total            int                    `json:"total"`
			Tier             string                 `json:"tier"`
			CVEScore         int                    `json:"cveScore"`
			BlastScore       int                    `json:"blastScore"`
			PermScore        int                    `json:"permScore"`
			PolicyGapScore   int                    `json:"policyGapScore"`
			SensitivityScore int                    `json:"sensitivityScore"`
			WorkloadClass    string                 `json:"workloadClass,omitempty"`
			RiskMultiplier   float64                `json:"riskMultiplier,omitempty"`
			BaseScore        int                    `json:"baseScore,omitempty"`
			Vulns            types.VulnSummary      `json:"vulns"`
			Blast            lightBlast             `json:"blast"`
			Permissions      types.PodPermissions   `json:"permissions"`
			Recommendations  []types.Recommendation `json:"recommendations,omitempty"`
			Roast            string                 `json:"roast,omitempty"`
			Labels           map[string]string      `json:"labels,omitempty"`
		}
		light := make([]lightScore, len(result.Scores))
		for i, s := range result.Scores {
			// Omit allCVEs from /api/scan — the dashboard uses /api/cves for the
			// CVE Explorer table. Keeping 43K entries here adds ~12MB of redundant data.
			vulns := s.Vulns
			vulns.AllCVEs = nil
			light[i] = lightScore{
				PodName: s.PodName, Namespace: s.Namespace, ImageName: s.ImageName,
				Total: s.Total, Tier: s.Tier,
				CVEScore: s.CVEScore, BlastScore: s.BlastScore, PermScore: s.PermScore,
				PolicyGapScore: s.PolicyGapScore, SensitivityScore: s.SensitivityScore,
				WorkloadClass: s.WorkloadClass, RiskMultiplier: s.RiskMultiplier, BaseScore: s.BaseScore,
				Vulns: vulns, Permissions: s.Permissions,
				Recommendations: s.Recommendations, Roast: s.Roast, Labels: s.Labels,
				Blast: lightBlast{
					ReachableCount:     len(s.Blast.ReachableTargets),
					ConfiguredTargets:  s.Blast.ConfiguredTargets,
					InternetAccess:     s.Blast.InternetAccess,
					HasNetworkPolicy:   s.Blast.HasNetworkPolicy,
					UnrestrictedEgress: s.Blast.UnrestrictedEgress,
					DataStoreAccess:    s.Blast.DataStoreAccess,
				},
			}
		}
		out := map[string]interface{}{
			"clusterName":     result.ClusterName,
			"namespace":       result.Namespace,
			"scanTime":        result.ScanTime,
			"totalPods":       result.TotalPods,
			"clusterScore":    result.ClusterScore,
			"networkPolicies": result.NetworkPolicies,
			"scores":          light,
			"warnings":        result.Warnings,
			"compliance":      result.Compliance,
			"runtimeInsights": result.RuntimeInsights,
			"attackPaths":     result.AttackPaths,
		}
		json.NewEncoder(w).Encode(out)
	})

	mux.HandleFunc("/api/scan/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"scanning":     isScanning(),
			"lastScanTime": getLastScanTime(),
			"hasData":      getCachedResult() != nil,
		})
	})

	mux.HandleFunc("/api/scan/trigger", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if isScanning() {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "already_scanning"})
			return
		}
		targetNs := r.URL.Query().Get("namespace")
		if targetNs == "" {
			targetNs = namespace
		}

		// Safety check: refuse to replace a larger scan with a smaller single-namespace scan.
		// This prevents dashboard filter changes from wiping out multi-namespace data.
		existing := getCachedResult()
		if existing != nil && targetNs != existing.Namespace && existing.TotalPods > 0 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "rejected",
				"reason":  "refusing to overwrite existing scan — use the CLI to scan a different namespace",
				"current": existing.Namespace,
			})
			return
		}

		go func() {
			setScanning(true)
			defer setScanning(false)
			result, err := api.RunScan(kubeconfig, targetNs, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠  Triggered scan for %s failed: %v\n", targetNs, err)
				return
			}
			setCachedResult(result)
			setLastScanTime(time.Now())
			_ = store.Save(result)
			vault.Record(result)
			metricsCollector.Update(result)
			alertEngine.Evaluate(result)
			fmt.Fprintf(os.Stderr, "🔄 Triggered scan (%s) — cluster score: %d, %d pods\n", targetNs, result.ClusterScore, result.TotalPods)
		}()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "triggered", "namespace": targetNs})
	})

	mux.HandleFunc("/api/history", func(w http.ResponseWriter, r *http.Request) {
		snapshots, _ := store.Load()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(snapshots)
	})

	mux.HandleFunc("/api/compliance", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		result := getCachedResult()
		if result == nil {
			json.NewEncoder(w).Encode([]interface{}{})
			return
		}
		json.NewEncoder(w).Encode(result.Compliance)
	})

	mux.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(alertEngine.Rules())
	})

	mux.HandleFunc("/api/generate/netpol", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		result := getCachedResult()
		if result == nil {
			json.NewEncoder(w).Encode([]interface{}{})
			return
		}
		policies := netpol.Generate(result.Scores, namespace)
		json.NewEncoder(w).Encode(policies)
	})

	mux.HandleFunc("/api/namespaces", func(w http.ResponseWriter, r *http.Request) {
		names, err := api.ListNamespaces(kubeconfig)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(names)
	})

	mux.HandleFunc("/api/alerts/events", func(w http.ResponseWriter, r *http.Request) {
		events := alertEngine.RecentEvents(50)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	})

	mux.HandleFunc("/api/export/csv", func(w http.ResponseWriter, r *http.Request) {
		result := getCachedResult()
		if result == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "no scan data yet"})
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=plexar-scan.csv")
		reporter.ExportCSV(w, result)
	})

	// CVE Explorer — returns ALL CVEs across all pods with optional filtering
	mux.HandleFunc("/api/cves", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		result := getCachedResult()
		if result == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"cves": []interface{}{}, "total": 0})
			return
		}

		// Query params for filtering
		nsFilter := r.URL.Query().Get("namespace")
		podFilter := r.URL.Query().Get("pod")
		sevFilter := strings.ToUpper(r.URL.Query().Get("severity"))
		pkgFilter := strings.ToLower(r.URL.Query().Get("package"))
		inUseFilter := r.URL.Query().Get("inuse") // "true" or "false"

		type CVERow struct {
			PodName     string  `json:"podName"`
			Namespace   string  `json:"namespace"`
			ImageName   string  `json:"imageName"`
			ID          string  `json:"id"`
			Severity    string  `json:"severity"`
			CVSS        float64 `json:"cvss"`
			Package     string  `json:"package"`
			Installed   string  `json:"installedVersion"`
			Fixed       string  `json:"fixedVersion"`
			InUse       bool    `json:"inUse"`
			Confidence  float64 `json:"confidence"`
			Published   string  `json:"publishedDate"`
			Description string  `json:"description,omitempty"`
		}

		var rows []CVERow
		for _, score := range result.Scores {
			if nsFilter != "" && score.Namespace != nsFilter {
				continue
			}
			if podFilter != "" && score.PodName != podFilter {
				continue
			}
			// Use AllCVEs if available, fall back to TopCVEs
			cves := score.Vulns.AllCVEs
			if len(cves) == 0 {
				cves = score.Vulns.TopCVEs
			}
			for _, c := range cves {
				if sevFilter != "" && c.Severity != sevFilter {
					continue
				}
				if pkgFilter != "" && !strings.Contains(strings.ToLower(c.Package), pkgFilter) {
					continue
				}
				if inUseFilter == "true" && !c.InUse {
					continue
				}
				if inUseFilter == "false" && c.InUse {
					continue
				}
				// Truncate description to save bandwidth (full text via CVE Lookup)
				desc := c.Description
				if len(desc) > 200 {
					desc = desc[:200] + "..."
				}
				rows = append(rows, CVERow{
					PodName:     score.PodName,
					Namespace:   score.Namespace,
					ImageName:   score.ImageName,
					ID:          c.ID,
					Severity:    c.Severity,
					CVSS:        c.CVSS,
					Package:     c.Package,
					Installed:   c.InstalledVersion,
					Fixed:       c.FixedVersion,
					InUse:       c.InUse,
					Confidence:  c.Confidence,
					Published:   c.PublishedDate,
					Description: desc,
				})
			}
		}

		// Sort by CVSS desc
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Severity != rows[j].Severity {
				sevOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
				return sevOrder[rows[i].Severity] < sevOrder[rows[j].Severity]
			}
			return rows[i].CVSS > rows[j].CVSS
		})

		// Server-side pagination: ?limit=N&offset=N (default: first 500)
		total := len(rows)
		limit := 500
		offset := 0
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				limit = n
			}
		}
		if o := r.URL.Query().Get("offset"); o != "" {
			if n, err := strconv.Atoi(o); err == nil && n > 0 {
				offset = n
			}
		}
		if offset > len(rows) {
			offset = len(rows)
		}
		end := offset + limit
		if end > len(rows) {
			end = len(rows)
		}
		rows = rows[offset:end]

		json.NewEncoder(w).Encode(map[string]interface{}{
			"cves":   rows,
			"total":  total,
			"offset": offset,
			"limit":  limit,
		})
	})

	// ── CVE Lookup — deep-dive on a single CVE across the cluster ──
	// Tracks user overrides (accepted / deferred / false-positive) in memory.
	var (
		cveOverrides   = map[string]CVEOverride{}
		cveOverridesMu sync.RWMutex
	)

	mux.HandleFunc("/api/cve/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Parse path: /api/cve/CVE-2024-38816 or /api/cve/CVE-2024-38816/override
		path := strings.TrimPrefix(r.URL.Path, "/api/cve/")
		parts := strings.SplitN(path, "/", 2)
		cveID := strings.ToUpper(strings.TrimSpace(parts[0]))
		isOverride := len(parts) > 1 && parts[1] == "override"

		if cveID == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "CVE ID required"})
			return
		}

		// Handle override POST
		if isOverride {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			var body struct {
				Status string `json:"status"` // accepted, deferred, false-positive
				Note   string `json:"note"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON"})
				return
			}
			validStatuses := map[string]bool{"accepted": true, "deferred": true, "false-positive": true, "": true}
			if !validStatuses[body.Status] {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "status must be: accepted, deferred, false-positive, or empty to clear"})
				return
			}
			cveOverridesMu.Lock()
			if body.Status == "" {
				delete(cveOverrides, cveID)
			} else {
				cveOverrides[cveID] = CVEOverride{Status: body.Status, Note: body.Note, SetAt: time.Now()}
			}
			cveOverridesMu.Unlock()
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "cve": cveID, "override": body.Status})
			return
		}

		// GET — lookup
		result := getCachedResult()
		if result == nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "no scan data"})
			return
		}

		type AffectedPod struct {
			PodName          string  `json:"podName"`
			Namespace        string  `json:"namespace"`
			ImageName        string  `json:"imageName"`
			Package          string  `json:"package"`
			InstalledVersion string  `json:"installedVersion"`
			FixedVersion     string  `json:"fixedVersion"`
			InUse            bool    `json:"inUse"`
			Confidence       float64 `json:"confidence"`
			BlastRadius      int     `json:"blastRadius"`
			InternetExposed  bool    `json:"internetExposed"`
			HasNetworkPolicy bool    `json:"hasNetworkPolicy"`
			PodScore         int     `json:"podScore"`
			PodTier          string  `json:"podTier"`
		}

		var affected []AffectedPod
		var matchedCVE *types.CVEInfo
		for _, score := range result.Scores {
			cves := score.Vulns.AllCVEs
			if len(cves) == 0 {
				cves = score.Vulns.TopCVEs
			}
			for _, c := range cves {
				if strings.EqualFold(c.ID, cveID) {
					if matchedCVE == nil {
						cp := c
						matchedCVE = &cp
					}
					affected = append(affected, AffectedPod{
						PodName:          score.PodName,
						Namespace:        score.Namespace,
						ImageName:        score.ImageName,
						Package:          c.Package,
						InstalledVersion: c.InstalledVersion,
						FixedVersion:     c.FixedVersion,
						InUse:            c.InUse,
						Confidence:       c.Confidence,
						BlastRadius:      len(score.Blast.ReachableTargets),
						InternetExposed:  score.Blast.InternetAccess,
						HasNetworkPolicy: score.Blast.HasNetworkPolicy,
						PodScore:         score.Total,
						PodTier:          score.Tier,
					})
				}
			}
		}

		if matchedCVE == nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      cveID,
				"found":   false,
				"message": "CVE not found in current scan data",
			})
			return
		}

		// Compute summary
		inUsePods := 0
		maxBlast := 0
		internetExposed := false
		for _, a := range affected {
			if a.InUse {
				inUsePods++
			}
			if a.BlastRadius > maxBlast {
				maxBlast = a.BlastRadius
			}
			if a.InternetExposed {
				internetExposed = true
			}
		}

		// Auto-score recommendation
		rec, reason := scoreCVERecommendation(matchedCVE, inUsePods, maxBlast, internetExposed, len(affected))

		// Check for user override
		cveOverridesMu.RLock()
		override, hasOverride := cveOverrides[cveID]
		cveOverridesMu.RUnlock()

		resp := map[string]interface{}{
			"id":            matchedCVE.ID,
			"found":         true,
			"severity":      matchedCVE.Severity,
			"cvss":          matchedCVE.CVSS,
			"description":   matchedCVE.Description,
			"publishedDate": matchedCVE.PublishedDate,
			"exploitType":   matchedCVE.ExploitType,
			"references":    matchedCVE.References,
			"affectedPods":  affected,
			"summary": map[string]interface{}{
				"totalAffectedPods": len(affected),
				"inUsePods":         inUsePods,
				"maxBlastRadius":    maxBlast,
				"internetExposed":   internetExposed,
			},
			"recommendation":       rec,
			"recommendationReason": reason,
		}
		if hasOverride {
			resp["override"] = override
		}

		// Try NVD enrichment if description is missing
		if matchedCVE.Description == "" {
			go enrichFromNVD(cveID) // fire-and-forget for next lookup
		}

		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/settings/weights", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scorer.ActiveWeights())
	})

	mux.HandleFunc("/api/meta", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version":      Version,
			"namespace":    namespace,
			"scanInterval": scanInterval.String(),
		})
	})

	mux.HandleFunc("/api/history/delta", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		delta := store.Delta()
		if delta == nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "insufficient data", "message": "Need at least 2 snapshots to compute delta"})
			return
		}
		json.NewEncoder(w).Encode(delta)
	})

	mux.HandleFunc("/api/history/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		latest := store.Latest()
		if latest == nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "no data"})
			return
		}
		json.NewEncoder(w).Encode(latest)
	})

	mux.HandleFunc("/api/rbac", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		result := getCachedResult()
		if result == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{"namespace": namespace, "findings": []interface{}{}, "totalPods": 0})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"namespace": result.Namespace,
			"findings":  result.RBACFindings,
			"totalPods": result.TotalPods,
		})
	})

	// Evidence Vault API
	mux.HandleFunc("/api/evidence", func(w http.ResponseWriter, r *http.Request) {
		var from, to time.Time
		if d := r.URL.Query().Get("days"); d != "" {
			if days, err := time.ParseDuration(d + "h"); err == nil {
				// User passed just a number, treat as days
				from = time.Now().Add(-days * 24)
			}
		}
		if v := r.URL.Query().Get("from"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				from = t
			}
		}
		if v := r.URL.Query().Get("to"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				to = t
			}
		}
		records := vault.List(from, to)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(records)
	})

	mux.HandleFunc("/api/evidence/summary", func(w http.ResponseWriter, r *http.Request) {
		days := 90
		if d := r.URL.Query().Get("days"); d != "" {
			fmt.Sscanf(d, "%d", &days)
		}
		from := time.Now().AddDate(0, 0, -days)
		stats := vault.ControlSummary(from, time.Time{})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"period":       fmt.Sprintf("%d days", days),
			"totalRecords": vault.Count(),
			"chainIntact":  vault.Verify() == -1,
			"controls":     stats,
		})
	})

	mux.HandleFunc("/api/evidence/drift", func(w http.ResponseWriter, r *http.Request) {
		days := 90
		if d := r.URL.Query().Get("days"); d != "" {
			fmt.Sscanf(d, "%d", &days)
		}
		from := time.Now().AddDate(0, 0, -days)
		severity := r.URL.Query().Get("severity")
		events := vault.DriftEvents(from, time.Time{}, severity)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"period":      fmt.Sprintf("%d days", days),
			"totalDrifts": len(events),
			"events":      events,
		})
	})

	mux.HandleFunc("/api/evidence/verify", func(w http.ResponseWriter, r *http.Request) {
		brokenAt := vault.Verify()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"intact":        brokenAt == -1,
			"totalRecords":  vault.Count(),
			"brokenAtIndex": brokenAt,
		})
	})

	mux.HandleFunc("/api/integrations", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"configured":   intMgr.HasProviders(),
			"vanta":        vantaToken != "",
			"drata":        drataKey != "",
			"recentPushes": intMgr.Log(20),
		})
	})

	mux.HandleFunc("/api/runtime", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		insights := api.LatestRuntimeInsights()
		if insights == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "pending",
				"message": "No runtime profile yet — waiting for first scan",
			})
			return
		}
		json.NewEncoder(w).Encode(insights)
	})

	mux.HandleFunc("/api/attackpath", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		paths := api.LatestAttackPaths()
		if paths == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "pending",
				"message": "No attack path analysis yet — waiting for first scan",
			})
			return
		}
		json.NewEncoder(w).Encode(paths)
	})

	// Exploit chains API
	mux.HandleFunc("/api/chains", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		paths := api.LatestAttackPaths()
		if paths == nil || paths.ChainSummary == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "pending",
				"message": "No exploit chain analysis yet — waiting for first scan",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"summary": paths.ChainSummary,
			"chains":  paths.ExploitChains,
		})
	})

	// Observed flows API (Hubble data)
	mux.HandleFunc("/api/flows", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		result := getCachedResult()
		if result == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "pending",
				"message": "No scan data yet",
			})
			return
		}

		var allFlows []types.ObservedFlow
		for _, score := range result.Scores {
			allFlows = append(allFlows, score.Blast.ObservedFlows...)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"hubbleAvailable": result.HubbleAvailable,
			"flowSource":      result.FlowSource,
			"totalFlows":      len(allFlows),
			"flows":           allFlows,
		})
	})

	// Sprint 9: Multi-source ingestion API
	mux.HandleFunc("/api/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "POST required"})
			return
		}

		source := r.URL.Query().Get("source")
		if source == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "source parameter required (kubescape, kyverno, trivy-sbom)"})
			return
		}

		result, err := ingest.Ingest(source, r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		// Merge findings into evidence
		externalEvidence := ingest.MergeFindings(result.Findings)
		fmt.Fprintf(os.Stderr, "📥 Ingested %s: %d findings (%d pass, %d fail), %d evidence entries\n",
			source, result.TotalFindings, result.PassCount, result.FailCount, len(externalEvidence))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":           "ok",
			"source":           result.Source,
			"totalFindings":    result.TotalFindings,
			"pass":             result.PassCount,
			"fail":             result.FailCount,
			"warn":             result.WarnCount,
			"evidenceEntries":  len(externalEvidence),
			"sbomComponents":   len(result.SBOMComponents),
			"complianceChecks": len(result.ComplianceChecks),
		})
	})

	// Sprint 9: Compliance framework filter
	mux.HandleFunc("/api/compliance/framework", func(w http.ResponseWriter, r *http.Request) {
		fw := r.URL.Query().Get("name")
		if fw == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "name parameter required (soc2, pci-dss, hipaa, cis, eu-cra)"})
			return
		}

		result := getCachedResult()
		if result == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "no scan data yet"})
			return
		}

		fwLower := strings.ToLower(fw)
		for _, c := range result.Compliance {
			if strings.ToLower(c.Framework) == fwLower ||
				strings.ReplaceAll(strings.ToLower(c.Framework), " ", "-") == fwLower {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(c)
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("framework %q not found", fw)})
	})

	// Sprint 9: Evidence sinks status
	mux.HandleFunc("/api/evidence/sinks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"configured": sinkMgr.HasSinks(),
			"recentLog":  sinkMgr.Log(20),
		})
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Web dashboard (embedded)
	if enableUI {
		dashboardFS, err := web.DashboardFS()
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠  Dashboard assets not found, serving API only\n")
		} else {
			mux.Handle("/", http.FileServer(http.FS(dashboardFS)))
			fmt.Fprintf(os.Stderr, "🖥  Dashboard enabled\n")
		}
	}

	// Fallback root for API-only mode
	if !enableUI {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"name":      "plexar",
				"version":   Version,
				"docs":      "https://plexar.io/docs",
				"endpoints": []string{"/api/scan", "/api/history", "/api/compliance", "/api/alerts", "/api/generate/netpol", "/healthz", "/metrics"},
			})
		})
	}

	handler := gzipMiddleware(authMiddleware(auth.NamespaceScopedMiddleware()(mux)))

	// Prometheus metrics server (separate port)
	go func() {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", metricsCollector.Handler())
		metricsAddr := fmt.Sprintf(":%d", metricsPort)
		fmt.Fprintf(os.Stderr, "📊 Prometheus metrics → http://0.0.0.0%s/metrics\n", metricsAddr)
		http.ListenAndServe(metricsAddr, metricsMux)
	}()

	// Background scan loop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Helper: run scan, update cache, persist
	doScan := func(label string) {
		setScanning(true)
		defer setScanning(false)

		result, err := api.RunScan(kubeconfig, namespace, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⚠  %s scan failed: %v\n", label, err)
			return
		}
		setCachedResult(result)
		setLastScanTime(time.Now())
		_ = store.Save(result)
		vault.Record(result)
		metricsCollector.Update(result)
		alertEngine.Evaluate(result)
		fmt.Fprintf(os.Stderr, "🔄 %s — cluster score: %d, %d pods | evidence: %d records\n", label, result.ClusterScore, result.TotalPods, vault.Count())
	}

	go func() {
		// Load from file or run initial scan
		if loadFile != "" {
			data, err := os.ReadFile(loadFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠  Failed to load %s: %v\n", loadFile, err)
			} else {
				var result types.ScanResult
				if err := json.Unmarshal(data, &result); err != nil {
					fmt.Fprintf(os.Stderr, "⚠  Failed to parse %s: %v\n", loadFile, err)
				} else {
					// Backfill empty descriptions in allCVEs from topCVEs (global lookup)
					descMap := map[string]string{}
					for si := range result.Scores {
						for _, c := range result.Scores[si].Vulns.TopCVEs {
							if c.Description != "" {
								descMap[c.ID] = c.Description
							}
						}
						for _, c := range result.Scores[si].Vulns.AllCVEs {
							if c.Description != "" {
								descMap[c.ID] = c.Description
							}
						}
					}
					for si := range result.Scores {
						for ci := range result.Scores[si].Vulns.AllCVEs {
							if result.Scores[si].Vulns.AllCVEs[ci].Description == "" {
								result.Scores[si].Vulns.AllCVEs[ci].Description = descMap[result.Scores[si].Vulns.AllCVEs[ci].ID]
							}
						}
					}

					setCachedResult(&result)
					setLastScanTime(result.ScanTime)
					_ = store.Save(&result)
					vault.Record(&result)
					metricsCollector.Update(&result)

					// Recompute attack paths from loaded data
					apSummary := api.RecomputeAttackPaths(&result)
					fmt.Fprintf(os.Stderr, "📂 Loaded scan from %s — cluster score: %d, %d pods\n", loadFile, result.ClusterScore, result.TotalPods)
					fmt.Fprintf(os.Stderr, "🗺  Attack paths: %d total (%d critical)\n", apSummary.TotalPaths, apSummary.CriticalPaths)
					if apSummary.ChainSummary != nil && apSummary.ChainSummary.TotalChains > 0 {
						fmt.Fprintf(os.Stderr, "⛓  Exploit chains: %d total (%d critical)\n", apSummary.ChainSummary.TotalChains, apSummary.ChainSummary.CriticalChains)
					}
				}
			}
		} else {
			doScan("Initial scan")
		}
		// Seed demo history from first result
		if r := getCachedResult(); r != nil {
			_ = store.SeedDemo(r)
		}

		if loadFile != "" {
			// Static mode — no background rescans
			<-ctx.Done()
			return
		}

		ticker := time.NewTicker(scanInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				doScan("Background scan")

				// Push evidence to compliance platforms
				if intMgr.HasProviders() {
					records := vault.List(time.Now().Add(-1*time.Minute), time.Time{})
					if len(records) > 0 {
						latest := records[len(records)-1]
						if errs := intMgr.PushEvidence(&latest); len(errs) > 0 {
							for _, e := range errs {
								fmt.Fprintf(os.Stderr, "⚠  Evidence push failed: %v\n", e)
							}
						} else {
							fmt.Fprintf(os.Stderr, "📤 Evidence pushed to compliance platforms\n")
						}
						if r := getCachedResult(); r != nil {
							if errs := intMgr.PushControls(latest.Controls, r.ClusterName); len(errs) > 0 {
								for _, e := range errs {
									fmt.Fprintf(os.Stderr, "⚠  Controls push failed: %v\n", e)
								}
							}
						}
					}
				}

				// Push evidence to configured sinks (S3, webhook)
				if sinkMgr.HasSinks() {
					records := vault.List(time.Now().Add(-1*time.Minute), time.Time{})
					if len(records) > 0 {
						latest := records[len(records)-1]
						if errs := sinkMgr.PushAll(&latest); len(errs) > 0 {
							for _, e := range errs {
								fmt.Fprintf(os.Stderr, "⚠  Sink push failed: %v\n", e)
							}
						} else {
							fmt.Fprintf(os.Stderr, "📦 Evidence pushed to %d sink(s)\n", len(sinkMgr.Log(0)))
						}
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Graceful shutdown
	addr := fmt.Sprintf("%s:%d", serveBind, servePort)
	server := &http.Server{Addr: addr, Handler: handler}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		fmt.Fprintf(os.Stderr, "\n🛑 Shutting down...\n")
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
	}()

	fmt.Fprintf(os.Stderr, "\n◈ Plexar operator → http://%s\n", addr)
	fmt.Fprintf(os.Stderr, "  Namespace: %s | Scan interval: %s\n", namespace, scanInterval)
	if enableUI {
		fmt.Fprintf(os.Stderr, "  Dashboard → http://localhost:%d\n", servePort)
	}
	fmt.Fprintf(os.Stderr, "  Metrics  → http://0.0.0.0:%d/metrics\n", metricsPort)
	if len(evidenceSinks) > 0 {
		fmt.Fprintf(os.Stderr, "  Sinks    → %d configured\n", len(evidenceSinks))
	}
	if vantaToken != "" || drataKey != "" {
		fmt.Fprintf(os.Stderr, "  GRC      → Vanta=%v Drata=%v\n", vantaToken != "", drataKey != "")
	}
	fmt.Fprintf(os.Stderr, "\nPress Ctrl+C to stop\n")

	return server.ListenAndServe()
}

// CVEOverride stores a user's triage decision for a specific CVE
type CVEOverride struct {
	Status string    `json:"status"` // accepted, deferred, false-positive
	Note   string    `json:"note"`
	SetAt  time.Time `json:"setAt"`
}

// scoreCVERecommendation produces an auto-scored recommendation
func scoreCVERecommendation(cve *types.CVEInfo, inUsePods, maxBlast int, internetExposed bool, totalAffected int) (string, string) {
	sevOrder := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
	sev := sevOrder[cve.Severity]

	// PATCH NOW: critical/high + in-use + high blast radius or internet exposed
	if sev >= 3 && inUsePods > 0 && (maxBlast > 50 || internetExposed) {
		parts := []string{cve.Severity + " severity", fmt.Sprintf("in-use in %d pod(s)", inUsePods)}
		if maxBlast > 0 {
			parts = append(parts, fmt.Sprintf("%d reachable services", maxBlast))
		}
		if internetExposed {
			parts = append(parts, "internet exposed")
		}
		return "PATCH NOW", strings.Join(parts, ", ")
	}

	// PATCH: critical/high + in-use but lower blast
	if sev >= 3 && inUsePods > 0 {
		return "PATCH", fmt.Sprintf("%s severity, in-use in %d pod(s), blast radius %d", cve.Severity, inUsePods, maxBlast)
	}

	// PATCH: critical + not confirmed in-use but wide blast
	if sev >= 4 && maxBlast > 50 {
		return "PATCH", fmt.Sprintf("CRITICAL severity, %d affected pod(s), blast radius %d — in-use status unconfirmed", totalAffected, maxBlast)
	}

	// MONITOR: medium severity or not in-use
	if sev >= 2 && (inUsePods == 0 || sev == 2) {
		if inUsePods == 0 {
			return "MONITOR", fmt.Sprintf("%s severity, not confirmed in-use in any pod — verify runtime profile", cve.Severity)
		}
		return "MONITOR", fmt.Sprintf("MEDIUM severity, in-use in %d pod(s)", inUsePods)
	}

	// DEPRIORITIZE: low severity or dormant + isolated
	if cve.FixedVersion == "" {
		return "DEPRIORITIZE", fmt.Sprintf("%s severity, no fix available yet", cve.Severity)
	}
	return "DEPRIORITIZE", fmt.Sprintf("%s severity, not in-use, limited blast radius", cve.Severity)
}

// enrichFromNVD fetches CVE details from NVD API (best-effort, non-blocking)
func enrichFromNVD(cveID string) {
	// NVD API v2 is rate-limited (5 req/30s without key). This is fire-and-forget
	// to enrich the cached scan data for the next lookup.
	// For now this is a no-op placeholder — the scan data from Trivy already has
	// descriptions for most CVEs. Full NVD enrichment can be added later.
}

// gzipMiddleware compresses responses for clients that accept gzip.
func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		gz, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
		defer gz.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length")
		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, Writer: gz}, r)
	})
}

type gzipResponseWriter struct {
	http.ResponseWriter
	Writer io.Writer
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) { return g.Writer.Write(b) }
