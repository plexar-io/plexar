package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
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
		json.NewEncoder(w).Encode(result)
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

	handler := authMiddleware(auth.NamespaceScopedMiddleware()(mux))

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
		// Initial scan on startup
		doScan("Initial scan")
		// Seed demo history from first result
		if r := getCachedResult(); r != nil {
			_ = store.SeedDemo(r)
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
