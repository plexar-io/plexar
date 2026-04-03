package metrics

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/plexar-security/plexar/internal/types"
)

// Collector maintains Prometheus metrics from scan results
type Collector struct {
	mu          sync.RWMutex
	lastResult  *types.ScanResult
}

// NewCollector creates a metrics Collector
func NewCollector() *Collector {
	return &Collector{}
}

// Update stores the latest scan result for metric exposition
func (c *Collector) Update(result *types.ScanResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastResult = result
}

// Handler returns an HTTP handler that exposes Prometheus metrics
func (c *Collector) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.RLock()
		defer c.mu.RUnlock()

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		if c.lastResult == nil {
			fmt.Fprintln(w, "# No scan data yet")
			return
		}

		var b strings.Builder
		result := c.lastResult

		// Cluster-level metrics
		b.WriteString("# HELP plexar_cluster_risk_score Overall cluster risk score (0-100)\n")
		b.WriteString("# TYPE plexar_cluster_risk_score gauge\n")
		fmt.Fprintf(&b, "plexar_cluster_risk_score{cluster=%q,namespace=%q} %d\n", result.ClusterName, result.Namespace, result.ClusterScore)

		b.WriteString("# HELP plexar_total_pods Total pods scanned\n")
		b.WriteString("# TYPE plexar_total_pods gauge\n")
		fmt.Fprintf(&b, "plexar_total_pods{cluster=%q,namespace=%q} %d\n", result.ClusterName, result.Namespace, result.TotalPods)

		b.WriteString("# HELP plexar_network_policies_count Number of NetworkPolicies in namespace\n")
		b.WriteString("# TYPE plexar_network_policies_count gauge\n")
		fmt.Fprintf(&b, "plexar_network_policies_count{cluster=%q,namespace=%q} %d\n", result.ClusterName, result.Namespace, result.NetworkPolicies)

		// Per-pod metrics
		b.WriteString("# HELP plexar_pod_blast_radius Blast radius risk score per pod (0-100)\n")
		b.WriteString("# TYPE plexar_pod_blast_radius gauge\n")
		for _, s := range result.Scores {
			fmt.Fprintf(&b, "plexar_pod_blast_radius{pod=%q,namespace=%q,tier=%q,image=%q} %d\n",
				s.PodName, result.Namespace, s.Tier, s.ImageName, s.Total)
		}

		b.WriteString("# HELP plexar_pod_cve_count CVE count per pod by severity\n")
		b.WriteString("# TYPE plexar_pod_cve_count gauge\n")
		for _, s := range result.Scores {
			fmt.Fprintf(&b, "plexar_pod_cve_count{pod=%q,namespace=%q,severity=\"critical\"} %d\n", s.PodName, result.Namespace, s.Vulns.Critical)
			fmt.Fprintf(&b, "plexar_pod_cve_count{pod=%q,namespace=%q,severity=\"high\"} %d\n", s.PodName, result.Namespace, s.Vulns.High)
			fmt.Fprintf(&b, "plexar_pod_cve_count{pod=%q,namespace=%q,severity=\"medium\"} %d\n", s.PodName, result.Namespace, s.Vulns.Medium)
		}

		b.WriteString("# HELP plexar_pod_reachable_services Number of services reachable from pod\n")
		b.WriteString("# TYPE plexar_pod_reachable_services gauge\n")
		for _, s := range result.Scores {
			fmt.Fprintf(&b, "plexar_pod_reachable_services{pod=%q,namespace=%q} %d\n", s.PodName, result.Namespace, len(s.Blast.ReachableTargets))
		}

		b.WriteString("# HELP plexar_pod_has_network_policy Whether the pod has a NetworkPolicy (0 or 1)\n")
		b.WriteString("# TYPE plexar_pod_has_network_policy gauge\n")
		for _, s := range result.Scores {
			val := 0
			if s.Blast.HasNetworkPolicy {
				val = 1
			}
			fmt.Fprintf(&b, "plexar_pod_has_network_policy{pod=%q,namespace=%q} %d\n", s.PodName, result.Namespace, val)
		}

		// Tier distribution
		tierCounts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
		for _, s := range result.Scores {
			tierCounts[s.Tier]++
		}
		b.WriteString("# HELP plexar_pods_by_tier Number of pods per risk tier\n")
		b.WriteString("# TYPE plexar_pods_by_tier gauge\n")
		for tier, count := range tierCounts {
			fmt.Fprintf(&b, "plexar_pods_by_tier{tier=%q,namespace=%q} %d\n", tier, result.Namespace, count)
		}

		// Compliance scores
		if len(result.Compliance) > 0 {
			b.WriteString("# HELP plexar_compliance_score Compliance framework score (0-100)\n")
			b.WriteString("# TYPE plexar_compliance_score gauge\n")
			for _, comp := range result.Compliance {
				fmt.Fprintf(&b, "plexar_compliance_score{framework=%q,version=%q} %d\n", comp.Framework, comp.Version, comp.Score)
			}
		}

		w.Write([]byte(b.String()))
	})
}
