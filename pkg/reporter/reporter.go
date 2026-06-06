package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/plexar-io/plexar/internal/types"
)

// PrintReport outputs the CLI scan report
func PrintReport(w io.Writer, result *types.ScanResult) {
	fmt.Fprintf(w, "\n🛡  Plexar — Kubernetes Blast Radius Intelligence\n")
	fmt.Fprintf(w, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Fprintf(w, "  Cluster:   %s\n", result.ClusterName)
	fmt.Fprintf(w, "  Namespace: %s\n", result.Namespace)
	fmt.Fprintf(w, "  Pods:      %d scanned\n", result.TotalPods)
	fmt.Fprintf(w, "  Policies:  %d NetworkPolicies\n", result.NetworkPolicies)
	fmt.Fprintf(w, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	for _, warning := range result.Warnings {
		fmt.Fprintf(w, "  ⚠  %s\n\n", warning)
	}

	// Tier summary
	tiers := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, s := range result.Scores {
		tiers[s.Tier]++
	}
	fmt.Fprintf(w, "  Cluster Score: %d/100    ", result.ClusterScore)
	fmt.Fprintf(w, "Low: %d  Medium: %d  High: %d  Critical: %d\n\n",
		tiers["low"], tiers["medium"], tiers["high"], tiers["critical"])

	// Table header
	fmt.Fprintf(w, "  %-5s %-6s %-10s %-24s %-22s %-10s %-12s %s\n",
		"RANK", "SCORE", "TIER", "SERVICE", "CLASS", "CVEs", "BLAST", "IMAGE")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 120))

	for i, s := range result.Scores {
		svcName := shortName(s.PodName)
		if len(svcName) > 23 {
			svcName = svcName[:23]
		}
		image := s.ImageName
		if len(image) > 24 {
			image = image[:24] + "…"
		}

		wclass := s.WorkloadClass
		if wclass == "" {
			wclass = "—"
		}
		if len(wclass) > 21 {
			wclass = wclass[:21]
		}
		if s.RiskMultiplier > 1.0 {
			wclass = fmt.Sprintf("%s ×%.1f", wclass, s.RiskMultiplier)
		}

		cves := fmt.Sprintf("%dC/%dH", s.Vulns.Critical, s.Vulns.High)
		blast := fmt.Sprintf("%d svc", len(s.Blast.ReachableTargets))
		if s.Blast.InternetAccess {
			blast += "+inet"
		}

		fmt.Fprintf(w, "  %-5d %-6d %-10s %-24s %-22s %-10s %-12s %s\n",
			i+1, s.Total, s.Tier, svcName, wclass, cves, blast, image)
	}

	fmt.Fprintln(w)

	// Top pod detail
	if len(result.Scores) > 0 {
		top := result.Scores[0]
		fmt.Fprintf(w, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Fprintf(w, "  ⚠  %s — Score: %d/100\n", shortName(top.PodName), top.Total)
		fmt.Fprintf(w, "  Image: %s\n\n", top.ImageName)

		if top.Roast != "" {
			fmt.Fprintf(w, "  💬 \"%s\"\n\n", top.Roast)
		}

		fmt.Fprintf(w, "  🎯 Blast Radius — If Exploited, Attacker Reaches:\n")
		if !top.Blast.HasNetworkPolicy {
			fmt.Fprintf(w, "    ⚠  +%d additional services reachable (no NetworkPolicy)\n", len(top.Blast.ReachableTargets))
		}
		if top.Blast.InternetAccess {
			fmt.Fprintf(w, "    🌐 INTERNET (0.0.0.0/0) — full egress access\n")
		}
		if len(top.Blast.DataStoreAccess) > 0 {
			fmt.Fprintf(w, "    💾 Data stores: %s\n", strings.Join(top.Blast.DataStoreAccess, ", "))
		}
		fmt.Fprintf(w, "    🔓 NetworkPolicy: %s\n\n", boolToPolicy(top.Blast.HasNetworkPolicy))

		fmt.Fprintf(w, "  🐛 CVEs: %d critical, %d high, %d medium (%d total, %d fixable)\n",
			top.Vulns.Critical, top.Vulns.High, top.Vulns.Medium, top.Vulns.TotalCount, top.Vulns.FixableCount)
		for _, cve := range top.Vulns.TopCVEs {
			fix := ""
			if cve.FixedVersion != "" {
				fix = " → " + cve.FixedVersion
			}
			fmt.Fprintf(w, "    %-9s %-18s CVSS:%.1f  %s%s\n", cve.Severity, cve.ID, cve.CVSS, cve.Package, fix)
		}
		fmt.Fprintln(w)

		if len(top.Recommendations) > 0 {
			fmt.Fprintf(w, "  💡 Recommendations:\n")
			for _, rec := range top.Recommendations {
				fmt.Fprintf(w, "    [%s] %s\n", rec.Priority, rec.Title)
			}
			fmt.Fprintln(w)
		}
	}
}

func shortName(podName string) string {
	parts := strings.Split(podName, "-")
	if len(parts) > 2 {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return podName
}

func boolToPolicy(has bool) string {
	if has {
		return "APPLIED"
	}
	return "NONE"
}
