package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/plexar-io/plexar/internal/types"
	"github.com/plexar-io/plexar/pkg/k8s"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TrivyScanner runs the trivy binary as a subprocess to scan container images.
// This is the default scanner — no prior setup required, just trivy in PATH.
type TrivyScanner struct {
	// Progress receives per-image scan status. Set to nil to suppress.
	Progress io.Writer
	// Fresh forces re-scan even if cache is valid.
	Fresh bool
}

func (t *TrivyScanner) Name() string { return "trivy" }

func (t *TrivyScanner) log(format string, args ...interface{}) {
	if t.Progress != nil {
		fmt.Fprintf(t.Progress, format, args...)
	}
}

// ScanNamespace discovers pods in the namespace, extracts their container images,
// and runs `trivy image --format json` on each unique image.
// Results are cached to ~/.plexar/cache/ so subsequent runs are instant.
func (t *TrivyScanner) ScanNamespace(ctx context.Context, client *k8s.Client, namespace string) ([]types.VulnSummary, error) {
	// Verify trivy is available
	trivyPath, err := exec.LookPath("trivy")
	if err != nil {
		return nil, fmt.Errorf("trivy binary not found in PATH. Install with: brew install trivy (or use --vuln-source trivy-operator / --vuln-source none)")
	}

	// List pods in namespace
	pods, err := client.Clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	// Collect unique images per pod
	type podImage struct {
		podName   string
		imageName string
	}
	var targets []podImage
	seen := make(map[string]bool)

	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			key := pod.Name + "|" + container.Image
			if seen[key] {
				continue
			}
			seen[key] = true
			targets = append(targets, podImage{podName: pod.Name, imageName: container.Image})
		}
	}

	// Deduplicate images — multiple pods may share the same image
	imageCache := make(map[string][]types.CVEInfo)
	total := len(targets)

	// Scan each unique image with trivy (or use cache)
	podVulns := make(map[string]*types.VulnSummary)

	for i, target := range targets {
		summary, exists := podVulns[target.podName]
		if !exists {
			summary = &types.VulnSummary{
				PodName:   target.podName,
				ImageName: target.imageName,
			}
			podVulns[target.podName] = summary
		}

		// Check in-memory cache (same image already scanned in this run)
		var vulns []types.CVEInfo
		if cached, ok := imageCache[target.imageName]; ok {
			vulns = cached
			t.log("   [%d/%d] %-40s ✓ (same image)\n", i+1, total, shortImage(target.imageName))
		} else if !t.Fresh {
			// Check disk cache
			if cached, ok := loadCached(target.imageName); ok {
				vulns = cached
				imageCache[target.imageName] = cached
				t.log("   [%d/%d] %-40s ✓ cached\n", i+1, total, shortImage(target.imageName))
			}
		}

		// Cache miss — run trivy
		if vulns == nil {
			t.log("   [%d/%d] %-40s scanning...", i+1, total, shortImage(target.imageName))
			start := time.Now()
			scanned, err := runTrivy(ctx, trivyPath, target.imageName)
			if err != nil {
				t.log(" ✗ failed (%v)\n", err)
				continue
			}
			elapsed := time.Since(start).Round(time.Second)
			vulns = scanned
			imageCache[target.imageName] = scanned
			saveCache(target.imageName, scanned)
			t.log(" ✓ %d CVEs (%s)\n", len(scanned), elapsed)
		}

		for _, v := range vulns {
			switch v.Severity {
			case "CRITICAL":
				summary.Critical++
			case "HIGH":
				summary.High++
			case "MEDIUM":
				summary.Medium++
			case "LOW":
				summary.Low++
			}
			summary.TotalCount++

			if v.FixedVersion != "" {
				summary.FixableCount++
			}

			if len(summary.TopCVEs) < 10 && (v.Severity == "CRITICAL" || v.Severity == "HIGH") {
				summary.TopCVEs = append(summary.TopCVEs, v)
			}
		}
	}

	var results []types.VulnSummary
	for _, summary := range podVulns {
		sort.Slice(summary.TopCVEs, func(i, j int) bool {
			return summary.TopCVEs[i].CVSS > summary.TopCVEs[j].CVSS
		})
		results = append(results, *summary)
	}

	return results, nil
}

// shortImage truncates long image names for progress display
func shortImage(image string) string {
	if len(image) > 40 {
		return image[:37] + "..."
	}
	return image
}

// trivyResult maps to trivy's JSON output format
type trivyResult struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			Severity         string `json:"Severity"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			PublishedDate    string `json:"PublishedDate"`
			CVSS             map[string]struct {
				V3Score float64 `json:"V3Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func runTrivy(ctx context.Context, trivyPath, image string) ([]types.CVEInfo, error) {
	cmd := exec.CommandContext(ctx, trivyPath, "image",
		"--format", "json",
		"--severity", "CRITICAL,HIGH,MEDIUM",
		"--quiet",
		"--no-progress",
		image,
	)

	output, err := cmd.Output()
	if err != nil {
		// trivy exits non-zero if vulns found — check if we still got JSON
		if len(output) == 0 {
			return nil, fmt.Errorf("trivy scan failed for %s: %w", image, err)
		}
	}

	var result trivyResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output for %s: %w", image, err)
	}

	var cves []types.CVEInfo
	for _, r := range result.Results {
		for _, v := range r.Vulnerabilities {
			cvss := 0.0
			for _, score := range v.CVSS {
				if score.V3Score > cvss {
					cvss = score.V3Score
				}
			}

			cves = append(cves, types.CVEInfo{
				ID:            v.VulnerabilityID,
				Severity:      strings.ToUpper(v.Severity),
				CVSS:          cvss,
				Package:       v.PkgName,
				FixedVersion:  v.FixedVersion,
				PublishedDate: v.PublishedDate,
			})
		}
	}

	return cves, nil
}
