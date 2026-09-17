package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	// ImageSource controls how Trivy accesses container images.
	// "auto" (default) detects the runtime; "crio" forces CRI-O mode.
	ImageSource string

	crioResolver *CRIOResolver
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
	// Verify trivy is available — check PATH, then common locations
	trivyPath, err := findTrivy()
	if err != nil {
		return nil, fmt.Errorf("trivy binary not found. Install: brew install trivy (macOS) or curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh (Linux). Or use --vuln-source=none to skip CVE scanning")
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

			var scanned []types.CVEInfo
			var scanErr error

			if t.effectiveImageSource() == ImageSourceCRIO {
				scanned, scanErr = t.scanViaCRIO(ctx, trivyPath, target.imageName)
			} else {
				scanned, scanErr = runTrivy(ctx, trivyPath, target.imageName)
			}

			if scanErr != nil {
				t.log(" ✗ failed (%v)\n", scanErr)
				summary.ScanError = scanErr.Error()
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

			// Store all CVEs for the full CVE explorer
			summary.AllCVEs = append(summary.AllCVEs, v)
		}
	}

	var results []types.VulnSummary
	failedScans := 0
	for _, summary := range podVulns {
		sort.Slice(summary.TopCVEs, func(i, j int) bool {
			return summary.TopCVEs[i].CVSS > summary.TopCVEs[j].CVSS
		})
		sort.Slice(summary.AllCVEs, func(i, j int) bool {
			return summary.AllCVEs[i].CVSS > summary.AllCVEs[j].CVSS
		})
		if summary.ScanError != "" {
			failedScans++
		}
		results = append(results, *summary)
	}

	if failedScans > 0 {
		t.log("   ⚠  %d/%d image scans failed — those pods show 0 CVEs (not genuinely clean)\n", failedScans, len(podVulns))
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
			VulnerabilityID  string   `json:"VulnerabilityID"`
			Severity         string   `json:"Severity"`
			PkgName          string   `json:"PkgName"`
			InstalledVersion string   `json:"InstalledVersion"`
			FixedVersion     string   `json:"FixedVersion"`
			PublishedDate    string   `json:"PublishedDate"`
			Title            string   `json:"Title"`
			Description      string   `json:"Description"`
			References       []string `json:"References"`
			CVSS             map[string]struct {
				V3Score float64 `json:"V3Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// effectiveImageSource returns the resolved image source, performing
// auto-detection if necessary.
func (t *TrivyScanner) effectiveImageSource() string {
	src := t.ImageSource
	if src == "" || src == ImageSourceAuto {
		src = DetectImageSource()
	}
	return src
}

// scanViaCRIO exports an image from CRI-O storage via skopeo, then scans
// the resulting tarball with trivy --input.
func (t *TrivyScanner) scanViaCRIO(ctx context.Context, trivyPath, imageName string) ([]types.CVEInfo, error) {
	if t.crioResolver == nil {
		t.crioResolver = &CRIOResolver{}
	}

	tarPath, cleanup, err := t.crioResolver.Export(ctx, imageName)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return runTrivyInput(ctx, trivyPath, tarPath, imageName)
}

// findTrivy locates the trivy binary. Checks in order:
// 1. TRIVY_PATH env var
// 2. Standard PATH lookup
// 3. Same directory as the running plexar binary
// 4. Common fallback paths (/usr/local/bin, ~/trivy, /home/*/trivy)
func findTrivy() (string, error) {
	// 1. Explicit env override
	if p := os.Getenv("TRIVY_PATH"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	// 2. Standard PATH
	if p, err := exec.LookPath("trivy"); err == nil {
		return p, nil
	}

	// 3. Same directory as plexar binary
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "trivy")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}

	// 4. Common locations
	fallbacks := []string{
		"/usr/local/bin/trivy",
		"/usr/bin/trivy",
	}
	// Also check home directories
	if home, err := os.UserHomeDir(); err == nil {
		fallbacks = append(fallbacks, filepath.Join(home, "trivy"))
	}
	// Check /home/*/trivy for multi-user setups (e.g. running as root, trivy in rescue-user)
	if matches, err := filepath.Glob("/home/*/trivy"); err == nil {
		fallbacks = append(fallbacks, matches...)
	}

	for _, p := range fallbacks {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p, nil
		}
	}

	return "", fmt.Errorf("trivy not found")
}

// FindTrivy exposes trivy binary resolution for preflight checks.
func FindTrivy() (string, error) { return findTrivy() }

// TrivyDBInfo locates the Trivy vulnerability DB and returns its path and the
// time it was last downloaded/updated. Used by preflight to detect a missing
// or stale DB — critical in air-gapped setups where the CRI-O scan path runs
// with --offline-scan/--skip-db-update and cannot refresh it automatically.
func TrivyDBInfo() (dbPath string, updatedAt time.Time, err error) {
	cacheDir := os.Getenv("TRIVY_CACHE_DIR")
	if cacheDir == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", time.Time{}, herr
		}
		// Check platform-specific paths: macOS uses ~/Library/Caches, Linux uses ~/.cache
		candidates := []string{
			filepath.Join(home, "Library", "Caches", "trivy"), // macOS
			filepath.Join(home, ".cache", "trivy"),            // Linux / default
		}
		for _, c := range candidates {
			if _, err := os.Stat(filepath.Join(c, "db", "trivy.db")); err == nil {
				cacheDir = c
				break
			}
		}
		if cacheDir == "" {
			cacheDir = filepath.Join(home, ".cache", "trivy") // fallback for error message
		}
	}
	dbPath = filepath.Join(cacheDir, "db", "trivy.db")
	info, statErr := os.Stat(dbPath)
	if statErr != nil {
		return dbPath, time.Time{}, fmt.Errorf("not found at %s — set TRIVY_CACHE_DIR if your DB is elsewhere", dbPath)
	}

	// Prefer metadata.json for an accurate download timestamp.
	if b, rerr := os.ReadFile(filepath.Join(cacheDir, "db", "metadata.json")); rerr == nil {
		var meta struct {
			DownloadedAt time.Time `json:"DownloadedAt"`
			UpdatedAt    time.Time `json:"UpdatedAt"`
		}
		if json.Unmarshal(b, &meta) == nil {
			if !meta.DownloadedAt.IsZero() {
				return dbPath, meta.DownloadedAt, nil
			}
			if !meta.UpdatedAt.IsZero() {
				return dbPath, meta.UpdatedAt, nil
			}
		}
	}
	// Fall back to the DB file's mtime.
	return dbPath, info.ModTime(), nil
}

func runTrivy(ctx context.Context, trivyPath, image string) ([]types.CVEInfo, error) {
	cmd := exec.CommandContext(ctx, trivyPath, "image",
		"--format", "json",
		"--severity", "CRITICAL,HIGH,MEDIUM",
		"--scanners", "vuln",
		"--quiet",
		"--no-progress",
		image,
	)
	return parseTrivyOutput(cmd, image)
}

// runTrivyInput scans a docker-archive tar (exported from CRI-O via skopeo).
// If a local Trivy DB exists, runs in offline mode (air-gapped safe).
// Otherwise lets Trivy download the DB on first run.
func runTrivyInput(ctx context.Context, trivyPath, tarPath, originalImage string) ([]types.CVEInfo, error) {
	args := []string{"image",
		"--input", tarPath,
		"--format", "json",
		"--severity", "CRITICAL,HIGH,MEDIUM",
		"--scanners", "vuln",
		"--quiet",
		"--no-progress",
		// Skip large non-package directories to reduce memory usage on enterprise images.
		// Trivy tries to parse every file for language-specific deps — docs, logs, and
		// test data in large images can push memory past node limits and trigger OOM kill.
		"--skip-dirs", "/usr/share/doc,/usr/share/man,/var/log,/var/cache,/tmp",
	}

	// Only force offline mode if a local DB already exists (air-gapped setup).
	// Otherwise let Trivy download the DB — the host may have internet access.
	if _, _, err := TrivyDBInfo(); err == nil {
		args = append(args, "--skip-db-update", "--offline-scan")
	}

	// Per-image scan timeout: 10 minutes. Enterprise Java images with thousands
	// of JARs can take a while, but >10min usually means Trivy is stuck or swapping.
	scanCtx, scanCancel := context.WithTimeout(ctx, 10*time.Minute)
	defer scanCancel()

	cmd := exec.CommandContext(scanCtx, trivyPath, args...)
	cves, err := parseTrivyOutput(cmd, originalImage)
	if err != nil && scanCtx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("trivy scan timed out for %s (>10min)", originalImage)
	}
	return cves, err
}

func parseTrivyOutput(cmd *exec.Cmd, imageLabel string) ([]types.CVEInfo, error) {
	output, err := cmd.Output()
	if err != nil {
		// trivy exits non-zero if vulns found — check if we still got JSON
		if len(output) == 0 {
			return nil, fmt.Errorf("trivy scan failed for %s: %w", imageLabel, err)
		}
	}

	var result trivyResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output for %s: %w", imageLabel, err)
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
				ID:               v.VulnerabilityID,
				Severity:         strings.ToUpper(v.Severity),
				CVSS:             cvss,
				Package:          v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				PublishedDate:    v.PublishedDate,
				Description:      v.Title,
				References:       v.References,
			})
		}
	}

	return cves, nil
}
