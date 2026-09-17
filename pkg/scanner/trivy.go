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
	"sync"
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
	// MaxImages limits the number of unique images to scan (0 = no limit).
	MaxImages int

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
// scanWorkers is the number of parallel image scans. Each worker runs
// skopeo export + trivy concurrently. 4 workers cuts a 39-image scan
// from ~3h to ~45min. Kept modest to avoid OOM on constrained nodes.
const scanWorkers = 4

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

	total := len(targets)
	isCRIO := t.effectiveImageSource() == ImageSourceCRIO

	// ── Phase 1: Scan unique images (parallel) ──────────────────────
	// Build list of unique images to scan. Pods sharing the same image
	// only need one scan — results are fanned out afterwards.
	type imageResult struct {
		cves    []types.CVEInfo
		scanErr string
	}

	imageResults := make(map[string]*imageResult)  // imageName -> result
	var imagesToScan []string                      // unique images needing live scan
	diskCached := make(map[string][]types.CVEInfo) // images found in disk cache

	for _, target := range targets {
		if _, done := imageResults[target.imageName]; done {
			continue // already queued or cached
		}
		// Check disk cache first
		if !t.Fresh {
			if cached, ok := loadCached(target.imageName); ok {
				imageResults[target.imageName] = &imageResult{cves: cached}
				diskCached[target.imageName] = cached
				continue
			}
		}
		imageResults[target.imageName] = nil // placeholder — will be filled by worker
		imagesToScan = append(imagesToScan, target.imageName)
	}

	// Apply --max-images limit
	if t.MaxImages > 0 && len(imagesToScan) > t.MaxImages {
		t.log("   ⚡ --max-images %d: scanning only %d of %d unique images\n", t.MaxImages, t.MaxImages, len(imagesToScan))
		imagesToScan = imagesToScan[:t.MaxImages]
	}

	uniqueTotal := len(imagesToScan) + len(diskCached)
	t.log("   %d pods, %d unique images (%d cached, %d to scan", total, uniqueTotal, len(diskCached), len(imagesToScan))
	if len(imagesToScan) > 0 && isCRIO {
		t.log(", %d workers", scanWorkers)
	}
	t.log(")\n")

	// Parallel scan with worker pool
	if len(imagesToScan) > 0 {
		type scanJob struct {
			imageName string
			index     int
		}
		jobs := make(chan scanJob, len(imagesToScan))
		resultsCh := make(chan struct {
			imageName string
			result    imageResult
		}, len(imagesToScan))

		// Determine worker count — use fewer workers for small batches
		workers := scanWorkers
		if len(imagesToScan) < workers {
			workers = len(imagesToScan)
		}

		// Start workers
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for job := range jobs {
					t.log("   [%d/%d] %-40s", job.index+1, len(imagesToScan), shortImage(job.imageName))
					start := time.Now()

					var scanned []types.CVEInfo
					var scanErr error

					if isCRIO {
						scanned, scanErr = t.scanViaCRIO(ctx, trivyPath, job.imageName)
					} else {
						t.log(" scanning...")
						scanned, scanErr = runTrivy(ctx, trivyPath, job.imageName)
					}

					elapsed := time.Since(start).Round(time.Second)
					if scanErr != nil {
						t.log(" ✗ failed after %s (%v)\n", elapsed, scanErr)
						resultsCh <- struct {
							imageName string
							result    imageResult
						}{job.imageName, imageResult{scanErr: scanErr.Error()}}
					} else {
						saveCache(job.imageName, scanned)
						t.log(" ✓ %d CVEs (%s)\n", len(scanned), elapsed)
						resultsCh <- struct {
							imageName string
							result    imageResult
						}{job.imageName, imageResult{cves: scanned}}
					}
				}
			}()
		}

		// Send jobs
		for i, img := range imagesToScan {
			jobs <- scanJob{imageName: img, index: i}
		}
		close(jobs)

		// Collect results in background
		go func() {
			wg.Wait()
			close(resultsCh)
		}()

		for r := range resultsCh {
			imageResults[r.imageName] = &r.result
		}
	}

	// ── Phase 2: Fan out image results to pods ──────────────────────
	podVulns := make(map[string]*types.VulnSummary)

	for _, target := range targets {
		summary, exists := podVulns[target.podName]
		if !exists {
			summary = &types.VulnSummary{
				PodName:   target.podName,
				ImageName: target.imageName,
			}
			podVulns[target.podName] = summary
		}

		ir := imageResults[target.imageName]
		if ir == nil {
			continue
		}
		if ir.scanErr != "" {
			summary.ScanError = ir.scanErr
			continue
		}

		for _, v := range ir.cves {
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

	t.log(" [export]")
	exportStart := time.Now()
	tarPath, cleanup, err := t.crioResolver.Export(ctx, imageName)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Log the exported tar size so we can gauge how long trivy will take
	if fi, statErr := os.Stat(tarPath); statErr == nil {
		sizeMB := fi.Size() / (1024 * 1024)
		t.log(" %dMB (%s)", sizeMB, time.Since(exportStart).Round(time.Second))
	}

	t.log(" [trivy]")
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

	// If the main vuln DB already exists, skip re-downloading it (saves time).
	// But do NOT use --offline-scan: trivy needs network access to download the
	// Java DB on first use. Without it, Java vulnerabilities are silently skipped
	// and enterprise Java images (like NDFC) appear to have 0 CVEs.
	if dbPath, _, dbErr := TrivyDBInfo(); dbErr == nil {
		args = append(args, "--skip-db-update")

		// Check if Java DB exists — if so, also skip that download
		// DB is at <cache>/db/trivy.db, Java DB at <cache>/java-db/trivy-java.db
		cacheDir := filepath.Dir(filepath.Dir(dbPath))
		javaDB := filepath.Join(cacheDir, "java-db", "trivy-java.db")
		if _, serr := os.Stat(javaDB); serr == nil {
			args = append(args, "--skip-java-db-update")
		}
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
