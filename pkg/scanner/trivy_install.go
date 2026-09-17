package scanner

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Pinned Trivy version for auto-download. Updated periodically after
// validation — avoids pulling an untested latest release.
const trivyPinnedVersion = "0.73.0"

// trivyBinDir returns ~/.plexar/bin — where we store the auto-downloaded trivy.
func trivyBinDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".plexar", "bin"), nil
}

// managedTrivyPath returns the path where an auto-downloaded trivy would live.
func managedTrivyPath() (string, error) {
	dir, err := trivyBinDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "trivy"), nil
}

// trivyDownloadURL builds the GitHub release download URL for the given version.
// Trivy uses: trivy_{version}_{OS}-{Arch}.tar.gz
//
//	OS:   macOS, Linux
//	Arch: 64bit (amd64), ARM64 (arm64)
func trivyDownloadURL(version string) (string, error) {
	var osName, archName string

	switch runtime.GOOS {
	case "darwin":
		osName = "macOS"
	case "linux":
		osName = "Linux"
	default:
		return "", fmt.Errorf("unsupported OS for trivy auto-download: %s", runtime.GOOS)
	}

	switch runtime.GOARCH {
	case "amd64":
		archName = "64bit"
	case "arm64":
		archName = "ARM64"
	default:
		return "", fmt.Errorf("unsupported architecture for trivy auto-download: %s", runtime.GOARCH)
	}

	return fmt.Sprintf(
		"https://github.com/aquasecurity/trivy/releases/download/v%s/trivy_%s_%s-%s.tar.gz",
		version, version, osName, archName,
	), nil
}

// latestTrivyVersion fetches the latest release tag from the GitHub API.
// Falls back to the pinned version on any error (network, rate limit, etc.).
func latestTrivyVersion() string {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/aquasecurity/trivy/releases/latest", nil)
	if err != nil {
		return trivyPinnedVersion
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return trivyPinnedVersion
	}
	defer resp.Body.Close()

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return trivyPinnedVersion
	}
	// Strip leading "v"
	v := strings.TrimPrefix(release.TagName, "v")
	if v == "" {
		return trivyPinnedVersion
	}
	return v
}

// ensureTrivy checks for a managed trivy binary in ~/.plexar/bin/ and
// downloads it if missing. Returns the path to the usable binary.
// The progress writer receives human-readable status messages.
func ensureTrivy(progress io.Writer) (string, error) {
	binPath, err := managedTrivyPath()
	if err != nil {
		return "", err
	}

	// Already downloaded?
	if info, err := os.Stat(binPath); err == nil && !info.IsDir() {
		return binPath, nil
	}

	// Resolve version — use pinned version (fast, no network call).
	// Users who want the latest can set TRIVY_VERSION env var.
	version := trivyPinnedVersion
	if v := os.Getenv("TRIVY_VERSION"); v != "" {
		version = strings.TrimPrefix(v, "v")
	}

	url, err := trivyDownloadURL(version)
	if err != nil {
		return "", err
	}

	if progress != nil {
		fmt.Fprintf(progress, "  ⬇  Trivy not found — downloading v%s for %s/%s...\n", version, runtime.GOOS, runtime.GOARCH)
	}

	// Create target directory
	dir := filepath.Dir(binPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("cannot create %s: %w", dir, err)
	}

	// Download
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to download trivy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to download trivy: HTTP %d from %s", resp.StatusCode, url)
	}

	// Stream progress: wrap the reader to show download progress
	contentLength := resp.ContentLength
	reader := io.Reader(resp.Body)
	if progress != nil && contentLength > 0 {
		reader = &progressReader{
			reader:  resp.Body,
			total:   contentLength,
			writer:  progress,
			prefix:  "  ⬇  ",
			started: time.Now(),
		}
	}

	// Extract the "trivy" binary from the tar.gz
	if err := extractTrivyFromTarGz(reader, binPath); err != nil {
		os.Remove(binPath) // clean up partial file
		return "", fmt.Errorf("failed to extract trivy: %w", err)
	}

	// Make executable
	if err := os.Chmod(binPath, 0755); err != nil {
		return "", fmt.Errorf("chmod trivy: %w", err)
	}

	if progress != nil {
		fmt.Fprintf(progress, "  ✓  Trivy v%s installed to %s\n", version, binPath)
	}

	return binPath, nil
}

// extractTrivyFromTarGz reads a tar.gz stream and extracts the "trivy" binary.
func extractTrivyFromTarGz(r io.Reader, destPath string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}

		// We only want the "trivy" binary (top-level in the archive)
		name := filepath.Base(hdr.Name)
		if name != "trivy" || hdr.Typeflag != tar.TypeReg {
			continue
		}

		out, err := os.Create(destPath)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		out.Close()
		return nil
	}

	return fmt.Errorf("trivy binary not found in archive")
}

// EnsureTrivy is the public API for auto-downloading trivy.
// Called by preflight checks and scan when trivy is not found.
func EnsureTrivy(progress io.Writer) (string, error) { return ensureTrivy(progress) }

// progressReader wraps an io.Reader to print download progress.
type progressReader struct {
	reader  io.Reader
	total   int64
	read    int64
	writer  io.Writer
	prefix  string
	started time.Time
	lastPct int
}

func (p *progressReader) Read(buf []byte) (int, error) {
	n, err := p.reader.Read(buf)
	p.read += int64(n)

	pct := int(p.read * 100 / p.total)
	// Print every 10% to avoid flooding
	if pct/10 > p.lastPct/10 {
		elapsed := time.Since(p.started).Round(time.Second)
		fmt.Fprintf(p.writer, "%s%d%% (%d MB / %d MB, %s)\n",
			p.prefix, pct, p.read/(1024*1024), p.total/(1024*1024), elapsed)
		p.lastPct = pct
	}

	return n, err
}
