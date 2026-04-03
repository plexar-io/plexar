package runtime

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/plexar-security/plexar/internal/types"
	"github.com/plexar-security/plexar/pkg/k8s"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Profiler inspects running containers via /proc to determine which
// libraries and packages are actually loaded at runtime.
// This enables "In Use" vulnerability filtering — Sysdig's $1B feature,
// implemented without eBPF using plain /proc filesystem access.
type Profiler struct {
	client   *k8s.Client
	procRoot string // default "/proc", override for testing
}

// NewProfiler creates a runtime profiler that reads /proc on the host.
func NewProfiler(client *k8s.Client) *Profiler {
	return &Profiler{client: client, procRoot: "/proc"}
}

// NewProfilerWithRoot creates a profiler with a custom /proc root (for testing).
func NewProfilerWithRoot(client *k8s.Client, procRoot string) *Profiler {
	return &Profiler{client: client, procRoot: procRoot}
}

// FallbackMode controls behavior when /proc is not accessible
type FallbackMode int

const (
	// FallbackConservative marks all CVEs as in-use when /proc unavailable (default)
	FallbackConservative FallbackMode = iota
	// FallbackOptimistic marks no CVEs as in-use when /proc unavailable
	FallbackOptimistic
	// FallbackImageMeta uses image metadata to estimate loaded packages
	FallbackImageMeta
)

// ProfileNamespace builds runtime profiles for all pods in a namespace.
// For each pod, it reads /proc/<pid>/maps and /proc/<pid>/fd to find loaded
// shared libraries and open files, then extracts package names.
func (p *Profiler) ProfileNamespace(ctx context.Context, namespace string) ([]types.RuntimeProfile, error) {
	return p.ProfileNamespaceWithFallback(ctx, namespace, FallbackConservative)
}

// ProfileNamespaceWithFallback builds runtime profiles with a specified fallback mode.
func (p *Profiler) ProfileNamespaceWithFallback(ctx context.Context, namespace string, fallback FallbackMode) ([]types.RuntimeProfile, error) {
	pods, err := p.client.Clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=Running",
	})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	var profiles []types.RuntimeProfile
	for _, pod := range pods.Items {
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.ContainerID == "" || !cs.Ready {
				continue
			}

			// Extract the numeric PID from container status
			// In a real cluster, we'd use the CRI to get the PID.
			// For the operator running on the node, we scan /proc for matching cgroup.
			pids := p.findContainerPIDs(cs.ContainerID)
			if len(pids) == 0 {
				// /proc not accessible — use fallback mode
				profile := buildFallbackProfile(pod.Name, namespace, cs.ContainerID, cs.Image, fallback)
				profiles = append(profiles, profile)
				continue
			}

			libs := make(map[string]bool)
			files := make(map[string]bool)
			var binaryLangs []string

			for _, pid := range pids {
				// Read /proc/<pid>/maps for loaded shared libraries
				for _, lib := range p.readMaps(pid) {
					libs[lib] = true
				}
				// Read /proc/<pid>/fd for open files (jars, .so, .py, .js, etc.)
				for _, f := range p.readFDs(pid) {
					files[f] = true
				}
				// Detect Go/Rust statically-linked binaries via /proc/<pid>/exe
				if lang := p.detectBinaryLanguage(pid); lang != "" {
					binaryLangs = append(binaryLangs, lang)
				}
			}

			libList := mapKeys(libs)
			fileList := mapKeys(files)
			pkgs := extractPackageNames(libList, fileList)

			profiles = append(profiles, types.RuntimeProfile{
				PodName:        pod.Name,
				Namespace:      namespace,
				ContainerID:    cs.ContainerID,
				LoadedLibs:     libList,
				OpenFiles:      fileList,
				LoadedPackages: pkgs,
				BinaryLangs:    binaryLangs,
			})
		}
	}

	return profiles, nil
}

// buildFallbackProfile creates a RuntimeProfile when /proc is not accessible.
func buildFallbackProfile(podName, namespace, containerID, image string, mode FallbackMode) types.RuntimeProfile {
	profile := types.RuntimeProfile{
		PodName:     podName,
		Namespace:   namespace,
		ContainerID: containerID,
		Fallback:    true,
	}

	switch mode {
	case FallbackImageMeta:
		// Estimate packages from image name
		profile.LoadedPackages = estimatePackagesFromImage(image)
	case FallbackOptimistic:
		// Empty profile — nothing marked as in-use
		profile.LoadedPackages = []string{}
	default: // FallbackConservative
		// No LoadedPackages = matcher will conservatively mark all as in-use
	}

	return profile
}

// estimatePackagesFromImage returns a rough list of expected packages based on image name.
func estimatePackagesFromImage(image string) []string {
	lower := strings.ToLower(image)
	var pkgs []string

	if strings.Contains(lower, "python") {
		pkgs = append(pkgs, "python", "pip", "setuptools")
	}
	if strings.Contains(lower, "node") {
		pkgs = append(pkgs, "node", "npm")
	}
	if strings.Contains(lower, "golang") || strings.Contains(lower, "/go:") {
		pkgs = append(pkgs, "go", "golang")
	}
	if strings.Contains(lower, "nginx") {
		pkgs = append(pkgs, "nginx", "libssl", "libpcre")
	}
	if strings.Contains(lower, "redis") {
		pkgs = append(pkgs, "redis")
	}
	if strings.Contains(lower, "postgres") {
		pkgs = append(pkgs, "postgresql", "libpq")
	}
	if strings.Contains(lower, "tensorflow") || strings.Contains(lower, "pytorch") {
		pkgs = append(pkgs, "numpy", "scipy")
	}

	return pkgs
}

// findContainerPIDs scans /proc to find PIDs belonging to a container.
// It checks /proc/<pid>/cgroup for the container ID substring.
func (p *Profiler) findContainerPIDs(containerID string) []int {
	// Strip the runtime prefix (containerd://, docker://, cri-o://)
	id := containerID
	if idx := strings.LastIndex(id, "//"); idx >= 0 {
		id = id[idx+2:]
	}
	if len(id) < 12 {
		return nil
	}
	shortID := id[:12]

	entries, err := os.ReadDir(p.procRoot)
	if err != nil {
		return nil
	}

	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil {
			continue
		}

		cgroupPath := filepath.Join(p.procRoot, entry.Name(), "cgroup")
		data, err := os.ReadFile(cgroupPath)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), shortID) {
			pids = append(pids, pid)
		}
	}
	return pids
}

// readMaps parses /proc/<pid>/maps to extract loaded shared library paths.
// Each line: address perms offset dev inode pathname
func (p *Profiler) readMaps(pid int) []string {
	path := filepath.Join(p.procRoot, fmt.Sprintf("%d", pid), "maps")
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]bool)
	var libs []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Maps format: addr perms offset dev inode path
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		path := fields[len(fields)-1]
		if path == "" || path[0] != '/' {
			continue
		}
		// Only track shared libraries, jars, and interpreted language files
		if isRuntimeFile(path) && !seen[path] {
			seen[path] = true
			libs = append(libs, path)
		}
	}
	return libs
}

// readFDs reads /proc/<pid>/fd symlinks to find open files.
func (p *Profiler) readFDs(pid int) []string {
	fdDir := filepath.Join(p.procRoot, fmt.Sprintf("%d", pid), "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var files []string

	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		if target == "" || target[0] != '/' {
			continue
		}
		if isRuntimeFile(target) && !seen[target] {
			seen[target] = true
			files = append(files, target)
		}
	}
	return files
}

// detectBinaryLanguage checks /proc/<pid>/exe to identify Go or Rust statically-linked binaries.
// These don't load .so files, so /proc/pid/maps won't show their dependencies.
// Instead we read the ELF binary header for telltale strings.
func (p *Profiler) detectBinaryLanguage(pid int) string {
	exePath := filepath.Join(p.procRoot, fmt.Sprintf("%d", pid), "exe")
	target, err := os.Readlink(exePath)
	if err != nil {
		return ""
	}

	// Read first 4KB of the binary for language detection
	f, err := os.Open(target)
	if err != nil {
		// Try reading the exe link directly (works even if target is in container mount)
		f, err = os.Open(exePath)
		if err != nil {
			return ""
		}
	}
	defer f.Close()

	buf := make([]byte, 4096)
	n, err := f.Read(buf)
	if err != nil || n < 4 {
		return ""
	}
	header := string(buf[:n])

	// Go binaries contain "Go build" or "go.buildid" in their headers
	if strings.Contains(header, "Go build") || strings.Contains(header, "go.buildid") {
		return "go"
	}
	// Rust binaries typically contain "rustc" or "rust_begin_unwind"
	if strings.Contains(header, "rustc") || strings.Contains(header, "rust_begin_unwind") || strings.Contains(header, "rust_panic") {
		return "rust"
	}

	return ""
}

// isRuntimeFile returns true if the file path is a loaded library or runtime artifact.
func isRuntimeFile(path string) bool {
	lower := strings.ToLower(path)
	// Shared libraries
	if strings.Contains(lower, ".so") {
		return true
	}
	// Java JARs
	if strings.HasSuffix(lower, ".jar") {
		return true
	}
	// Python packages
	if strings.Contains(lower, "/site-packages/") || strings.HasSuffix(lower, ".py") {
		return true
	}
	// Node.js modules
	if strings.Contains(lower, "/node_modules/") {
		return true
	}
	// Ruby gems
	if strings.Contains(lower, "/gems/") {
		return true
	}
	// Go binaries (statically linked, show up as the main executable)
	if strings.HasSuffix(lower, ".go") {
		return true
	}
	// Rust crates
	if strings.Contains(lower, "/cargo/") || strings.HasSuffix(lower, ".rlib") {
		return true
	}
	return false
}

// extractPackageNames converts loaded file paths into normalized package names
// that can be matched against Trivy SBOM entries.
func extractPackageNames(libs, files []string) []string {
	pkgs := make(map[string]bool)

	for _, path := range append(libs, files...) {
		pkg := pathToPackage(path)
		if pkg != "" {
			pkgs[pkg] = true
		}
	}

	return mapKeys(pkgs)
}

// pathToPackage extracts a package name from a file path.
// Examples:
//
//	/usr/lib/x86_64-linux-gnu/libssl.so.3      -> "libssl3" or "openssl"
//	/usr/lib/python3.11/site-packages/flask/... -> "flask"
//	/app/node_modules/express/index.js          -> "express"
//	/usr/share/java/log4j-core-2.17.jar         -> "log4j-core"
func pathToPackage(path string) string {
	lower := strings.ToLower(path)

	// Shared libraries: extract lib name
	if strings.Contains(lower, ".so") {
		base := filepath.Base(path)
		// libssl.so.3 -> libssl
		if idx := strings.Index(base, ".so"); idx > 0 {
			return base[:idx]
		}
		return base
	}

	// Python site-packages
	if strings.Contains(lower, "/site-packages/") {
		parts := strings.Split(path, "/site-packages/")
		if len(parts) > 1 {
			pkg := strings.Split(parts[1], "/")[0]
			pkg = strings.TrimSuffix(pkg, ".py")
			return strings.ToLower(pkg)
		}
	}

	// Node.js modules
	if strings.Contains(lower, "/node_modules/") {
		parts := strings.Split(path, "/node_modules/")
		if len(parts) > 1 {
			pkg := strings.Split(parts[1], "/")[0]
			// Handle scoped packages (@scope/pkg)
			if strings.HasPrefix(pkg, "@") {
				rest := strings.Split(parts[1], "/")
				if len(rest) > 1 {
					return rest[0] + "/" + rest[1]
				}
			}
			return pkg
		}
	}

	// Java JARs
	if strings.HasSuffix(lower, ".jar") {
		base := filepath.Base(path)
		base = strings.TrimSuffix(base, ".jar")
		// Remove version suffix: log4j-core-2.17.1 -> log4j-core
		parts := strings.Split(base, "-")
		for i := len(parts) - 1; i > 0; i-- {
			if len(parts[i]) > 0 && parts[i][0] >= '0' && parts[i][0] <= '9' {
				parts = parts[:i]
			} else {
				break
			}
		}
		return strings.Join(parts, "-")
	}

	// Ruby gems — use the last /gems/ segment which has the actual gem name
	if strings.Contains(lower, "/gems/") {
		idx := strings.LastIndex(path, "/gems/")
		if idx >= 0 {
			rest := path[idx+len("/gems/"):]
			gem := strings.Split(rest, "/")[0]
			// Remove version: nokogiri-1.15.4 -> nokogiri
			gparts := strings.Split(gem, "-")
			for i := len(gparts) - 1; i > 0; i-- {
				if len(gparts[i]) > 0 && gparts[i][0] >= '0' && gparts[i][0] <= '9' {
					gparts = gparts[:i]
				} else {
					break
				}
			}
			return strings.Join(gparts, "-")
		}
	}

	return ""
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
