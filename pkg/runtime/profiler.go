package runtime

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/plexar-io/plexar/internal/types"
	"github.com/plexar-io/plexar/pkg/k8s"
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
// Strategy: try kubectl exec into each pod first (works across nodes), then
// fall back to host /proc (works when plexar runs on the same node as the pod).
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

			// Strategy 1: kubectl exec into the pod (works across nodes)
			profile, execErr := p.profileViaExec(ctx, pod.Name, namespace, cs.Name, cs.ContainerID, cs.Image)
			if execErr == nil && len(profile.LoadedPackages) > 0 {
				profiles = append(profiles, profile)
				continue
			}

			// Strategy 2: host /proc scan (works when plexar is on the same node)
			pids := p.findContainerPIDs(cs.ContainerID)
			if len(pids) > 0 {
				profile := p.profileViaProcPIDs(pod.Name, namespace, cs.ContainerID, pids)
				profiles = append(profiles, profile)
				continue
			}

			// Strategy 3: fallback
			fb := buildFallbackProfile(pod.Name, namespace, cs.ContainerID, cs.Image, fallback)
			profiles = append(profiles, fb)
		}
	}

	return profiles, nil
}

// profileViaExec runs `cat /proc/1/maps` and `ls -la /proc/1/fd/` inside the
// pod via kubectl exec. This works across all nodes — plexar does NOT need to
// run on the same host as the pod.
func (p *Profiler) profileViaExec(ctx context.Context, podName, namespace, containerName, containerID, image string) (types.RuntimeProfile, error) {
	empty := types.RuntimeProfile{}

	// Read /proc/1/maps inside the container (PID 1 = main process)
	mapsOut, err := p.client.ExecInPod(ctx, namespace, podName, containerName,
		[]string{"cat", "/proc/1/maps"})
	if err != nil {
		// Some containers don't have `cat` — try with /bin/sh
		mapsOut, err = p.client.ExecInPod(ctx, namespace, podName, containerName,
			[]string{"/bin/sh", "-c", "cat /proc/1/maps 2>/dev/null || cat /proc/self/maps 2>/dev/null"})
		if err != nil {
			return empty, fmt.Errorf("exec cat /proc/1/maps: %w", err)
		}
	}

	libs := make(map[string]bool)
	for _, line := range strings.Split(mapsOut, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		path := fields[len(fields)-1]
		if path == "" || path[0] != '/' {
			continue
		}
		if isRuntimeFile(path) && !libs[path] {
			libs[path] = true
		}
	}

	// Read /proc/1/fd via readlink inside the container
	files := make(map[string]bool)
	fdOut, fdErr := p.client.ExecInPod(ctx, namespace, podName, containerName,
		[]string{"/bin/sh", "-c", "ls -la /proc/1/fd/ 2>/dev/null | awk '{print $NF}'"})
	if fdErr == nil {
		for _, line := range strings.Split(fdOut, "\n") {
			path := strings.TrimSpace(line)
			if path == "" || path[0] != '/' {
				continue
			}
			if isRuntimeFile(path) && !files[path] {
				files[path] = true
			}
		}
	}

	// Detect Go/Rust via /proc/1/exe
	var binaryLangs []string
	exeOut, exeErr := p.client.ExecInPod(ctx, namespace, podName, containerName,
		[]string{"/bin/sh", "-c", "head -c 4096 /proc/1/exe 2>/dev/null | strings 2>/dev/null | head -50"})
	if exeErr == nil {
		if strings.Contains(exeOut, "Go build") || strings.Contains(exeOut, "go.buildid") {
			binaryLangs = append(binaryLangs, "go")
		} else if strings.Contains(exeOut, "rustc") || strings.Contains(exeOut, "rust_begin_unwind") {
			binaryLangs = append(binaryLangs, "rust")
		}
	}

	libList := mapKeys(libs)
	fileList := mapKeys(files)
	pkgs := extractPackageNames(libList, fileList)

	// Deep inspection: Go module dependencies from embedded build info
	if containsLang(binaryLangs, "go") {
		goMods := p.extractGoModules(ctx, podName, namespace, containerName)
		for _, mod := range goMods {
			pkgs = append(pkgs, mod)
		}
	}

	// Deep inspection: Java fat JAR internals (Spring Boot, shaded JARs)
	javaLibs := p.extractJavaFatJarDeps(ctx, podName, namespace, containerName, libs, files)
	for _, lib := range javaLibs {
		pkgs = append(pkgs, lib)
	}

	if len(pkgs) == 0 && len(libs) == 0 {
		return empty, fmt.Errorf("no runtime data found")
	}

	return types.RuntimeProfile{
		PodName:        podName,
		Namespace:      namespace,
		ContainerID:    containerID,
		LoadedLibs:     libList,
		OpenFiles:      fileList,
		LoadedPackages: pkgs,
		BinaryLangs:    binaryLangs,
	}, nil
}

// profileViaProcPIDs profiles a container via host /proc when PIDs are available.
func (p *Profiler) profileViaProcPIDs(podName, namespace, containerID string, pids []int) types.RuntimeProfile {
	libs := make(map[string]bool)
	files := make(map[string]bool)
	var binaryLangs []string

	for _, pid := range pids {
		for _, lib := range p.readMaps(pid) {
			libs[lib] = true
		}
		for _, f := range p.readFDs(pid) {
			files[f] = true
		}
		if lang := p.detectBinaryLanguage(pid); lang != "" {
			binaryLangs = append(binaryLangs, lang)
		}
	}

	libList := mapKeys(libs)
	fileList := mapKeys(files)
	pkgs := extractPackageNames(libList, fileList)

	// Go module extraction via host /proc for the first PID
	if containsLang(binaryLangs, "go") && len(pids) > 0 {
		goMods := p.extractGoModulesFromProc(pids[0])
		pkgs = append(pkgs, goMods...)
	}

	return types.RuntimeProfile{
		PodName:        podName,
		Namespace:      namespace,
		ContainerID:    containerID,
		LoadedLibs:     libList,
		OpenFiles:      fileList,
		LoadedPackages: pkgs,
		BinaryLangs:    binaryLangs,
	}
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

// extractGoModules reads the Go binary's embedded module dependency list.
// Go 1.18+ embeds build info in the binary (same data as `go version -m <binary>`).
// We extract it with `strings` + grep — no `go` binary needed in the container.
func (p *Profiler) extractGoModules(ctx context.Context, podName, namespace, containerName string) []string {
	// Go embeds module info as text lines like:
	//   path	github.com/plexar-io/plexar
	//   mod	github.com/plexar-io/plexar	(devel)
	//   dep	github.com/spf13/cobra	v1.8.0	h1:...
	//   dep	golang.org/x/net	v0.24.0	h1:...
	// We read enough of the binary to capture this section.
	out, err := p.client.ExecInPod(ctx, namespace, podName, containerName,
		[]string{"/bin/sh", "-c", "strings /proc/1/exe 2>/dev/null | grep -E '^(dep|mod)\\s+' | head -200"})
	if err != nil {
		return nil
	}

	var modules []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "dep\tmodule/path\tversion\thash" or "mod\tmodule/path\tversion"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kind := fields[0]
		if kind != "dep" && kind != "mod" {
			continue
		}
		modPath := fields[1]

		// Extract the short package name from the module path
		// e.g. "github.com/spf13/cobra" -> "cobra"
		// e.g. "golang.org/x/net" -> "net"
		// e.g. "google.golang.org/grpc" -> "grpc"
		parts := strings.Split(modPath, "/")
		shortName := parts[len(parts)-1]
		// Also keep the last two segments for better matching
		// "github.com/lib/pq" -> "pq" and "lib/pq"
		if !seen[shortName] {
			seen[shortName] = true
			modules = append(modules, shortName)
		}
		if len(parts) >= 2 {
			twoSeg := parts[len(parts)-2] + "/" + parts[len(parts)-1]
			if !seen[twoSeg] {
				seen[twoSeg] = true
				modules = append(modules, twoSeg)
			}
		}
		// Store full module path for exact matching against Trivy's Go SBOM
		if !seen[modPath] {
			seen[modPath] = true
			modules = append(modules, modPath)
		}
	}

	return modules
}

// extractJavaFatJarDeps inspects Java fat JARs (Spring Boot, shaded) to find
// embedded library JARs inside BOOT-INF/lib/ or WEB-INF/lib/.
// Without this, a fat JAR appears as a single dependency and all transitive
// libraries inside it are invisible to the in-use matcher.
func (p *Profiler) extractJavaFatJarDeps(ctx context.Context, podName, namespace, containerName string, libs, files map[string]bool) []string {
	// Find JAR paths from /proc/1/cmdline (java -jar /app.jar) and open files
	var jarPaths []string
	cmdOut, cmdErr := p.client.ExecInPod(ctx, namespace, podName, containerName,
		[]string{"/bin/sh", "-c", "cat /proc/1/cmdline 2>/dev/null | tr '\\0' '\\n'"})
	if cmdErr == nil {
		for _, arg := range strings.Split(cmdOut, "\n") {
			arg = strings.TrimSpace(arg)
			if strings.HasSuffix(strings.ToLower(arg), ".jar") {
				jarPaths = append(jarPaths, arg)
			}
		}
	}
	// Also check open file descriptors for JARs
	for f := range files {
		if strings.HasSuffix(strings.ToLower(f), ".jar") {
			jarPaths = append(jarPaths, f)
		}
	}
	for f := range libs {
		if strings.HasSuffix(strings.ToLower(f), ".jar") {
			jarPaths = append(jarPaths, f)
		}
	}

	if len(jarPaths) == 0 {
		return nil
	}

	// Deduplicate JAR paths
	seenJars := make(map[string]bool)
	var uniqueJars []string
	for _, jp := range jarPaths {
		if !seenJars[jp] {
			seenJars[jp] = true
			uniqueJars = append(uniqueJars, jp)
		}
	}

	// List contents of each JAR looking for embedded libs
	// Spring Boot: BOOT-INF/lib/spring-core-6.1.5.jar
	// War files: WEB-INF/lib/commons-io-2.11.jar
	// Shaded JARs: META-INF/maven/groupId/artifactId/pom.properties
	var deps []string
	seen := make(map[string]bool)

	for _, jar := range uniqueJars {
		// Try unzip -l (most minimal containers have it), fall back to jar tf
		out, err := p.client.ExecInPod(ctx, namespace, podName, containerName,
			[]string{"/bin/sh", "-c", fmt.Sprintf(
				"(unzip -l '%s' 2>/dev/null || jar tf '%s' 2>/dev/null) | grep -iE '(BOOT-INF/lib/|WEB-INF/lib/|META-INF/maven/).+\\.jar$' | head -500",
				jar, jar)})
		if err != nil {
			// Try listing pom.properties for shaded JARs (no embedded .jar files)
			out, err = p.client.ExecInPod(ctx, namespace, podName, containerName,
				[]string{"/bin/sh", "-c", fmt.Sprintf(
					"(unzip -l '%s' 2>/dev/null || jar tf '%s' 2>/dev/null) | grep 'pom.properties' | head -200",
					jar, jar)})
			if err != nil {
				continue
			}
		}

		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)

			// Extract JAR filename from lines like:
			// "  12345  2024-01-01 00:00   BOOT-INF/lib/spring-core-6.1.5.jar"
			// or just: "BOOT-INF/lib/spring-core-6.1.5.jar"
			var jarFile string
			if strings.HasSuffix(line, ".jar") {
				fields := strings.Fields(line)
				jarFile = fields[len(fields)-1]
			} else if strings.Contains(line, "pom.properties") {
				// META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.properties
				// Extract artifactId from the path
				parts := strings.Split(line, "/")
				fields := strings.Fields(parts[len(parts)-1])
				lastPart := fields[len(fields)-1]
				if lastPart == "pom.properties" && len(parts) >= 2 {
					artifactID := parts[len(parts)-2]
					if !seen[artifactID] {
						seen[artifactID] = true
						deps = append(deps, artifactID)
					}
				}
				continue
			} else {
				continue
			}

			// Parse JAR filename: spring-core-6.1.5.jar -> spring-core
			base := filepath.Base(jarFile)
			base = strings.TrimSuffix(base, ".jar")
			name := stripJarVersion(base)
			if name != "" && !seen[name] {
				seen[name] = true
				deps = append(deps, name)
			}
		}
	}

	return deps
}

// stripJarVersion removes the version suffix from a JAR base name.
// "spring-core-6.1.5" -> "spring-core"
// "jackson-databind-2.15.3" -> "jackson-databind"
// "log4j-core-2.17.1" -> "log4j-core"
func stripJarVersion(base string) string {
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

// extractGoModulesFromProc reads Go module info from a binary via host /proc.
func (p *Profiler) extractGoModulesFromProc(pid int) []string {
	exePath := filepath.Join(p.procRoot, fmt.Sprintf("%d", pid), "exe")

	// Read a larger chunk of the binary to capture Go build info
	f, err := os.Open(exePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	// Go build info is typically within the first 2MB
	buf := make([]byte, 2*1024*1024)
	n, _ := f.Read(buf)
	if n < 100 {
		return nil
	}
	content := string(buf[:n])

	var modules []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] != "dep" && fields[0] != "mod" {
			continue
		}
		modPath := fields[1]
		parts := strings.Split(modPath, "/")
		shortName := parts[len(parts)-1]

		if !seen[shortName] {
			seen[shortName] = true
			modules = append(modules, shortName)
		}
		if len(parts) >= 2 {
			twoSeg := parts[len(parts)-2] + "/" + parts[len(parts)-1]
			if !seen[twoSeg] {
				seen[twoSeg] = true
				modules = append(modules, twoSeg)
			}
		}
		if !seen[modPath] {
			seen[modPath] = true
			modules = append(modules, modPath)
		}
	}
	return modules
}

// containsLang checks if a language is in the binary langs list.
func containsLang(langs []string, target string) bool {
	for _, l := range langs {
		if l == target {
			return true
		}
	}
	return false
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
