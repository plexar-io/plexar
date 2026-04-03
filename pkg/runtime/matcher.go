package runtime

import (
	"strings"

	"github.com/plexar-security/plexar/internal/types"
)

// MatchInUse cross-references runtime profiles against Trivy SBOM (VulnSummary)
// to tag CVEs whose packages are actually loaded at runtime.
// Returns updated VulnSummaries with InUse flags set on CVEInfo entries,
// plus aggregate RuntimeInsights with noise reduction stats.
func MatchInUse(vulns []types.VulnSummary, profiles []types.RuntimeProfile) ([]types.VulnSummary, *types.RuntimeInsights) {
	// Build lookup: podName -> set of loaded package names (normalized lowercase)
	podPackages := make(map[string]map[string]bool)
	podFallback := make(map[string]bool) // podName -> whether profile is fallback
	for _, prof := range profiles {
		pkgSet := make(map[string]bool)
		for _, pkg := range prof.LoadedPackages {
			pkgSet[strings.ToLower(pkg)] = true
		}
		// Also index loaded libs directly for .so matching
		for _, lib := range prof.LoadedLibs {
			base := libToPackageName(lib)
			if base != "" {
				pkgSet[strings.ToLower(base)] = true
			}
		}
		podPackages[prof.PodName] = pkgSet
		podFallback[prof.PodName] = prof.Fallback
	}

	updated := make([]types.VulnSummary, len(vulns))
	podInUseMap := make(map[string]int)

	// Track unique CVEs across all pods (deduplicate by CVE ID)
	uniqueCVEs := make(map[string]bool)  // CVE ID -> seen
	uniqueInUse := make(map[string]bool) // CVE ID -> in-use
	// Track images already counted for bulk (non-TopCVE) totals
	seenImages := make(map[string]bool)
	bulkTotal := 0
	bulkInUse := 0

	for i, vuln := range vulns {
		updated[i] = vuln
		pkgSet := podPackages[vuln.PodName]
		isFallback := podFallback[vuln.PodName]
		hasProfile := pkgSet != nil && len(pkgSet) > 0

		podInUseCount := 0

		for j, cve := range updated[i].TopCVEs {
			if hasProfile && !isFallback {
				// Real /proc profile available — use confidence-scored matching
				matchType := matchPackageConfidence(cve.Package, pkgSet)
				if matchType > 0 {
					updated[i].TopCVEs[j].InUse = true
					updated[i].TopCVEs[j].Confidence = matchType
					podInUseCount++
					uniqueCVEs[cve.ID] = true
					uniqueInUse[cve.ID] = true
				} else {
					updated[i].TopCVEs[j].Confidence = 0
					uniqueCVEs[cve.ID] = true
				}
			} else if hasProfile && isFallback {
				// Fallback profile (image-based estimate) — conservative confidence
				if isPackageInUse(cve.Package, pkgSet) {
					updated[i].TopCVEs[j].InUse = true
					updated[i].TopCVEs[j].Confidence = ConfidenceConservative
					podInUseCount++
					uniqueCVEs[cve.ID] = true
					uniqueInUse[cve.ID] = true
				} else {
					uniqueCVEs[cve.ID] = true
				}
			} else if !hasProfile {
				// No runtime profile available — conservatively mark as in-use
				updated[i].TopCVEs[j].InUse = true
				updated[i].TopCVEs[j].Confidence = ConfidenceConservative
				podInUseCount++
				uniqueCVEs[cve.ID] = true
				uniqueInUse[cve.ID] = true
			} else {
				uniqueCVEs[cve.ID] = true
			}
		}

		// Count bulk CVEs (beyond TopCVEs) once per unique image
		bulkCount := vuln.TotalCount - len(vuln.TopCVEs)
		if bulkCount > 0 && !seenImages[vuln.ImageName] {
			seenImages[vuln.ImageName] = true
			bulkTotal += bulkCount
			if !hasProfile {
				bulkInUse += bulkCount
				podInUseCount += bulkCount
			}
		} else if bulkCount > 0 && !hasProfile {
			// Still count per-pod for the bar chart even if image is duplicate
			podInUseCount += bulkCount
		}

		podInUseMap[vuln.PodName] = podInUseCount
	}

	totalCVEs := len(uniqueCVEs) + bulkTotal
	inUseCVEs := len(uniqueInUse) + bulkInUse

	noiseReduction := 0.0
	if totalCVEs > 0 {
		noiseReduction = float64(totalCVEs-inUseCVEs) / float64(totalCVEs) * 100
	}

	insights := &types.RuntimeInsights{
		TotalCVEs:      totalCVEs,
		InUseCVEs:      inUseCVEs,
		NoiseReduction: noiseReduction,
		Profiles:       profiles,
		PodInUseMap:    podInUseMap,
	}

	return updated, insights
}

// Confidence levels for "in use" matching
const (
	ConfidenceExact        float64 = 1.0 // Direct package name match
	ConfidenceFuzzy        float64 = 0.7 // Fuzzy match (contains, lib prefix)
	ConfidenceConservative float64 = 0.5 // No /proc data, conservatively marked
)

// matchPackageConfidence returns the confidence score for a package match.
// Returns 0 if no match found.
func matchPackageConfidence(cvePackage string, loadedPkgs map[string]bool) float64 {
	pkg := strings.ToLower(cvePackage)

	// Direct/exact match — highest confidence
	if loadedPkgs[pkg] {
		return ConfidenceExact
	}

	// Fuzzy matching
	for loaded := range loadedPkgs {
		if strings.Contains(loaded, pkg) || strings.Contains(pkg, loaded) {
			return ConfidenceFuzzy
		}
		// Handle lib prefix: "openssl" <-> "libssl"
		trimmedPkg := strings.TrimPrefix(pkg, "lib")
		trimmedLoaded := strings.TrimPrefix(loaded, "lib")
		if trimmedPkg == trimmedLoaded {
			return ConfidenceFuzzy
		}
		if strings.Contains(trimmedLoaded, trimmedPkg) || strings.Contains(trimmedPkg, trimmedLoaded) {
			return ConfidenceFuzzy
		}
	}

	return 0
}

// isPackageInUse checks whether a CVE's package name matches any loaded package.
// Uses fuzzy matching: "openssl" matches "libssl", "libcrypto" matches "openssl", etc.
func isPackageInUse(cvePackage string, loadedPkgs map[string]bool) bool {
	return matchPackageConfidence(cvePackage, loadedPkgs) > 0
}

// libToPackageName converts a shared library path to a package name for matching.
func libToPackageName(libPath string) string {
	lower := strings.ToLower(libPath)

	// Extract base filename
	parts := strings.Split(lower, "/")
	base := parts[len(parts)-1]

	// Strip .so and version suffixes
	if idx := strings.Index(base, ".so"); idx > 0 {
		return base[:idx]
	}

	return ""
}

// EnrichScoresWithRuntime adds InUse CVE counts to ReflexScores.
// Updates the Vulns.TopCVEs with InUse flags from the matched vulns.
func EnrichScoresWithRuntime(scores []types.PlexarScore, vulns []types.VulnSummary) []types.PlexarScore {
	vulnMap := make(map[string]types.VulnSummary)
	for _, v := range vulns {
		vulnMap[v.PodName] = v
	}

	for i, score := range scores {
		if v, ok := vulnMap[score.PodName]; ok {
			scores[i].Vulns = v
		}
	}
	return scores
}
