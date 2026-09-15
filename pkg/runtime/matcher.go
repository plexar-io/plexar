package runtime

import (
	"strings"

	"github.com/plexar-io/plexar/internal/types"
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

	// Instance counts (total CVE rows across all pods — matches what the user sees)
	totalInstances := 0
	inUseInstances := 0
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

		// Helper: tag a single CVE based on runtime profile
		tagCVE := func(cve *types.CVEInfo) {
			if hasProfile && !isFallback {
				matchType := matchPackageConfidence(cve.Package, pkgSet)
				if matchType > 0 {
					cve.InUse = true
					cve.Confidence = matchType
					podInUseCount++
				} else {
					cve.Confidence = 0
				}
			} else if hasProfile && isFallback {
				if isPackageInUse(cve.Package, pkgSet) {
					cve.InUse = true
					cve.Confidence = ConfidenceConservative
					podInUseCount++
				}
			} else if !hasProfile {
				cve.InUse = true
				cve.Confidence = ConfidenceConservative
				podInUseCount++
			}
		}

		// When AllCVEs is present, tag those (the authoritative list).
		// Also tag TopCVEs so both slices are consistent.
		if len(updated[i].AllCVEs) > 0 {
			for j := range updated[i].AllCVEs {
				tagCVE(&updated[i].AllCVEs[j])
			}
			totalInstances += len(updated[i].AllCVEs)
			inUseInstances += podInUseCount

			// Sync TopCVEs in-use flags from AllCVEs
			allMap := make(map[string]*types.CVEInfo)
			for j := range updated[i].AllCVEs {
				c := &updated[i].AllCVEs[j]
				allMap[c.ID+"|"+c.Package] = c
			}
			for j := range updated[i].TopCVEs {
				tc := &updated[i].TopCVEs[j]
				if ac, ok := allMap[tc.ID+"|"+tc.Package]; ok {
					tc.InUse = ac.InUse
					tc.Confidence = ac.Confidence
				}
			}
		} else {
			// Only TopCVEs available — tag them and estimate bulk
			for j := range updated[i].TopCVEs {
				tagCVE(&updated[i].TopCVEs[j])
			}
			totalInstances += len(updated[i].TopCVEs)
			inUseInstances += podInUseCount

			bulkCount := vuln.TotalCount - len(vuln.TopCVEs)
			if bulkCount > 0 && !seenImages[vuln.ImageName] {
				seenImages[vuln.ImageName] = true
				bulkTotal += bulkCount
				if !hasProfile {
					bulkInUse += bulkCount
					podInUseCount += bulkCount
				}
			} else if bulkCount > 0 && !hasProfile {
				podInUseCount += bulkCount
			}
		}

		podInUseMap[vuln.PodName] = podInUseCount
	}

	totalCVEs := totalInstances + bulkTotal
	inUseCVEs := inUseInstances + bulkInUse

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
