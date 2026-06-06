package runtime

import (
	"testing"

	"github.com/plexar-io/plexar/internal/types"
)

func TestMatchInUse_WithProfiles(t *testing.T) {
	vulns := []types.VulnSummary{
		{
			PodName:    "web-abc-123",
			ImageName:  "nginx:1.25",
			Critical:   1,
			High:       2,
			TotalCount: 10,
			TopCVEs: []types.CVEInfo{
				{ID: "CVE-2024-001", Severity: "CRITICAL", CVSS: 9.8, Package: "openssl"},
				{ID: "CVE-2024-002", Severity: "HIGH", CVSS: 7.5, Package: "zlib"},
				{ID: "CVE-2024-003", Severity: "HIGH", CVSS: 6.0, Package: "curl"},
			},
		},
	}

	profiles := []types.RuntimeProfile{
		{
			PodName:        "web-abc-123",
			Namespace:      "default",
			LoadedLibs:     []string{"/usr/lib/libssl.so.3", "/usr/lib/libz.so.1"},
			LoadedPackages: []string{"libssl", "libz"},
		},
	}

	updated, insights := MatchInUse(vulns, profiles)

	// openssl should match libssl (fuzzy match via lib prefix stripping)
	if !updated[0].TopCVEs[0].InUse {
		t.Error("CVE-2024-001 (openssl) should be marked InUse — libssl is loaded")
	}

	// zlib should match libz
	if !updated[0].TopCVEs[1].InUse {
		t.Error("CVE-2024-002 (zlib) should be marked InUse — libz is loaded")
	}

	// curl should NOT match anything loaded
	if updated[0].TopCVEs[2].InUse {
		t.Error("CVE-2024-003 (curl) should NOT be marked InUse — curl is not loaded")
	}

	if insights.TotalCVEs == 0 {
		t.Error("TotalCVEs should be > 0")
	}

	if insights.NoiseReduction <= 0 {
		t.Error("NoiseReduction should be > 0 when some CVEs are dormant")
	}
}

func TestMatchInUse_NoProfiles(t *testing.T) {
	vulns := []types.VulnSummary{
		{
			PodName:    "api-xyz-456",
			TotalCount: 5,
			TopCVEs: []types.CVEInfo{
				{ID: "CVE-2024-010", Severity: "HIGH", CVSS: 7.0, Package: "libc"},
			},
		},
	}

	// No profiles — conservative mode: mark all as in-use
	updated, insights := MatchInUse(vulns, nil)

	if !updated[0].TopCVEs[0].InUse {
		t.Error("Without profiles, CVEs should be conservatively marked InUse")
	}

	if insights.NoiseReduction != 0 {
		t.Errorf("NoiseReduction should be 0 with no profiles, got %f", insights.NoiseReduction)
	}
}

func TestIsPackageInUse(t *testing.T) {
	loaded := map[string]bool{
		"libssl":  true,
		"libz":    true,
		"express": true,
		"flask":   true,
	}

	tests := []struct {
		pkg  string
		want bool
	}{
		{"openssl", true}, // libssl matches via lib prefix stripping (ssl == ssl)
		{"libssl", true},  // direct match
		{"zlib", true},    // libz contains "z", zlib contains "z" — fuzzy
		{"express", true}, // direct match
		{"flask", true},   // direct match
		{"curl", false},   // not loaded
		{"nginx", false},  // not loaded
	}

	for _, tt := range tests {
		got := isPackageInUse(tt.pkg, loaded)
		if got != tt.want {
			t.Errorf("isPackageInUse(%q, loaded) = %v, want %v", tt.pkg, got, tt.want)
		}
	}
}

func TestMatchInUse_DeduplicatesAcrossImages(t *testing.T) {
	// Two pods running the same image — CVEs should be counted once in aggregate stats
	vulns := []types.VulnSummary{
		{
			PodName:    "web-replica-1",
			ImageName:  "nginx:1.25",
			TotalCount: 100,
			TopCVEs: []types.CVEInfo{
				{ID: "CVE-2024-001", Severity: "CRITICAL", CVSS: 9.8, Package: "openssl"},
				{ID: "CVE-2024-002", Severity: "HIGH", CVSS: 7.5, Package: "zlib"},
			},
		},
		{
			PodName:    "web-replica-2",
			ImageName:  "nginx:1.25",
			TotalCount: 100,
			TopCVEs: []types.CVEInfo{
				{ID: "CVE-2024-001", Severity: "CRITICAL", CVSS: 9.8, Package: "openssl"},
				{ID: "CVE-2024-002", Severity: "HIGH", CVSS: 7.5, Package: "zlib"},
			},
		},
	}

	// No profiles — conservative: all in-use
	_, insights := MatchInUse(vulns, nil)

	// 2 unique TopCVE IDs + 98 bulk from first image only = 100 total (not 200)
	if insights.TotalCVEs > 110 {
		t.Errorf("TotalCVEs should be ~100 (deduplicated), got %d", insights.TotalCVEs)
	}

	// Without dedup, this would be 200. With dedup, ~100.
	if insights.TotalCVEs == 200 {
		t.Error("TotalCVEs is 200 — CVEs are NOT being deduplicated across same-image pods")
	}

	// Per-pod counts should still reflect each pod's own CVEs (for bar chart)
	if insights.PodInUseMap["web-replica-1"] == 0 {
		t.Error("PodInUseMap should have per-pod counts for web-replica-1")
	}
	if insights.PodInUseMap["web-replica-2"] == 0 {
		t.Error("PodInUseMap should have per-pod counts for web-replica-2")
	}
}

func TestEnrichScoresWithRuntime(t *testing.T) {
	scores := []types.PlexarScore{
		{PodName: "web-1", Vulns: types.VulnSummary{PodName: "web-1", TopCVEs: []types.CVEInfo{{ID: "CVE-1", InUse: false}}}},
	}
	vulns := []types.VulnSummary{
		{PodName: "web-1", TopCVEs: []types.CVEInfo{{ID: "CVE-1", InUse: true}}},
	}

	enriched := EnrichScoresWithRuntime(scores, vulns)
	if !enriched[0].Vulns.TopCVEs[0].InUse {
		t.Error("EnrichScoresWithRuntime should update InUse flag from matched vulns")
	}
}
