# Plexar Roadmap

## Corona-Parity: Multi-Scanner Support

Goal: Match Cisco Corona's scan coverage for open-source components by adding
multiple scanners and consolidated SBOM generation.

### Phase 1 -- Grype as 2nd vulnerability scanner (HIGH PRIORITY)
- Add Grype alongside Trivy for cross-validation
- Grype uses Anchore's vulnerability database (different from Trivy's)
- Run both scanners per image, merge + deduplicate CVE results
- Expected improvement: ~10-15% more CVEs detected
- Effort: 2-3 days

### Phase 2 -- Syft SBOM generation
- Add Syft for deeper software composition analysis
- Better detection of nested/embedded packages Trivy misses
- Generate CycloneDX or SPDX SBOMs per image
- Feed Syft SBOM into both Trivy and Grype for more accurate matching
- Effort: 2-3 days

### Phase 3 -- Multi-scanner result merging
- Deduplicate CVEs across scanners (same CVE ID + package = 1 entry)
- Track which scanner(s) detected each CVE (provenance)
- Confidence scoring: CVE found by 2 scanners > 1 scanner
- Unified output format in scan results
- Effort: 1 day

### Phase 4 -- Binary-level detection (STRETCH)
- Hash-based identification of compiled libraries (e.g., statically linked C libs)
- Would require maintaining a hash database or integrating OSS tools like ORT
- Low ROI for Cisco-proprietary components (not in any public DB)
- Effort: weeks

## What Corona does that Plexar will NOT replicate
- Cisco-internal component detection (requires proprietary data)
- Cisco PSIRT advisory integration (internal only)
- YARA rule scanning for proprietary formats
- SDLC/build pipeline integration (Corona is pre-release; Plexar is runtime)

## Completed Improvements
- [x] Java fat JAR inspection (BOOT-INF/lib, WEB-INF/lib) -- partially covers Corona's "unbundling"
- [x] Go module extraction from binaries (strings /proc/1/exe)
- [x] Java DB download fix (was silently skipping all Java CVEs)
- [x] Parallel image scanning (4 workers)
- [x] CRI-O large image support (15min timeout, OOM skip-dirs)
- [x] Real-time TUI progress for long scans
