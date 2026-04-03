package ingest

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CycloneDX SBOM structures (subset)
type cycloneDXBOM struct {
	BOMFormat    string              `json:"bomFormat"`
	SpecVersion  string              `json:"specVersion"`
	Version      int                 `json:"version"`
	Metadata     cycloneDXMetadata   `json:"metadata"`
	Components   []cycloneDXComponent `json:"components"`
}

type cycloneDXMetadata struct {
	Component cycloneDXComponent `json:"component"`
}

type cycloneDXComponent struct {
	Type       string              `json:"type"`     // library, framework, application, operating-system
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	BOMRef     string              `json:"bom-ref"`
	PURL       string              `json:"purl"`
	Licenses   []cycloneDXLicense  `json:"licenses"`
	Properties []cycloneDXProperty `json:"properties"`
}

type cycloneDXLicense struct {
	License cycloneDXLicenseDetail `json:"license"`
}

type cycloneDXLicenseDetail struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SPDX SBOM structures (subset)
type spdxDocument struct {
	SPDXVersion    string         `json:"spdxVersion"`
	Name           string         `json:"name"`
	Packages       []spdxPackage  `json:"packages"`
}

type spdxPackage struct {
	Name                 string `json:"name"`
	VersionInfo          string `json:"versionInfo"`
	ExternalRefs         []spdxExternalRef `json:"externalRefs"`
	LicenseConcluded     string `json:"licenseConcluded"`
	LicenseDeclared      string `json:"licenseDeclared"`
	PrimaryPackagePurpose string `json:"primaryPackagePurpose"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

func ingestTrivySBOM(data []byte) (*IngestResult, error) {
	result := &IngestResult{
		Source: SourceTrivySBOM,
	}

	// Try CycloneDX first
	var cdx cycloneDXBOM
	if err := json.Unmarshal(data, &cdx); err == nil && cdx.BOMFormat == "CycloneDX" {
		return parseCycloneDX(&cdx, result)
	}

	// Try SPDX
	var spdx spdxDocument
	if err := json.Unmarshal(data, &spdx); err == nil && strings.HasPrefix(spdx.SPDXVersion, "SPDX") {
		return parseSPDX(&spdx, result)
	}

	return nil, fmt.Errorf("failed to parse SBOM: not CycloneDX or SPDX format")
}

func parseCycloneDX(cdx *cycloneDXBOM, result *IngestResult) (*IngestResult, error) {
	imageName := cdx.Metadata.Component.Name

	for _, comp := range cdx.Components {
		if comp.Type == "operating-system" {
			continue
		}

		pkgType := detectPkgTypeFromPURL(comp.PURL)
		if pkgType == "" {
			pkgType = comp.Type
		}

		var licenses []string
		for _, lic := range comp.Licenses {
			if lic.License.ID != "" {
				licenses = append(licenses, lic.License.ID)
			} else if lic.License.Name != "" {
				licenses = append(licenses, lic.License.Name)
			}
		}

		result.SBOMComponents = append(result.SBOMComponents, SBOMComponent{
			Name:     comp.Name,
			Version:  comp.Version,
			Type:     comp.Type,
			PkgType:  pkgType,
			Licenses: licenses,
			PodName:  imageName,
		})

		// Each component is a "pass" finding (it exists in the SBOM)
		result.Findings = append(result.Findings, ExternalFinding{
			Source:   SourceTrivySBOM,
			Category: "sbom",
			Severity: "info",
			Resource: imageName,
			RuleID:   "sbom-component",
			RuleName: "SBOM Component Inventory",
			Message:  fmt.Sprintf("%s@%s (%s)", comp.Name, comp.Version, pkgType),
			Status:   "pass",
		})
		result.PassCount++
	}

	result.TotalFindings = len(result.Findings)
	return result, nil
}

func parseSPDX(spdx *spdxDocument, result *IngestResult) (*IngestResult, error) {
	imageName := spdx.Name

	for _, pkg := range spdx.Packages {
		pkgType := ""
		for _, ref := range pkg.ExternalRefs {
			if ref.ReferenceType == "purl" {
				pkgType = detectPkgTypeFromPURL(ref.ReferenceLocator)
				break
			}
		}

		var licenses []string
		if pkg.LicenseConcluded != "" && pkg.LicenseConcluded != "NOASSERTION" {
			licenses = append(licenses, pkg.LicenseConcluded)
		}

		compType := "library"
		if pkg.PrimaryPackagePurpose != "" {
			compType = strings.ToLower(pkg.PrimaryPackagePurpose)
		}

		result.SBOMComponents = append(result.SBOMComponents, SBOMComponent{
			Name:     pkg.Name,
			Version:  pkg.VersionInfo,
			Type:     compType,
			PkgType:  pkgType,
			Licenses: licenses,
			PodName:  imageName,
		})

		result.Findings = append(result.Findings, ExternalFinding{
			Source:   SourceTrivySBOM,
			Category: "sbom",
			Severity: "info",
			Resource: imageName,
			RuleID:   "sbom-component",
			RuleName: "SBOM Component Inventory",
			Message:  fmt.Sprintf("%s@%s (%s)", pkg.Name, pkg.VersionInfo, pkgType),
			Status:   "pass",
		})
		result.PassCount++
	}

	result.TotalFindings = len(result.Findings)
	return result, nil
}

// detectPkgTypeFromPURL extracts the package type from a Package URL
// e.g., "pkg:npm/express@4.18.2" → "npm"
func detectPkgTypeFromPURL(purl string) string {
	if purl == "" {
		return ""
	}
	// Format: pkg:<type>/<namespace>/<name>@<version>
	purl = strings.TrimPrefix(purl, "pkg:")
	idx := strings.Index(purl, "/")
	if idx > 0 {
		return purl[:idx]
	}
	return ""
}
