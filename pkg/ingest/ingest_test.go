package ingest

import (
	"strings"
	"testing"
)

// ── Sample Kubescape JSON ──

var sampleKubescapeJSON = `{
	"summaryDetails": {
		"frameworks": [{"name": "NSA", "score": 42.5}]
	},
	"results": [
		{
			"controlID": "C-0057",
			"name": "Privileged container",
			"status": {"status": "failed"},
			"rules": [{"name": "privileged-container", "description": "Detect privileged", "remediation": "Remove privileged: true"}],
			"resourceResults": [
				{"resourceID": "v1/Pod/production/payment-service-abc123", "controls": []},
				{"resourceID": "v1/Pod/production/search-service-def456", "controls": []}
			]
		},
		{
			"controlID": "C-0013",
			"name": "Non-root containers",
			"status": {"status": "passed"},
			"rules": [{"name": "non-root", "description": "Check non-root", "remediation": "Set runAsNonRoot: true"}],
			"resourceResults": [
				{"resourceID": "v1/Pod/production/inventory-service-ghi789", "controls": []}
			]
		}
	]
}`

func TestIngestKubescape(t *testing.T) {
	result, err := Ingest(SourceKubescape, strings.NewReader(sampleKubescapeJSON))
	if err != nil {
		t.Fatalf("Ingest kubescape failed: %v", err)
	}

	if result.Source != SourceKubescape {
		t.Errorf("expected source %q, got %q", SourceKubescape, result.Source)
	}

	if result.TotalFindings != 3 {
		t.Errorf("expected 3 findings, got %d", result.TotalFindings)
	}

	if result.FailCount != 2 {
		t.Errorf("expected 2 fails, got %d", result.FailCount)
	}

	if result.PassCount != 1 {
		t.Errorf("expected 1 pass, got %d", result.PassCount)
	}

	// Verify severity mapping
	for _, f := range result.Findings {
		if f.RuleID == "C-0057" && f.Severity != "critical" {
			t.Errorf("expected C-0057 severity critical, got %q", f.Severity)
		}
	}
}

// ── Sample Kyverno PolicyReport JSON ──

var sampleKyvernoJSON = `{
	"items": [
		{
			"metadata": {"name": "polr-production", "namespace": "production"},
			"summary": {"pass": 2, "fail": 1, "warn": 0, "error": 0, "skip": 0},
			"results": [
				{
					"policy": "disallow-privileged",
					"rule": "check-privileged",
					"result": "fail",
					"message": "Privileged containers are not allowed",
					"severity": "critical",
					"category": "Pod Security",
					"scored": true,
					"resources": [{"apiVersion": "v1", "kind": "Pod", "name": "payment-service-abc", "namespace": "production"}]
				},
				{
					"policy": "require-run-as-nonroot",
					"rule": "check-nonroot",
					"result": "pass",
					"message": "Container runs as non-root",
					"severity": "high",
					"category": "Pod Security",
					"scored": true,
					"resources": [{"apiVersion": "v1", "kind": "Pod", "name": "inventory-service-def", "namespace": "production"}]
				},
				{
					"policy": "require-resource-limits",
					"rule": "check-limits",
					"result": "pass",
					"message": "Resource limits are set",
					"severity": "medium",
					"category": "Best Practices",
					"scored": true,
					"resources": [{"apiVersion": "v1", "kind": "Pod", "name": "order-service-ghi", "namespace": "production"}]
				}
			]
		}
	]
}`

func TestIngestKyverno(t *testing.T) {
	result, err := Ingest(SourceKyverno, strings.NewReader(sampleKyvernoJSON))
	if err != nil {
		t.Fatalf("Ingest kyverno failed: %v", err)
	}

	if result.Source != SourceKyverno {
		t.Errorf("expected source %q, got %q", SourceKyverno, result.Source)
	}

	if result.TotalFindings != 3 {
		t.Errorf("expected 3 findings, got %d", result.TotalFindings)
	}

	if result.FailCount != 1 {
		t.Errorf("expected 1 fail, got %d", result.FailCount)
	}

	if result.PassCount != 2 {
		t.Errorf("expected 2 pass, got %d", result.PassCount)
	}

	// Verify ComplianceChecks generated
	if len(result.ComplianceChecks) == 0 {
		t.Error("expected ComplianceChecks to be generated")
	}

	// Check that the failed policy has violations
	for _, cc := range result.ComplianceChecks {
		if cc.ID == "disallow-privileged/check-privileged" {
			if cc.Violations != 1 {
				t.Errorf("expected 1 violation for disallow-privileged, got %d", cc.Violations)
			}
			if cc.Status != "fail" {
				t.Errorf("expected status 'fail', got %q", cc.Status)
			}
		}
	}
}

// ── Sample CycloneDX SBOM JSON ──

var sampleCycloneDXJSON = `{
	"bomFormat": "CycloneDX",
	"specVersion": "1.5",
	"version": 1,
	"metadata": {
		"component": {"type": "container", "name": "nginx:1.21.6", "version": "1.21.6"}
	},
	"components": [
		{
			"type": "library",
			"name": "openssl",
			"version": "1.1.1k",
			"purl": "pkg:apk/alpine/openssl@1.1.1k",
			"licenses": [{"license": {"id": "Apache-2.0"}}]
		},
		{
			"type": "library",
			"name": "zlib",
			"version": "1.2.11",
			"purl": "pkg:apk/alpine/zlib@1.2.11",
			"licenses": [{"license": {"name": "Zlib"}}]
		},
		{
			"type": "library",
			"name": "express",
			"version": "4.18.2",
			"purl": "pkg:npm/express@4.18.2",
			"licenses": [{"license": {"id": "MIT"}}]
		}
	]
}`

func TestIngestTrivySBOM(t *testing.T) {
	result, err := Ingest(SourceTrivySBOM, strings.NewReader(sampleCycloneDXJSON))
	if err != nil {
		t.Fatalf("Ingest trivy-sbom failed: %v", err)
	}

	if result.Source != SourceTrivySBOM {
		t.Errorf("expected source %q, got %q", SourceTrivySBOM, result.Source)
	}

	if len(result.SBOMComponents) != 3 {
		t.Errorf("expected 3 SBOM components, got %d", len(result.SBOMComponents))
	}

	// Check package type detection
	for _, comp := range result.SBOMComponents {
		switch comp.Name {
		case "openssl":
			if comp.PkgType != "apk" {
				t.Errorf("expected openssl pkgType 'apk', got %q", comp.PkgType)
			}
		case "express":
			if comp.PkgType != "npm" {
				t.Errorf("expected express pkgType 'npm', got %q", comp.PkgType)
			}
		}
	}

	// All findings should be "pass" (component exists in SBOM)
	if result.PassCount != 3 {
		t.Errorf("expected 3 pass, got %d", result.PassCount)
	}
}

// ── Sample SPDX SBOM JSON ──

var sampleSPDXJSON = `{
	"spdxVersion": "SPDX-2.3",
	"name": "python:3.8.12",
	"packages": [
		{
			"name": "pip",
			"versionInfo": "21.2.4",
			"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pip/pip@21.2.4"}],
			"licenseConcluded": "MIT",
			"primaryPackagePurpose": "LIBRARY"
		},
		{
			"name": "setuptools",
			"versionInfo": "58.1.0",
			"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pip/setuptools@58.1.0"}],
			"licenseConcluded": "MIT",
			"primaryPackagePurpose": "LIBRARY"
		}
	]
}`

func TestIngestSPDX(t *testing.T) {
	result, err := Ingest(SourceTrivySBOM, strings.NewReader(sampleSPDXJSON))
	if err != nil {
		t.Fatalf("Ingest SPDX failed: %v", err)
	}

	if len(result.SBOMComponents) != 2 {
		t.Errorf("expected 2 SBOM components, got %d", len(result.SBOMComponents))
	}

	for _, comp := range result.SBOMComponents {
		if comp.PkgType != "pip" {
			t.Errorf("expected pkgType 'pip', got %q for %s", comp.PkgType, comp.Name)
		}
	}
}

func TestIngestUnsupportedSource(t *testing.T) {
	_, err := Ingest("unknown", strings.NewReader("{}"))
	if err == nil {
		t.Error("expected error for unsupported source")
	}
}

func TestMergeFindings(t *testing.T) {
	findings := []ExternalFinding{
		{Source: "kubescape", RuleID: "C-0057", RuleName: "Privileged container", Status: "fail"},
		{Source: "kubescape", RuleID: "C-0057", RuleName: "Privileged container", Status: "fail"},
		{Source: "kubescape", RuleID: "C-0013", RuleName: "Non-root containers", Status: "pass"},
	}

	evidence := MergeFindings(findings)
	if len(evidence) != 2 {
		t.Errorf("expected 2 evidence entries, got %d", len(evidence))
	}

	for _, e := range evidence {
		if e.ControlID == "C-0057" && e.Violations != 2 {
			t.Errorf("expected 2 violations for C-0057, got %d", e.Violations)
		}
		if e.ControlID == "C-0013" && e.Status != "pass" {
			t.Errorf("expected pass for C-0013, got %q", e.Status)
		}
	}
}

func TestDetectPkgTypeFromPURL(t *testing.T) {
	tests := []struct {
		purl     string
		expected string
	}{
		{"pkg:npm/express@4.18.2", "npm"},
		{"pkg:pip/flask@2.0.1", "pip"},
		{"pkg:apk/alpine/openssl@1.1.1k", "apk"},
		{"pkg:gem/rails@7.0.0", "gem"},
		{"pkg:cargo/serde@1.0.0", "cargo"},
		{"pkg:golang/github.com/gin-gonic/gin@1.9.0", "golang"},
		{"", ""},
	}

	for _, tt := range tests {
		got := detectPkgTypeFromPURL(tt.purl)
		if got != tt.expected {
			t.Errorf("detectPkgTypeFromPURL(%q) = %q, want %q", tt.purl, got, tt.expected)
		}
	}
}
