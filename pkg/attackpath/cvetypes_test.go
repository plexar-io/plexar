package attackpath

import (
	"testing"

	"github.com/plexar-io/plexar/internal/types"
)

func TestClassifyCVE_KnownID(t *testing.T) {
	cve := types.CVEInfo{ID: "CVE-2021-44228", Description: "Apache Log4j2"}
	result := ClassifyCVE(cve)
	if result != ExploitRCE {
		t.Errorf("Expected %s for Log4Shell, got %s", ExploitRCE, result)
	}
}

func TestClassifyCVE_DescriptionMatch(t *testing.T) {
	tests := []struct {
		name     string
		cve      types.CVEInfo
		expected string
	}{
		{
			name:     "SSRF description",
			cve:      types.CVEInfo{ID: "CVE-2099-0001", Description: "A server-side request forgery vulnerability allows..."},
			expected: ExploitSSRF,
		},
		{
			name:     "RCE description",
			cve:      types.CVEInfo{ID: "CVE-2099-0002", Description: "Remote code execution via crafted input"},
			expected: ExploitRCE,
		},
		{
			name:     "Deserialization description",
			cve:      types.CVEInfo{ID: "CVE-2099-0003", Description: "Insecure deserialization in YAML processing"},
			expected: ExploitDeserialization,
		},
		{
			name:     "SQLi description",
			cve:      types.CVEInfo{ID: "CVE-2099-0004", Description: "SQL injection in user search endpoint"},
			expected: ExploitSQLi,
		},
		{
			name:     "Path traversal description",
			cve:      types.CVEInfo{ID: "CVE-2099-0005", Description: "Directory traversal in file upload handler"},
			expected: ExploitPathTraversal,
		},
		{
			name:     "Auth bypass description",
			cve:      types.CVEInfo{ID: "CVE-2099-0006", Description: "Authentication bypass in admin panel"},
			expected: ExploitAuthBypass,
		},
		{
			name:     "LFI description",
			cve:      types.CVEInfo{ID: "CVE-2099-0007", Description: "Local file inclusion via template parameter"},
			expected: ExploitLFI,
		},
		{
			name:     "Info disclosure description",
			cve:      types.CVEInfo{ID: "CVE-2099-0008", Description: "Information disclosure in error response"},
			expected: ExploitInfoDisclosure,
		},
		{
			name:     "Unknown description",
			cve:      types.CVEInfo{ID: "CVE-2099-9999", Description: "A vulnerability exists in version 2.3"},
			expected: ExploitUnknown,
		},
		{
			name:     "Empty description",
			cve:      types.CVEInfo{ID: "CVE-2099-0000"},
			expected: ExploitUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyCVE(tt.cve)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestClassifyCVEs(t *testing.T) {
	cves := []types.CVEInfo{
		{ID: "CVE-2021-44228", Description: "Log4Shell"},
		{ID: "CVE-2099-0001", Description: "Server-side request forgery in proxy"},
	}

	result := ClassifyCVEs(cves)
	if len(result) != 2 {
		t.Fatalf("Expected 2 CVEs, got %d", len(result))
	}
	if result[0].ExploitType != ExploitRCE {
		t.Errorf("Expected %s for CVE-2021-44228, got %s", ExploitRCE, result[0].ExploitType)
	}
	if result[1].ExploitType != ExploitSSRF {
		t.Errorf("Expected %s for SSRF CVE, got %s", ExploitSSRF, result[1].ExploitType)
	}
}

func TestExploitTypeEnablesTransition(t *testing.T) {
	tests := []struct {
		exploitType string
		edgeType    string
		expected    bool
	}{
		{ExploitSSRF, "network_reach", true},
		{ExploitRCE, "network_reach", true},
		{ExploitSQLi, "network_reach", false},
		{ExploitRCE, "container_escape", true},
		{ExploitSSRF, "container_escape", false},
		{ExploitAuthBypass, "rbac_escalate", true},
		{ExploitRCE, "secret_access", true},
		{ExploitPathTraversal, "secret_access", true},
		{ExploitInfoDisclosure, "secret_access", true},
		{ExploitUnknown, "network_reach", false},
	}

	for _, tt := range tests {
		name := tt.exploitType + "->" + tt.edgeType
		t.Run(name, func(t *testing.T) {
			result := exploitTypeEnablesTransition(tt.exploitType, tt.edgeType)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
