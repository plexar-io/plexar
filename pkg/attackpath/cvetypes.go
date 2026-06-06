package attackpath

import (
	"strings"

	"github.com/plexar-io/plexar/internal/types"
)

// Exploit type constants used for CVE-type-aware chain traversal
const (
	ExploitSSRF            = "ssrf"
	ExploitRCE             = "rce"
	ExploitDeserialization = "deserialization"
	ExploitSQLi            = "sqli"
	ExploitPathTraversal   = "path_traversal"
	ExploitAuthBypass      = "auth_bypass"
	ExploitLFI             = "lfi"
	ExploitInfoDisclosure  = "info_disclosure"
	ExploitUnknown         = "unknown"
)

// exploitTypeKeywords maps exploit types to keywords found in CVE descriptions
var exploitTypeKeywords = map[string][]string{
	ExploitSSRF: {
		"server-side request forgery", "ssrf", "server side request forgery",
		"url redirect", "open redirect", "request forgery",
	},
	ExploitRCE: {
		"remote code execution", "rce", "arbitrary code execution",
		"code injection", "command injection", "os command injection",
		"arbitrary command", "execute arbitrary", "code execution",
		"shell injection", "eval injection",
	},
	ExploitDeserialization: {
		"deserialization", "deserialize", "insecure deserialization",
		"object injection", "pickle", "yaml.load", "unmarshall",
		"java deserialization", "unsafe deserialization",
	},
	ExploitSQLi: {
		"sql injection", "sqli", "sql command", "blind sql",
		"second-order sql", "sql syntax",
	},
	ExploitPathTraversal: {
		"path traversal", "directory traversal", "dot-dot-slash",
		"../", "file path manipulation", "zip slip",
	},
	ExploitAuthBypass: {
		"authentication bypass", "auth bypass", "authorization bypass",
		"privilege escalation", "broken authentication",
		"access control bypass", "security bypass",
		"improper authentication", "missing authentication",
	},
	ExploitLFI: {
		"local file inclusion", "lfi", "file inclusion",
		"arbitrary file read", "file read vulnerability",
		"sensitive file", "file disclosure",
	},
	ExploitInfoDisclosure: {
		"information disclosure", "information leak", "sensitive data exposure",
		"data leak", "credential leak", "token leak",
		"memory leak", "heap dump", "stack trace exposure",
	},
}

// knownCVETypes maps specific well-known CVE IDs to their exploit type
var knownCVETypes = map[string]string{
	// Log4Shell — RCE via JNDI
	"CVE-2021-44228": ExploitRCE,
	"CVE-2021-45046": ExploitRCE,
	"CVE-2021-45105": ExploitRCE,
	// Spring4Shell — RCE
	"CVE-2022-22965": ExploitRCE,
	// Apache Struts — RCE
	"CVE-2017-5638":  ExploitRCE,
	// ProxyShell / ProxyLogon — SSRF + RCE
	"CVE-2021-26855": ExploitSSRF,
	"CVE-2021-27065": ExploitRCE,
	// Jackson deserialization
	"CVE-2019-12384": ExploitDeserialization,
	"CVE-2017-7525":  ExploitDeserialization,
	// SnakeYAML deserialization
	"CVE-2022-1471":  ExploitDeserialization,
	// SQLi examples
	"CVE-2019-3396":  ExploitPathTraversal,
	// ImageTragick — RCE
	"CVE-2016-3714":  ExploitRCE,
	// Heartbleed — info disclosure
	"CVE-2014-0160":  ExploitInfoDisclosure,
	// Shellshock — RCE
	"CVE-2014-6271":  ExploitRCE,
	// Text4Shell — RCE
	"CVE-2022-42889": ExploitRCE,
	// curl SOCKS5 heap buffer overflow
	"CVE-2023-38545": ExploitRCE,
	// MOVEit SQLi
	"CVE-2023-34362": ExploitSQLi,
}

// ClassifyCVE determines the exploit type of a CVE based on its ID and description
func ClassifyCVE(cve types.CVEInfo) string {
	// Check known CVE mappings first
	if t, ok := knownCVETypes[cve.ID]; ok {
		return t
	}

	// Keyword match on description
	desc := strings.ToLower(cve.Description)
	if desc == "" {
		// Try the package name as a weak signal
		desc = strings.ToLower(cve.Package)
	}

	if desc == "" {
		return ExploitUnknown
	}

	for exploitType, keywords := range exploitTypeKeywords {
		for _, kw := range keywords {
			if strings.Contains(desc, kw) {
				return exploitType
			}
		}
	}

	return ExploitUnknown
}

// ClassifyCVEs classifies all CVEs in a list and sets their ExploitType field
func ClassifyCVEs(cves []types.CVEInfo) []types.CVEInfo {
	result := make([]types.CVEInfo, len(cves))
	for i, cve := range cves {
		cve.ExploitType = ClassifyCVE(cve)
		result[i] = cve
	}
	return result
}

// exploitTypeEnablesTransition returns true if the given exploit type can enable
// lateral movement or privilege escalation in an attack chain.
// SSRF and RCE enable pivoting to other services.
// Auth bypass enables privilege escalation.
// Deserialization enables code execution on the target.
// SQLi enables data access.
// Path traversal and LFI enable credential/config theft.
func exploitTypeEnablesTransition(exploitType string, edgeType string) bool {
	switch edgeType {
	case "network_reach":
		// Lateral movement requires SSRF, RCE, or deserialization
		return exploitType == ExploitSSRF ||
			exploitType == ExploitRCE ||
			exploitType == ExploitDeserialization
	case "rbac_escalate":
		// Privilege escalation requires auth bypass, RCE, or deserialization
		return exploitType == ExploitAuthBypass ||
			exploitType == ExploitRCE ||
			exploitType == ExploitDeserialization
	case "secret_access":
		// Secret access requires RCE, path traversal, LFI, SQLi, or info disclosure
		return exploitType == ExploitRCE ||
			exploitType == ExploitPathTraversal ||
			exploitType == ExploitLFI ||
			exploitType == ExploitSQLi ||
			exploitType == ExploitInfoDisclosure
	case "container_escape":
		// Container escape requires RCE
		return exploitType == ExploitRCE
	case "exec_into":
		// Exec into requires RCE or auth bypass
		return exploitType == ExploitRCE ||
			exploitType == ExploitAuthBypass
	}
	// Unknown edge type — allow any exploit
	return exploitType != ExploitUnknown
}
