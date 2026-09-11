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
	"CVE-2017-5638": ExploitRCE,
	// ProxyShell / ProxyLogon — SSRF + RCE
	"CVE-2021-26855": ExploitSSRF,
	"CVE-2021-27065": ExploitRCE,
	// Jackson deserialization
	"CVE-2019-12384": ExploitDeserialization,
	"CVE-2017-7525":  ExploitDeserialization,
	// SnakeYAML deserialization
	"CVE-2022-1471": ExploitDeserialization,
	// SQLi examples
	"CVE-2019-3396": ExploitPathTraversal,
	// ImageTragick — RCE
	"CVE-2016-3714": ExploitRCE,
	// Heartbleed — info disclosure
	"CVE-2014-0160": ExploitInfoDisclosure,
	// Shellshock — RCE
	"CVE-2014-6271": ExploitRCE,
	// Text4Shell — RCE
	"CVE-2022-42889": ExploitRCE,
	// curl SOCKS5 heap buffer overflow
	"CVE-2023-38545": ExploitRCE,
	// MOVEit SQLi
	"CVE-2023-34362": ExploitSQLi,
}

// ClassifyCVE determines the exploit type of a CVE based on its ID, package,
// CVSS score, and description. When Trivy output lacks descriptions, we use
// package-aware heuristics to infer likely exploit types.
func ClassifyCVE(cve types.CVEInfo) string {
	// Check known CVE mappings first
	if t, ok := knownCVETypes[cve.ID]; ok {
		return t
	}

	// Keyword match on description (if available)
	desc := strings.ToLower(cve.Description)
	if desc != "" {
		for exploitType, keywords := range exploitTypeKeywords {
			for _, kw := range keywords {
				if strings.Contains(desc, kw) {
					return exploitType
				}
			}
		}
	}

	// Package-aware heuristics when descriptions are unavailable
	pkg := strings.ToLower(cve.Package)
	if t := classifyByPackage(pkg, cve.CVSS); t != ExploitUnknown {
		return t
	}

	// High-CVSS fallback: CVSS >= 9.5 with no other signal → likely RCE
	if cve.CVSS >= 9.5 {
		return ExploitRCE
	}

	return ExploitUnknown
}

// classifyByPackage infers exploit type from the package name and CVSS score.
// This covers the common case where Trivy output lacks CVE descriptions.
func classifyByPackage(pkg string, cvss float64) string {
	// Go stdlib critical CVEs are almost always RCE (net/http, html/template, etc.)
	if pkg == "stdlib" && cvss >= 9.0 {
		return ExploitRCE
	}

	// Container runtime packages → container escape / RCE
	for _, runtime := range []string{"runc", "containerd", "cri-o", "docker"} {
		if strings.Contains(pkg, runtime) {
			if cvss >= 7.0 {
				return ExploitRCE
			}
		}
	}

	// Crypto/TLS libraries → auth bypass at high CVSS, info disclosure otherwise
	for _, crypto := range []string{"openssl", "libssl", "libcrypto", "golang.org/x/crypto", "cryptography"} {
		if strings.Contains(pkg, crypto) {
			if cvss >= 9.0 {
				return ExploitAuthBypass
			}
			if cvss >= 7.0 {
				return ExploitInfoDisclosure
			}
		}
	}

	// Database drivers → SQLi
	for _, db := range []string{"pgx", "mysql", "sqlite", "mongo-driver", "go-mssqldb"} {
		if strings.Contains(pkg, db) && cvss >= 8.0 {
			return ExploitSQLi
		}
	}

	// Auth/identity packages → auth bypass
	for _, auth := range []string{"auth", "oidc", "oauth", "jwt", "saml", "ldap", "kerberos"} {
		if strings.Contains(pkg, auth) && cvss >= 7.0 {
			return ExploitAuthBypass
		}
	}

	// gRPC / HTTP frameworks → SSRF or RCE
	for _, net := range []string{"grpc", "aiohttp", "requests", "urllib"} {
		if strings.Contains(pkg, net) && cvss >= 8.0 {
			return ExploitSSRF
		}
	}

	// Serialization libraries → deserialization
	for _, ser := range []string{"msgpack", "protobuf", "cbor", "yaml", "pickle", "jackson"} {
		if strings.Contains(pkg, ser) && cvss >= 7.0 {
			return ExploitDeserialization
		}
	}

	// OpenAPI / API frameworks with high CVSS → auth bypass (validation bypass)
	for _, api := range []string{"openapi", "kin-openapi", "swagger"} {
		if strings.Contains(pkg, api) && cvss >= 8.0 {
			return ExploitAuthBypass
		}
	}

	// etcd → RCE (cluster state store)
	if strings.Contains(pkg, "etcd") && cvss >= 8.0 {
		return ExploitRCE
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
