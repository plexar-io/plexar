package types

import "time"

// ScanResult is the complete output of a Plexar scan
type ScanResult struct {
	ClusterName     string             `json:"clusterName"`
	Namespace       string             `json:"namespace"`
	ScanTime        time.Time          `json:"scanTime"`
	TotalPods       int                `json:"totalPods"`
	ClusterScore    int                `json:"clusterScore"`
	NetworkPolicies int                `json:"networkPolicies"`
	PodPrefix       string             `json:"podPrefix,omitempty"`
	Scores          []PlexarScore      `json:"scores"`
	Warnings        []string           `json:"warnings,omitempty"`
	Compliance      []ComplianceResult `json:"compliance,omitempty"`
	RBACFindings    []RBACFinding      `json:"rbacFindings,omitempty"`
	HubbleAvailable bool               `json:"hubbleAvailable,omitempty"`
	FlowSource      string             `json:"flowSource,omitempty"` // "hubble" or "inferred"
}

// PlexarScore is the composite risk score for a single pod
type PlexarScore struct {
	PodName          string            `json:"podName"`
	Namespace        string            `json:"namespace"`
	ImageName        string            `json:"imageName"`
	Total            int               `json:"total"`
	Tier             string            `json:"tier"`
	CVEScore         int               `json:"cveScore"`
	BlastScore       int               `json:"blastScore"`
	PermScore        int               `json:"permScore"`
	PolicyGapScore   int               `json:"policyGapScore"`
	SensitivityScore int               `json:"sensitivityScore"`
	WorkloadClass    string            `json:"workloadClass,omitempty"`
	RiskMultiplier   float64           `json:"riskMultiplier,omitempty"`
	BaseScore        int               `json:"baseScore,omitempty"`
	Vulns            VulnSummary       `json:"vulns"`
	Blast            BlastRadius       `json:"blast"`
	Permissions      PodPermissions    `json:"permissions"`
	Recommendations  []Recommendation  `json:"recommendations,omitempty"`
	Roast            string            `json:"roast,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
}

// VulnSummary aggregates vulnerability data for a pod
type VulnSummary struct {
	Critical     int       `json:"critical"`
	High         int       `json:"high"`
	Medium       int       `json:"medium"`
	Low          int       `json:"low"`
	TotalCount   int       `json:"totalCount"`
	FixableCount int       `json:"fixableCount"`
	TopCVEs      []CVEInfo `json:"topCVEs,omitempty"`
	PodName      string    `json:"podName"`
	ImageName    string    `json:"imageName"`
}

// CVEInfo represents a single CVE finding
type CVEInfo struct {
	ID               string  `json:"id"`
	Severity         string  `json:"severity"`
	CVSS             float64 `json:"cvss"`
	Package          string  `json:"package"`
	InstalledVersion string  `json:"installedVersion"`
	FixedVersion     string  `json:"fixedVersion,omitempty"`
	PublishedDate    string  `json:"publishedDate,omitempty"`
	Description      string  `json:"description,omitempty"`
	ExploitType      string  `json:"exploitType,omitempty"` // ssrf, rce, deserialization, sqli, path_traversal, auth_bypass, lfi, info_disclosure
	InUse            bool    `json:"inUse"`
	Confidence       float64 `json:"confidence,omitempty"` // 1.0=exact, 0.7=fuzzy, 0.5=conservative
}

// ObservedFlow represents a single observed network flow from Hubble
type ObservedFlow struct {
	SrcPod       string    `json:"srcPod"`
	DstPod       string    `json:"dstPod"`
	DstIP        string    `json:"dstIp,omitempty"`
	Port         uint32    `json:"port"`
	Protocol     string    `json:"protocol"`             // TCP, UDP
	L7Protocol   string    `json:"l7Protocol,omitempty"` // HTTP, gRPC, DNS
	L7Info       string    `json:"l7Info,omitempty"`     // HTTP method+path, gRPC service, DNS query
	ByteCount    uint64    `json:"byteCount"`
	RequestCount uint64    `json:"requestCount"`
	LastSeen     time.Time `json:"lastSeen"`
	Verdict      string    `json:"verdict"` // FORWARDED, DROPPED
}

// FlowSummary aggregates observed flows between a pod pair
type FlowSummary struct {
	SrcPod      string    `json:"srcPod"`
	DstPod      string    `json:"dstPod"`
	TotalBytes  uint64    `json:"totalBytes"`
	TotalReqs   uint64    `json:"totalReqs"`
	Ports       []uint32  `json:"ports"`
	L7Protocols []string  `json:"l7Protocols,omitempty"`
	LastSeen    time.Time `json:"lastSeen"`
}

// BlastRadius describes what a pod can reach if compromised
type BlastRadius struct {
	PodName            string         `json:"podName"`
	ReachableTargets   []string       `json:"reachableTargets"`
	ConfiguredTargets  []string       `json:"configuredTargets"`
	HasNetworkPolicy   bool           `json:"hasNetworkPolicy"`
	UnrestrictedEgress bool           `json:"unrestrictedEgress"`
	InternetAccess     bool           `json:"internetAccess"`
	DataStoreAccess    []string       `json:"dataStoreAccess,omitempty"`
	ObservedFlows      []ObservedFlow `json:"observedFlows,omitempty"`
}

// PodPermissions captures security context and RBAC signals
type PodPermissions struct {
	PodName            string   `json:"podName"`
	RunAsRoot          bool     `json:"runAsRoot"`
	Privileged         bool     `json:"privileged"`
	ReadOnlyRootFS     bool     `json:"readOnlyRootFS"`
	HostNetwork        bool     `json:"hostNetwork"`
	AllowPrivilegeEsc  bool     `json:"allowPrivilegeEsc"`
	EnvSecrets         []string `json:"envSecrets,omitempty"`
	ServiceAccountName string   `json:"serviceAccountName"`
}

// Recommendation is an actionable fix suggestion
type Recommendation struct {
	Priority    string `json:"priority"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
}

// ComplianceResult maps scan findings to a compliance framework
type ComplianceResult struct {
	Framework   string            `json:"framework"`
	Version     string            `json:"version"`
	Score       int               `json:"score"`
	TotalChecks int               `json:"totalChecks"`
	Passing     int               `json:"passing"`
	Controls    []ComplianceCheck `json:"controls"`
}

// ComplianceCheck is a single control within a framework
type ComplianceCheck struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Status        string   `json:"status"`
	Score         int      `json:"score"`
	Violations    int      `json:"violations"`
	Evidence      string   `json:"evidence,omitempty"`
	EvidenceItems []string `json:"evidenceItems,omitempty"`
	Findings      []string `json:"findings,omitempty"`
	Remediation   string   `json:"remediation,omitempty"`
}

// AlertRule defines when to fire an alert
type AlertRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Condition   string `json:"condition"`
	Threshold   int    `json:"threshold,omitempty"`
}

// AlertEvent is a triggered alert
type AlertEvent struct {
	RuleID      string    `json:"ruleId"`
	RuleName    string    `json:"ruleName"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
	PodName     string    `json:"podName,omitempty"`
	ScoreDelta  int       `json:"scoreDelta,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
}

// HistorySnapshot is a point-in-time scan result for trending
type HistorySnapshot struct {
	Timestamp       time.Time `json:"timestamp"`
	ClusterScore    int       `json:"clusterScore"`
	TotalPods       int       `json:"totalPods"`
	CriticalPods    int       `json:"criticalPods"`
	HighPods        int       `json:"highPods"`
	UnprotectedPods int       `json:"unprotectedPods"`
	CriticalCVEs    int       `json:"criticalCVEs"`
	ComplianceScore int       `json:"complianceScore,omitempty"`
}

// DriftEvent represents a compliance regression or improvement between scans
type DriftEvent struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	Category     string    `json:"category"` // control_regression, control_recovery, score_increase, pods_unprotected, netpol_removed, cve_spike
	Severity     string    `json:"severity"` // critical, high, medium, low, info
	Framework    string    `json:"framework,omitempty"`
	ControlID    string    `json:"controlId,omitempty"`
	ControlName  string    `json:"controlName,omitempty"`
	PrevStatus   string    `json:"prevStatus,omitempty"`
	NewStatus    string    `json:"newStatus,omitempty"`
	PrevValue    int       `json:"prevValue,omitempty"`
	NewValue     int       `json:"newValue,omitempty"`
	Message      string    `json:"message"`
	RecordID     string    `json:"recordId"`
	PrevRecordID string    `json:"prevRecordId"`
}

// EvidenceRecord is an immutable, hash-chained compliance evidence snapshot
type EvidenceRecord struct {
	ID              string            `json:"id"`
	Timestamp       time.Time         `json:"timestamp"`
	ClusterName     string            `json:"clusterName"`
	Namespace       string            `json:"namespace"`
	ClusterScore    int               `json:"clusterScore"`
	TotalPods       int               `json:"totalPods"`
	NetworkPolicies int               `json:"networkPolicies"`
	Controls        []ControlEvidence `json:"controls"`
	Summary         EvidenceSummary   `json:"summary"`
	PrevHash        string            `json:"prevHash"`
	Hash            string            `json:"hash"`
}

// ControlEvidence captures a single compliance control observation
type ControlEvidence struct {
	Framework   string `json:"framework"`
	ControlID   string `json:"controlId"`
	ControlName string `json:"controlName"`
	Status      string `json:"status"`
	Violations  int    `json:"violations"`
	Evidence    string `json:"evidence"`
}

// EvidenceSummary captures aggregate risk metrics at a point in time
type EvidenceSummary struct {
	CriticalPods    int `json:"criticalPods"`
	HighPods        int `json:"highPods"`
	UnprotectedPods int `json:"unprotectedPods"`
	CriticalCVEs    int `json:"criticalCVEs"`
	HighCVEs        int `json:"highCVEs"`
	InternetExposed int `json:"internetExposed"`
	ComplianceScore int `json:"complianceScore"`
}

// RBACFinding is the RBAC audit result for a single pod
type RBACFinding struct {
	PodName            string           `json:"podName"`
	Namespace          string           `json:"namespace"`
	ServiceAccountName string           `json:"serviceAccountName"`
	RiskScore          int              `json:"riskScore"`
	RiskLevel          string           `json:"riskLevel"`
	HasClusterAdmin    bool             `json:"hasClusterAdmin"`
	HasWildcardAccess  bool             `json:"hasWildcardAccess"`
	HasExecCapability  bool             `json:"hasExecCapability"`
	HasSecretAccess    bool             `json:"hasSecretAccess"`
	HasDeleteAccess    bool             `json:"hasDeleteAccess"`
	HasCreatePods      bool             `json:"hasCreatePods"`
	HasDaemonSetAccess bool             `json:"hasDaemonSetAccess"`
	HasNodeAccess      bool             `json:"hasNodeAccess"`
	HasEscalatePriv    bool             `json:"hasEscalatePriv"`
	Roles              []RBACRoleRef    `json:"roles"`
	Flags              []string         `json:"flags"`
	Permissions        []RBACPermission `json:"permissions"`
}

// RBACRoleRef links a pod to a role via a binding
type RBACRoleRef struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Namespace   string `json:"namespace,omitempty"`
	BindingName string `json:"bindingName"`
	BindingKind string `json:"bindingKind"`
}

// RBACPermission is a single permission rule with risk assessment
type RBACPermission struct {
	APIGroup  string   `json:"apiGroup"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
	RiskLevel string   `json:"riskLevel"`
}

// RBACAuditResult is the full RBAC audit for a namespace
type RBACAuditResult struct {
	Namespace     string        `json:"namespace"`
	TotalPods     int           `json:"totalPods"`
	CriticalCount int           `json:"criticalCount"`
	HighCount     int           `json:"highCount"`
	Findings      []RBACFinding `json:"findings"`
}

// RuntimeProfile captures which libraries/packages are loaded at runtime for a pod
type RuntimeProfile struct {
	PodName        string   `json:"podName"`
	Namespace      string   `json:"namespace"`
	ContainerID    string   `json:"containerId,omitempty"`
	LoadedLibs     []string `json:"loadedLibs"`
	OpenFiles      []string `json:"openFiles"`
	LoadedPackages []string `json:"loadedPackages"`
	BinaryLangs    []string `json:"binaryLangs,omitempty"` // detected languages for static binaries (go, rust)
	Fallback       bool     `json:"fallback,omitempty"`    // true if /proc was not accessible
}

// RuntimeInsights aggregates "in use" intelligence across a scan
type RuntimeInsights struct {
	TotalCVEs      int              `json:"totalCves"`
	InUseCVEs      int              `json:"inUseCves"`
	NoiseReduction float64          `json:"noiseReduction"`
	Profiles       []RuntimeProfile `json:"profiles"`
	PodInUseMap    map[string]int   `json:"podInUseMap,omitempty"`
}

// AttackPath represents an exploitable chain through the cluster
type AttackPath struct {
	ID            string           `json:"id"`
	Severity      string           `json:"severity"`
	Score         float64          `json:"score"`
	Description   string           `json:"description"`
	Nodes         []AttackPathNode `json:"nodes"`
	Edges         []AttackPathEdge `json:"edges"`
	EntryPoint    string           `json:"entryPoint"`
	Target        string           `json:"target"`
	HopCount      int              `json:"hopCount"`
	RiskReduction string           `json:"riskReduction,omitempty"` // e.g. "Fixing this drops severity from Critical to Medium"
}

// AttackPathNode is a vertex in the attack graph
type AttackPathNode struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"` // pod, role, secret, internet, cluster-admin
	Label    string            `json:"label"`
	Risk     int               `json:"risk"`
	Metadata map[string]string `json:"metadata,omitempty"`
	CVEs     []CVEInfo         `json:"cves,omitempty"`
	IsAgent  bool              `json:"isAgent,omitempty"`
}

// AttackPathEdge is an edge in the attack graph
type AttackPathEdge struct {
	From        string `json:"from"`
	To          string `json:"to"`
	AttackType  string `json:"attackType"` // network_reach, rbac_escalate, secret_access, container_escape, exec_into
	Description string `json:"description"`
	Weight      int    `json:"weight"`                // lower = easier to exploit
	Remediation string `json:"remediation,omitempty"` // suggested fix for this edge
}

// AttackPathSummary is the top-level attack path analysis result
type AttackPathSummary struct {
	TotalPaths     int                  `json:"totalPaths"`
	CriticalPaths  int                  `json:"criticalPaths"`
	ShortestHops   int                  `json:"shortestHops"`
	MostExposedPod string               `json:"mostExposedPod"`
	Paths          []AttackPath         `json:"paths"`
	ExploitChains  []ExploitChain       `json:"exploitChains,omitempty"`
	ChainSummary   *ExploitChainSummary `json:"chainSummary,omitempty"`
}

// ExploitChain represents a CVE-type-aware exploit chain through the cluster
type ExploitChain struct {
	ID            string        `json:"id"`
	ChainScore    float64       `json:"chainScore"`
	CompositeRisk float64       `json:"compositeRisk"`
	Severity      string        `json:"severity"`
	Description   string        `json:"description"`
	Hops          []ChainHop    `json:"hops"`
	BreakFix      BreakChainFix `json:"breakFix"`
	DataTarget    string        `json:"dataTarget,omitempty"`
	EntryPoint    string        `json:"entryPoint"`
	FinalTarget   string        `json:"finalTarget"`
	HopCount      int           `json:"hopCount"`
	HasAgentNode  bool          `json:"hasAgentNode,omitempty"`
	AgentNodes    []string      `json:"agentNodes,omitempty"`
}

// ChainHop represents a single hop in an exploit chain
type ChainHop struct {
	PodName          string  `json:"podName"`
	NodeID           string  `json:"nodeId"`
	CVE              CVEInfo `json:"cve"`
	ExploitType      string  `json:"exploitType"`
	TransitionReason string  `json:"transitionReason"`
}

// BreakChainFix identifies the single fix that eliminates the most chains
type BreakChainFix struct {
	CVEID            string `json:"cveId"`
	PodName          string `json:"podName"`
	ChainsEliminated int    `json:"chainsEliminated"`
	Recommendation   string `json:"recommendation"`
}

// ExploitChainSummary aggregates exploit chain analysis results
type ExploitChainSummary struct {
	TotalChains        int           `json:"totalChains"`
	CriticalChains     int           `json:"criticalChains"`
	AgentChains        int           `json:"agentChains"`
	TopBreakFix        BreakChainFix `json:"topBreakFix"`
	UniqueExploitTypes []string      `json:"uniqueExploitTypes"`
}

// LicenseInfo describes the enterprise license
type LicenseInfo struct {
	Organization string    `json:"organization"`
	Edition      string    `json:"edition"`
	MaxClusters  int       `json:"maxClusters"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Features     []string  `json:"features"`
}
