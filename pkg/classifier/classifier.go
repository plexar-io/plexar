package classifier

import (
	"strings"

	"github.com/plexar-io/plexar/internal/types"
)

// WorkloadClass represents a classified workload type
type WorkloadClass struct {
	Name           string  // e.g. "database", "api-gateway", "cache"
	Label          string  // human-readable e.g. "Database", "API Gateway"
	RiskMultiplier float64 // 1.0 = neutral, >1.0 = higher risk, <1.0 = lower risk
	Reason         string  // why this classification was chosen
}

// classificationRule is a pattern-matching rule for workload classification
type classificationRule struct {
	class      WorkloadClass
	imageHints []string // substrings matched against image name
	nameHints  []string // substrings matched against pod/service name
	portHints  []int    // well-known ports
}

var rules = []classificationRule{
	{
		class: WorkloadClass{
			Name: "database", Label: "Database",
			RiskMultiplier: 1.4,
			Reason:         "Databases store persistent data; compromise leads to data exfiltration",
		},
		imageHints: []string{"postgres", "mysql", "mariadb", "mongodb", "mongo", "cockroach", "cassandra", "couchdb", "neo4j", "timescaledb", "percona", "oracle"},
		nameHints:  []string{"database", "db-", "-db", "datastore", "postgres", "mysql", "mongo"},
		portHints:  []int{5432, 3306, 27017, 9042, 7687},
	},
	{
		class: WorkloadClass{
			Name: "cache", Label: "Cache / In-Memory Store",
			RiskMultiplier: 1.25,
			Reason:         "Caches often hold session tokens, auth state, and hot data",
		},
		imageHints: []string{"redis", "memcached", "hazelcast", "dragonfly", "keydb", "valkey"},
		nameHints:  []string{"cache", "redis", "memcache", "session-store"},
		portHints:  []int{6379, 11211},
	},
	{
		class: WorkloadClass{
			Name: "message-queue", Label: "Message Queue",
			RiskMultiplier: 1.2,
			Reason:         "Message brokers carry inter-service data; compromise enables lateral eavesdropping",
		},
		imageHints: []string{"rabbitmq", "kafka", "nats", "pulsar", "activemq", "mosquitto", "redpanda"},
		nameHints:  []string{"queue", "broker", "mq-", "kafka", "rabbitmq", "nats", "messaging"},
		portHints:  []int{5672, 9092, 4222, 6650, 1883},
	},
	{
		class: WorkloadClass{
			Name: "search-engine", Label: "Search Engine",
			RiskMultiplier: 1.3,
			Reason:         "Search indices often contain copies of sensitive business data",
		},
		imageHints: []string{"elasticsearch", "opensearch", "solr", "meilisearch", "typesense"},
		nameHints:  []string{"search", "elastic", "solr", "index"},
		portHints:  []int{9200, 9300, 8983, 7700},
	},
	{
		class: WorkloadClass{
			Name: "auth-service", Label: "Authentication Service",
			RiskMultiplier: 1.5,
			Reason:         "Auth services control access; compromise enables full impersonation",
		},
		imageHints: []string{"keycloak", "dex", "oauth2-proxy", "authelia", "ory/hydra", "ory/kratos"},
		nameHints:  []string{"auth", "identity", "sso", "login", "oauth", "oidc", "keycloak", "iam"},
		portHints:  []int{},
	},
	{
		class: WorkloadClass{
			Name: "api-gateway", Label: "API Gateway / Ingress",
			RiskMultiplier: 1.3,
			Reason:         "API gateways are internet-facing entry points; compromise exposes all backend services",
		},
		imageHints: []string{"nginx", "envoy", "traefik", "kong", "haproxy", "apisix", "caddy", "istio"},
		nameHints:  []string{"gateway", "ingress", "proxy", "edge", "api-gw", "loadbalancer", "lb-"},
		portHints:  []int{80, 443, 8080, 8443},
	},
	{
		class: WorkloadClass{
			Name: "payment", Label: "Payment / Financial Service",
			RiskMultiplier: 1.5,
			Reason:         "Payment services handle financial transactions and PCI-scoped data",
		},
		imageHints: []string{"stripe", "braintree"},
		nameHints:  []string{"payment", "billing", "invoice", "checkout", "transaction", "finance", "ledger"},
		portHints:  []int{},
	},
	{
		class: WorkloadClass{
			Name: "ai-agent", Label: "AI Agent Runtime",
			RiskMultiplier: 1.55,
			Reason:         "AI agents have non-deterministic communication patterns; compromise enables tool abuse, data exfiltration via LLM, and unpredictable lateral movement",
		},
		imageHints: []string{"langchain", "crewai", "autogen", "kagent", "agentkit", "langgraph", "llamaindex", "semantic-kernel", "haystack", "agent-runtime"},
		nameHints:  []string{"agent", "crew", "orchestrator", "planner", "agentic", "autogen", "langchain"},
		portHints:  []int{},
	},
	{
		class: WorkloadClass{
			Name: "llm-inference", Label: "LLM Inference",
			RiskMultiplier: 1.50,
			Reason:         "LLM inference endpoints process untrusted prompts; compromise enables prompt injection, model theft, and data leakage",
		},
		imageHints: []string{"vllm", "tgi", "text-generation-inference", "llama-cpp", "llama.cpp", "ollama", "llm-d", "localai", "koboldai", "exllama", "lmdeploy"},
		nameHints:  []string{"llm", "inference", "completion", "chat", "vllm", "tgi", "ollama", "llama"},
		portHints:  []int{8000, 11434},
	},
	{
		class: WorkloadClass{
			Name: "ai-gateway", Label: "AI Gateway",
			RiskMultiplier: 1.45,
			Reason:         "AI gateways route all LLM traffic; compromise enables prompt interception, model impersonation, and credential theft for upstream APIs",
		},
		imageHints: []string{"higress", "litellm", "portkey", "helicone", "promptlayer", "openrouter", "braintrustdata"},
		nameHints:  []string{"ai-gateway", "model-router", "llm-gateway", "prompt-proxy", "litellm", "higress"},
		portHints:  []int{4000},
	},
	{
		class: WorkloadClass{
			Name: "rag-pipeline", Label: "RAG Pipeline",
			RiskMultiplier: 1.40,
			Reason:         "RAG pipelines have read access to knowledge bases; compromise enables knowledge poisoning and sensitive data extraction",
		},
		imageHints: []string{"chromadb", "chroma", "pinecone", "weaviate", "qdrant", "milvus", "pgvector", "faiss"},
		nameHints:  []string{"rag", "embedding", "vector-db", "retriev", "knowledge-base", "chromadb", "qdrant", "weaviate", "milvus"},
		portHints:  []int{8000, 6333, 19530},
	},
	{
		class: WorkloadClass{
			Name: "model-registry", Label: "Model Registry",
			RiskMultiplier: 1.40,
			Reason:         "Model registries store trained models and artifacts; compromise enables model poisoning and supply chain attacks",
		},
		imageHints: []string{"mlflow", "wandb", "neptune", "clearml", "bentoml", "seldon"},
		nameHints:  []string{"model-registry", "model-store", "artifact", "mlflow", "wandb", "model-repo"},
		portHints:  []int{5000},
	},
	{
		class: WorkloadClass{
			Name: "ml-ai", Label: "ML / AI Workload",
			RiskMultiplier: 1.35,
			Reason:         "ML workloads often have broad data access and GPU resources; model theft or data poisoning risk",
		},
		imageHints: []string{"tensorflow", "pytorch", "nvidia", "cuda", "huggingface", "mlflow", "jupyter", "ray", "triton"},
		nameHints:  []string{"ml-", "ai-", "model", "inference", "training", "predict", "llm", "embedding", "vector"},
		portHints:  []int{8888, 8501, 8001},
	},
	{
		class: WorkloadClass{
			Name: "ci-cd", Label: "CI/CD Pipeline",
			RiskMultiplier: 1.4,
			Reason:         "CI/CD tools have cluster write access and secrets; compromise enables supply chain attacks",
		},
		imageHints: []string{"jenkins", "gitlab-runner", "drone", "tekton", "argo", "flux", "buildkit"},
		nameHints:  []string{"cicd", "ci-", "cd-", "pipeline", "build", "deploy", "runner", "jenkins", "argo"},
		portHints:  []int{},
	},
	{
		class: WorkloadClass{
			Name: "monitoring", Label: "Monitoring / Observability",
			RiskMultiplier: 0.85,
			Reason:         "Monitoring agents are lower risk but may contain cluster-wide telemetry",
		},
		imageHints: []string{"prometheus", "grafana", "datadog", "newrelic", "jaeger", "zipkin", "otel", "fluentd", "fluentbit", "logstash", "vector", "loki"},
		nameHints:  []string{"monitor", "metric", "observ", "logging", "log-", "trace", "telemetry", "apm"},
		portHints:  []int{9090, 3000, 14268, 9411, 4317},
	},
	{
		class: WorkloadClass{
			Name: "secret-manager", Label: "Secret Manager / Vault",
			RiskMultiplier: 1.5,
			Reason:         "Secret managers hold all cluster secrets; compromise is catastrophic",
		},
		imageHints: []string{"vault", "conjur", "sealed-secret", "external-secrets", "sops"},
		nameHints:  []string{"vault", "secret", "kms", "seal"},
		portHints:  []int{8200},
	},
	{
		class: WorkloadClass{
			Name: "storage", Label: "Object Storage",
			RiskMultiplier: 1.25,
			Reason:         "Object storage may contain backups, uploads, and sensitive files",
		},
		imageHints: []string{"minio", "ceph", "rook", "longhorn"},
		nameHints:  []string{"storage", "minio", "s3-", "bucket", "blob"},
		portHints:  []int{9000},
	},
}

// defaultClass is returned when no rules match
var defaultClass = WorkloadClass{
	Name:           "application",
	Label:          "General Application",
	RiskMultiplier: 1.0,
	Reason:         "No specific workload pattern detected",
}

// Classify determines the workload class of a pod based on its image, name, and ports
func Classify(score *types.PlexarScore) WorkloadClass {
	imageLower := strings.ToLower(score.ImageName)
	nameLower := strings.ToLower(score.PodName)
	// Split pod name into segments for word-boundary matching
	nameSegments := strings.FieldsFunc(nameLower, func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})

	bestMatch := defaultClass
	bestConfidence := 0

	for _, rule := range rules {
		confidence := 0

		// Check image hints (strongest signal) — substring match is fine for image refs
		for _, hint := range rule.imageHints {
			if strings.Contains(imageLower, hint) {
				confidence += 3
				break
			}
		}

		// Check name hints — use segment matching to avoid false positives
		// e.g. "processor" should NOT match "sso"
		for _, hint := range rule.nameHints {
			if segmentContains(nameSegments, hint) {
				confidence += 2
				break
			}
		}

		if confidence > bestConfidence {
			bestConfidence = confidence
			bestMatch = rule.class
		}
	}

	return bestMatch
}

// segmentContains checks if any segment of the pod name matches the hint.
// A match is: exact equality, or the segment starts with the hint (e.g. segment
// "payment" matches hint "payment"), or the segment contains the hint as a
// complete token. This avoids false positives like "processor" matching "sso"
// or "my" matching "mysql".
func segmentContains(segments []string, hint string) bool {
	for _, seg := range segments {
		if seg == hint || strings.HasPrefix(seg, hint) {
			return true
		}
	}
	return false
}

// ListClasses returns the names of all available workload classes
func ListClasses() []string {
	names := make([]string, 0, len(rules)+1)
	for _, r := range rules {
		names = append(names, r.class.Label)
	}
	names = append(names, defaultClass.Label)
	return names
}

// ClassifyAll classifies all pods and applies risk multipliers to their scores
func ClassifyAll(scores []types.PlexarScore) []types.PlexarScore {
	for i := range scores {
		wc := Classify(&scores[i])
		scores[i].WorkloadClass = wc.Label
		scores[i].RiskMultiplier = wc.RiskMultiplier
		scores[i].BaseScore = scores[i].Total

		// Apply multiplier: scale the score but cap at 100
		adjusted := int(float64(scores[i].Total) * wc.RiskMultiplier)
		if adjusted > 100 {
			adjusted = 100
		}
		scores[i].Total = adjusted

		// Recalculate tier based on adjusted score
		scores[i].Tier = tierFromScore(adjusted)
	}
	return scores
}

// IsAgentClass returns true if the workload class name represents an AI agent workload
// that has non-deterministic communication patterns and should boost chain risk
func IsAgentClass(className string) bool {
	switch strings.ToLower(className) {
	case "ai-agent", "ai agent runtime",
		"llm-inference", "llm inference",
		"ai-gateway", "ai gateway",
		"rag-pipeline", "rag pipeline",
		"model-registry", "model registry":
		return true
	}
	return false
}

func tierFromScore(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}
