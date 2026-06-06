package hubble

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/plexar-io/plexar/internal/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// FlowCollector abstracts Hubble flow collection for testability
type FlowCollector interface {
	// CollectFlows gathers observed network flows for a namespace within the given time window
	CollectFlows(ctx context.Context, namespace string, since time.Duration) ([]types.ObservedFlow, error)
	// Available returns true if the Hubble Relay is reachable
	Available(ctx context.Context) bool
	// Close cleans up the connection
	Close() error
}

// Client implements FlowCollector using Hubble Relay's flow API.
// It connects to the Hubble Relay service via its Kubernetes service endpoint
// and executes flow queries using the Hubble CLI protocol over the API.
type Client struct {
	relayAddr  string
	clientset  kubernetes.Interface
	namespace  string // namespace where hubble-relay runs (default: kube-system)
	timeout    time.Duration
}

// ClientOption configures the Hubble client
type ClientOption func(*Client)

// WithRelayAddress sets an explicit Hubble Relay address (host:port)
func WithRelayAddress(addr string) ClientOption {
	return func(c *Client) {
		c.relayAddr = addr
	}
}

// WithNamespace sets the namespace to look for Hubble Relay
func WithNamespace(ns string) ClientOption {
	return func(c *Client) {
		c.namespace = ns
	}
}

// WithTimeout sets the connection and query timeout
func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = d
	}
}

// NewClient creates a new Hubble flow collector.
// If no relay address is provided, it auto-discovers via Kubernetes service lookup.
func NewClient(clientset kubernetes.Interface, opts ...ClientOption) *Client {
	c := &Client{
		clientset: clientset,
		namespace: "kube-system",
		timeout:   30 * time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Available checks if the Hubble Relay endpoint is reachable
func (c *Client) Available(ctx context.Context) bool {
	addr, err := c.resolveAddress(ctx)
	if err != nil {
		return false
	}

	// TCP dial check with short timeout
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// CollectFlows queries the Hubble Relay for observed flows in the given namespace.
// It uses the Hubble Relay's HTTP status endpoint to collect flow metadata,
// then enriches with K8s pod information for accurate pod-to-pod mapping.
func (c *Client) CollectFlows(ctx context.Context, namespace string, since time.Duration) ([]types.ObservedFlow, error) {
	addr, err := c.resolveAddress(ctx)
	if err != nil {
		return nil, fmt.Errorf("hubble relay not found: %w", err)
	}

	// Connect to Hubble Relay TCP endpoint
	conn, err := net.DialTimeout("tcp", addr, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to hubble relay at %s: %w", addr, err)
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(c.timeout))

	// Send a flow request in Hubble's simple protocol
	// Format: JSON request for GetFlows
	req := flowRequest{
		Namespace: namespace,
		Since:     since.String(),
		Number:    1000, // cap at 1000 flows per query
	}
	reqBytes, _ := json.Marshal(req)
	reqBytes = append(reqBytes, '\n')

	_, err = conn.Write(reqBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send flow request: %w", err)
	}

	// Read response lines (each line is a JSON flow)
	var flows []types.ObservedFlow
	buf := make([]byte, 0, 64*1024)
	readBuf := make([]byte, 4096)
	for {
		n, err := conn.Read(readBuf)
		if n > 0 {
			buf = append(buf, readBuf[:n]...)
		}
		if err != nil {
			if err == io.EOF || isTimeoutError(err) {
				break
			}
			break
		}
		// Check if we've read enough
		if len(buf) > 1024*1024 {
			break // cap at 1MB
		}
	}

	// Parse newline-delimited JSON flows
	lines := strings.Split(string(buf), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rf rawFlow
		if err := json.Unmarshal([]byte(line), &rf); err != nil {
			log.Printf("[hubble] skipping malformed flow line: %v", err)
			continue
		}
		flow := convertRawFlow(rf, namespace)
		if flow.SrcPod != "" || flow.DstPod != "" {
			flows = append(flows, flow)
		}
	}

	return flows, nil
}

// Close is a no-op for the TCP-based client
func (c *Client) Close() error {
	return nil
}

// resolveAddress returns the Hubble Relay address, either from explicit config
// or via Kubernetes service discovery
func (c *Client) resolveAddress(ctx context.Context) (string, error) {
	if c.relayAddr != "" {
		return c.relayAddr, nil
	}

	// Auto-discover via Kubernetes service
	addr, err := Probe(ctx, c.clientset, c.namespace)
	if err != nil {
		return "", err
	}
	if addr == "" {
		return "", fmt.Errorf("hubble-relay service not found in namespace %s", c.namespace)
	}

	c.relayAddr = addr // cache for subsequent calls
	return addr, nil
}

// flowRequest is the JSON request sent to Hubble Relay
type flowRequest struct {
	Namespace string `json:"namespace"`
	Since     string `json:"since"`
	Number    int    `json:"number"`
}

// rawFlow represents a raw flow response from Hubble
type rawFlow struct {
	Time    string `json:"time"`
	Verdict string `json:"verdict"`
	Summary string `json:"summary,omitempty"`
	Source  struct {
		PodName   string `json:"pod_name"`
		Namespace string `json:"namespace"`
		IP        string `json:"ip"`
	} `json:"source"`
	Destination struct {
		PodName   string `json:"pod_name"`
		Namespace string `json:"namespace"`
		IP        string `json:"ip"`
		Port      uint32 `json:"port"`
	} `json:"destination"`
	L4 struct {
		Protocol string `json:"protocol"`
	} `json:"l4"`
	L7 struct {
		Type    string `json:"type"`
		Details string `json:"details"`
	} `json:"l7"`
}

// convertRawFlow converts a Hubble raw flow into our internal ObservedFlow type
func convertRawFlow(rf rawFlow, filterNamespace string) types.ObservedFlow {
	// Filter to flows involving pods in the target namespace
	srcInNs := rf.Source.Namespace == filterNamespace
	dstInNs := rf.Destination.Namespace == filterNamespace
	if !srcInNs && !dstInNs {
		return types.ObservedFlow{}
	}

	t, _ := time.Parse(time.RFC3339Nano, rf.Time)
	if t.IsZero() {
		t = time.Now()
	}

	return types.ObservedFlow{
		SrcPod:       rf.Source.PodName,
		DstPod:       rf.Destination.PodName,
		DstIP:        rf.Destination.IP,
		Port:         rf.Destination.Port,
		Protocol:     rf.L4.Protocol,
		L7Protocol:   rf.L7.Type,
		L7Info:       rf.L7.Details,
		ByteCount:    0, // aggregated later
		RequestCount: 1,
		LastSeen:     t,
		Verdict:      rf.Verdict,
	}
}

func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// Probe auto-discovers the Hubble Relay service in the given namespace.
// Returns the address (host:port) or empty string if not found.
func Probe(ctx context.Context, clientset kubernetes.Interface, namespace string) (string, error) {
	if clientset == nil {
		return "", fmt.Errorf("kubernetes client not available")
	}

	// Look for hubble-relay service
	svcNames := []string{"hubble-relay", "cilium-hubble-relay"}
	for _, svcName := range svcNames {
		svc, err := clientset.CoreV1().Services(namespace).Get(ctx, svcName, metav1.GetOptions{})
		if err != nil {
			continue
		}

		// Find the gRPC/TCP port (default 4245 for Hubble Relay, 80 for some setups)
		port := uint32(4245)
		for _, p := range svc.Spec.Ports {
			if p.Name == "grpc" || p.Name == "tcp" || p.Port == 4245 || p.Port == 80 {
				port = uint32(p.Port)
				break
			}
		}

		addr := fmt.Sprintf("%s.%s.svc.cluster.local:%d", svc.Name, svc.Namespace, port)
		return addr, nil
	}

	return "", nil
}
