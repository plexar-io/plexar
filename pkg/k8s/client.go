package k8s

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// UseKubectlTransport enables kubectl-based API transport for restricted
// environments where direct TCP connections to the API server are blocked.
var UseKubectlTransport bool

// Client wraps Kubernetes API access
type Client struct {
	Clientset     kubernetes.Interface
	DynamicClient dynamic.Interface
	RestConfig    *rest.Config
	clusterName   string
}

// NewClient creates a Kubernetes client from kubeconfig or in-cluster config.
// If UseKubectlTransport is true, all API calls are routed through the kubectl
// binary instead of direct TCP connections.
func NewClient(kubeconfigPath string) (*Client, error) {
	if UseKubectlTransport {
		return newKubectlClient()
	}

	var config *rest.Config
	var clusterName string
	var err error

	if kubeconfigPath == "" {
		// Try in-cluster first
		config, err = rest.InClusterConfig()
		if err != nil {
			// Fall back to default kubeconfig
			if home := homedir.HomeDir(); home != "" {
				kubeconfigPath = filepath.Join(home, ".kube", "config")
			}
		} else {
			clusterName = "in-cluster"
		}
	}

	if config == nil {
		loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
		configOverrides := &clientcmd.ConfigOverrides{}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

		config, err = kubeConfig.ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
		}

		rawConfig, err := kubeConfig.RawConfig()
		if err == nil {
			clusterName = rawConfig.CurrentContext
		}
	}

	// Generous timeout for slow or non-standard API server ports (e.g. NodePort 30002)
	config.Timeout = 2 * time.Minute

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	return &Client{
		Clientset:     clientset,
		DynamicClient: dynClient,
		RestConfig:    config,
		clusterName:   clusterName,
	}, nil
}

// newKubectlClient creates a Client that routes all API calls through kubectl.
// Used in restricted environments where only the kubectl binary has network
// access to the API server (e.g., Cisco IKS/HyperFlex nodes).
func newKubectlClient() (*Client, error) {
	config := &rest.Config{
		Host:      "http://kubectl-transport",
		Transport: &KubectlTransport{},
	}
	config.ContentType = "application/json"

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubectl-backed clientset: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubectl-backed dynamic client: %w", err)
	}

	// Get cluster name via kubectl (cluster-info is in the allowed subcommands)
	clusterName := "kubernetes"
	out, execErr := exec.Command("/bin/sh", "-c", "kubectl cluster-info").Output()
	if execErr == nil {
		line := strings.SplitN(string(out), "\n", 2)[0]
		if idx := strings.Index(line, "https://"); idx >= 0 {
			clusterName = strings.TrimSpace(line[idx:])
		}
	}

	return &Client{
		Clientset:     clientset,
		DynamicClient: dynClient,
		RestConfig:    config,
		clusterName:   clusterName,
	}, nil
}

// ClusterName returns the current cluster context name
func (c *Client) ClusterName() string {
	return c.clusterName
}
