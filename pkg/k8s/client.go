package k8s

import (
	"fmt"
	"path/filepath"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// Client wraps Kubernetes API access
type Client struct {
	Clientset     kubernetes.Interface
	DynamicClient dynamic.Interface
	RestConfig    *rest.Config
	clusterName   string
}

// NewClient creates a Kubernetes client from kubeconfig or in-cluster config
func NewClient(kubeconfigPath string) (*Client, error) {
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

// ClusterName returns the current cluster context name
func (c *Client) ClusterName() string {
	return c.clusterName
}
