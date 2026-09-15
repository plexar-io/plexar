package k8s

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
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

// ExecInPod runs a command inside a pod container and returns stdout.
// If the RestConfig is a kubectl-transport stub, it shells out to `kubectl exec` instead.
func (c *Client) ExecInPod(ctx context.Context, namespace, podName, container string, command []string) (string, error) {
	// If using kubectl transport, shell out directly
	if UseKubectlTransport || c.RestConfig == nil || c.RestConfig.Host == "http://kubectl-transport" {
		return c.kubectlExec(namespace, podName, container, command)
	}

	req := c.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   command,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(c.RestConfig, "POST", req.URL())
	if err != nil {
		return "", fmt.Errorf("create executor: %w", err)
	}

	var stdout, stderr bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		return "", fmt.Errorf("exec in pod %s/%s: %w (stderr: %s)", namespace, podName, err, stderr.String())
	}

	return stdout.String(), nil
}

// kubectlExec shells out to kubectl exec for restricted environments.
func (c *Client) kubectlExec(namespace, podName, container string, command []string) (string, error) {
	args := []string{"exec", "-n", namespace, podName}
	if container != "" {
		args = append(args, "-c", container)
	}
	args = append(args, "--")
	args = append(args, command...)

	cmd := exec.Command("kubectl", args...)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("kubectl exec %s/%s: %w", namespace, podName, err)
	}
	return string(out), nil
}
