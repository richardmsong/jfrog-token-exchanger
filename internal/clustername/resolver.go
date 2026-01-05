/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package clustername

import (
	"fmt"
	"os"
	"strings"
)

const (
	// ResolutionModeAzure is the cluster name resolution mode for Azure Kubernetes Service
	ResolutionModeAzure = "azure"
	// KubernetesServiceHostEnv is the environment variable for Kubernetes service host
	KubernetesServiceHostEnv = "KUBERNETES_SERVICE_HOST"
)

// Resolver provides methods for resolving cluster names from the environment
type Resolver struct {
	// getEnv is a function to retrieve environment variables (allows testing)
	getEnv func(string) string
}

// NewResolver creates a new cluster name resolver
func NewResolver() *Resolver {
	return &Resolver{
		getEnv: os.Getenv,
	}
}

// ResolveClusterName resolves the cluster name based on the resolution mode
// Supported modes: "azure"
func (r *Resolver) ResolveClusterName(mode string) (string, error) {
	switch mode {
	case ResolutionModeAzure:
		return r.resolveAzureClusterName()
	default:
		return "", fmt.Errorf("unsupported cluster name resolution mode: %s (supported modes: azure)", mode)
	}
}

// resolveAzureClusterName extracts the cluster name from the KUBERNETES_SERVICE_HOST environment variable
// Expected format: cluster-name-dns-somehash.<guid>.privatelink.<region>.azmk8s.io
// Returns: cluster-name
func (r *Resolver) resolveAzureClusterName() (string, error) {
	serviceHost := r.getEnv(KubernetesServiceHostEnv)
	if serviceHost == "" {
		return "", fmt.Errorf("%s environment variable not found", KubernetesServiceHostEnv)
	}

	// Split by '-dns' to extract cluster name (use last occurrence)
	dnsIndex := strings.LastIndex(serviceHost, "-dns")
	if dnsIndex == -1 {
		return "", fmt.Errorf("invalid AKS service host format: expected '<cluster-name>-dns-...' but got '%s'", serviceHost)
	}

	clusterName := serviceHost[:dnsIndex]
	if clusterName == "" {
		return "", fmt.Errorf("extracted cluster name is empty from service host: %s", serviceHost)
	}

	return clusterName, nil
}
