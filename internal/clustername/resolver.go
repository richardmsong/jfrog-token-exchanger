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
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// ResolutionModeAzure is the cluster name resolution mode for Azure Kubernetes Service
	ResolutionModeAzure = "azure"
	// KubernetesServiceHostEnv is the environment variable for Kubernetes service host
	KubernetesServiceHostEnv = "KUBERNETES_SERVICE_HOST"
	// azureIMDSEndpoint is the Azure Instance Metadata Service endpoint
	azureIMDSEndpoint = "http://169.254.169.254/metadata/instance/compute/resourceId?api-version=2021-02-01&format=text"
	// azureIMDSTimeout is the timeout for IMDS requests
	azureIMDSTimeout = 2 * time.Second
)

// Resolver provides methods for resolving cluster names from the environment
type Resolver struct {
	// getEnv is a function to retrieve environment variables (allows testing)
	getEnv func(string) string
	// httpClient is the HTTP client for making requests (allows testing)
	httpClient *http.Client
}

// NewResolver creates a new cluster name resolver
func NewResolver() *Resolver {
	return &Resolver{
		getEnv: os.Getenv,
		httpClient: &http.Client{
			Timeout: azureIMDSTimeout,
		},
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
// If KUBERNETES_SERVICE_HOST is an IP address, falls back to Azure IMDS
// Returns: cluster-name
func (r *Resolver) resolveAzureClusterName() (string, error) {
	serviceHost := r.getEnv(KubernetesServiceHostEnv)
	if serviceHost == "" {
		return "", fmt.Errorf("%s environment variable not found", KubernetesServiceHostEnv)
	}

	// Check if serviceHost is an IP address
	if isIPAddress(serviceHost) {
		// Fall back to Azure IMDS
		return r.resolveFromAzureIMDS()
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

// isIPAddress checks if a string is an IP address
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// resolveFromAzureIMDS queries the Azure Instance Metadata Service to get the cluster name
func (r *Resolver) resolveFromAzureIMDS() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), azureIMDSTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", azureIMDSEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create IMDS request: %w", err)
	}

	// Azure IMDS requires the Metadata header
	req.Header.Set("Metadata", "true")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query Azure IMDS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Azure IMDS returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read IMDS response: %w", err)
	}

	// resourceId format: /subscriptions/{subscription}/resourceGroups/{rg}/providers/Microsoft.ContainerService/managedClusters/{cluster-name}
	resourceID := string(body)
	clusterName := extractClusterNameFromResourceID(resourceID)
	if clusterName == "" {
		return "", fmt.Errorf("failed to extract cluster name from resource ID: %s", resourceID)
	}

	return clusterName, nil
}

// extractClusterNameFromResourceID extracts the cluster name from an Azure resource ID
func extractClusterNameFromResourceID(resourceID string) string {
	// Expected format: /subscriptions/{subscription}/resourceGroups/{rg}/providers/Microsoft.ContainerService/managedClusters/{cluster-name}
	parts := strings.Split(resourceID, "/")

	// Find the index of "managedClusters"
	for i, part := range parts {
		if part == "managedClusters" && i+1 < len(parts) {
			return parts[i+1]
		}
	}

	return ""
}
