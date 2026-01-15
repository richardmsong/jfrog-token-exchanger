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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	// ResolutionModeAzure is the cluster name resolution mode for Azure Kubernetes Service
	ResolutionModeAzure = "azure"
	// ServiceAccountTokenPath is the default path to the Kubernetes service account token
	ServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // G101: This is a file path, not a credential
)

// Resolver provides methods for resolving cluster names from the environment
type Resolver struct {
	// getEnv is a function to retrieve environment variables (allows testing)
	getEnv func(string) string
	// readFile is a function to read files (allows testing)
	readFile func(string) ([]byte, error)
}

// NewResolver creates a new cluster name resolver
func NewResolver() *Resolver {
	return &Resolver{
		getEnv:   os.Getenv,
		readFile: os.ReadFile,
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

// resolveAzureClusterName extracts the cluster name from the Kubernetes service account token
// It reads the token from /var/run/secrets/kubernetes.io/serviceaccount/token,
// decodes the JWT, and extracts the cluster name from the audience claim.
// Expected audience format: https://<cluster-name>-dns-<hash>.hcp.<region>.azmk8s.io
// Returns: cluster-name
func (r *Resolver) resolveAzureClusterName() (string, error) {
	// Read the service account token
	tokenBytes, err := r.readFile(ServiceAccountTokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read service account token from %s: %w", ServiceAccountTokenPath, err)
	}

	token := string(tokenBytes)
	if token == "" {
		return "", fmt.Errorf("service account token is empty")
	}

	// Decode JWT without verification (we only need to read the payload)
	clusterName, err := extractClusterNameFromToken(token)
	if err != nil {
		return "", fmt.Errorf("failed to extract cluster name from token: %w", err)
	}

	return clusterName, nil
}

// extractClusterNameFromToken decodes a JWT token and extracts the cluster name from the audience claim
func extractClusterNameFromToken(token string) (string, error) {
	// JWT format: header.payload.signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse the JSON payload
	var claims struct {
		Aud interface{} `json:"aud"` // Can be string or []string
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Extract audiences (handle both string and array formats)
	var audiences []string
	switch aud := claims.Aud.(type) {
	case string:
		audiences = []string{aud}
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				audiences = append(audiences, s)
			}
		}
	default:
		return "", fmt.Errorf("unexpected aud claim type: %T", claims.Aud)
	}

	// Find the AKS audience and extract cluster name
	for _, aud := range audiences {
		clusterName, err := extractClusterNameFromAudience(aud)
		if err == nil {
			return clusterName, nil
		}
	}

	return "", fmt.Errorf("no valid AKS audience found in token (expected format: https://<cluster-name>-dns-<hash>.hcp.<region>.azmk8s.io)")
}

// extractClusterNameFromAudience extracts the cluster name from an AKS audience URL
// Expected format: https://<cluster-name>-dns-<hash>.hcp.<region>.azmk8s.io
// Returns error if format doesn't match
func extractClusterNameFromAudience(audience string) (string, error) {
	// Check if this looks like an AKS audience URL
	if !strings.HasPrefix(audience, "https://") {
		return "", fmt.Errorf("audience does not start with https://: %s", audience)
	}
	if !strings.Contains(audience, ".hcp.") {
		return "", fmt.Errorf("audience does not contain .hcp.: %s", audience)
	}
	if !strings.Contains(audience, ".azmk8s.io") {
		return "", fmt.Errorf("audience does not contain .azmk8s.io: %s", audience)
	}

	// Remove the https:// prefix
	host := strings.TrimPrefix(audience, "https://")

	// Extract cluster name (everything before -dns)
	dnsIndex := strings.Index(host, "-dns-")
	if dnsIndex == -1 {
		return "", fmt.Errorf("audience does not contain -dns- segment: %s", audience)
	}

	clusterName := host[:dnsIndex]
	if clusterName == "" {
		return "", fmt.Errorf("cluster name is empty in audience: %s", audience)
	}

	return clusterName, nil
}
