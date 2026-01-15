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
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestClusterName(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ClusterName Suite")
}

// Helper function to create a mock JWT token with specified audiences
func createMockToken(audiences interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))

	claims := map[string]interface{}{
		"aud": audiences,
		"exp": 1234567890,
		"iss": "kubernetes/serviceaccount",
	}

	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := base64.RawURLEncoding.EncodeToString([]byte("mock-signature"))

	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}

var _ = Describe("Resolver", func() {
	Context("ResolveClusterName", func() {
		It("should return error for unsupported mode", func() {
			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
				readFile: func(path string) ([]byte, error) {
					return nil, fmt.Errorf("not called")
				},
			}
			_, err := resolver.ResolveClusterName("unsupported")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unsupported cluster name resolution mode"))
		})

		It("should support azure mode with token", func() {
			token := createMockToken([]interface{}{
				"https://my-cluster-dns-abc123.hcp.eastus.azmk8s.io",
			})

			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
				readFile: func(path string) ([]byte, error) {
					if path == ServiceAccountTokenPath {
						return []byte(token), nil
					}
					return nil, fmt.Errorf("file not found")
				},
			}
			name, err := resolver.ResolveClusterName(ResolutionModeAzure)
			Expect(err).NotTo(HaveOccurred())
			Expect(name).To(Equal("my-cluster"))
		})

		It("should return error for empty mode", func() {
			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
				readFile: func(path string) ([]byte, error) {
					return nil, fmt.Errorf("not called")
				},
			}
			_, err := resolver.ResolveClusterName("")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unsupported cluster name resolution mode"))
		})
	})

	Context("resolveAzureClusterName", func() {
		It("should extract cluster name from service account token", func() {
			token := createMockToken([]interface{}{
				"https://my-aks-cluster-dns-abc12345.hcp.eastus.azmk8s.io",
			})

			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
				readFile: func(path string) ([]byte, error) {
					if path == ServiceAccountTokenPath {
						return []byte(token), nil
					}
					return nil, fmt.Errorf("file not found")
				},
			}

			name, err := resolver.resolveAzureClusterName()
			Expect(err).NotTo(HaveOccurred())
			Expect(name).To(Equal("my-aks-cluster"))
		})

		It("should handle cluster name with hyphens", func() {
			token := createMockToken([]interface{}{
				"https://prod-k8s-cluster-dns-xyz789.hcp.westus2.azmk8s.io",
			})

			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
				readFile: func(path string) ([]byte, error) {
					return []byte(token), nil
				},
			}

			name, err := resolver.resolveAzureClusterName()
			Expect(err).NotTo(HaveOccurred())
			Expect(name).To(Equal("prod-k8s-cluster"))
		})

		It("should handle multiple audiences and find the AKS one", func() {
			token := createMockToken([]interface{}{
				"https://kubernetes.default.svc",
				"https://my-cluster-dns-abc.hcp.centralus.azmk8s.io",
				"https://other-service.example.com",
			})

			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
				readFile: func(path string) ([]byte, error) {
					return []byte(token), nil
				},
			}

			name, err := resolver.resolveAzureClusterName()
			Expect(err).NotTo(HaveOccurred())
			Expect(name).To(Equal("my-cluster"))
		})

		It("should handle audience as a single string", func() {
			token := createMockToken("https://cluster123-dns-abc.hcp.northeurope.azmk8s.io")

			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
				readFile: func(path string) ([]byte, error) {
					return []byte(token), nil
				},
			}

			name, err := resolver.resolveAzureClusterName()
			Expect(err).NotTo(HaveOccurred())
			Expect(name).To(Equal("cluster123"))
		})

		It("should return error when token file cannot be read", func() {
			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
				readFile: func(path string) ([]byte, error) {
					return nil, fmt.Errorf("permission denied")
				},
			}

			_, err := resolver.resolveAzureClusterName()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to read service account token"))
		})

		It("should return error when token is empty", func() {
			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
				readFile: func(path string) ([]byte, error) {
					return []byte(""), nil
				},
			}

			_, err := resolver.resolveAzureClusterName()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("service account token is empty"))
		})

		It("should return error when no AKS audience is found", func() {
			token := createMockToken([]interface{}{
				"https://kubernetes.default.svc",
				"https://other-service.example.com",
			})

			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
				readFile: func(path string) ([]byte, error) {
					return []byte(token), nil
				},
			}

			_, err := resolver.resolveAzureClusterName()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no valid AKS audience found"))
		})
	})

	Context("extractClusterNameFromToken", func() {
		It("should return error for invalid JWT format", func() {
			_, err := extractClusterNameFromToken("invalid-token")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid JWT format"))
		})

		It("should return error for invalid base64 encoding", func() {
			_, err := extractClusterNameFromToken("header.invalid@base64.signature")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to decode JWT payload"))
		})

		It("should return error for invalid JSON in payload", func() {
			header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
			payload := base64.RawURLEncoding.EncodeToString([]byte(`{invalid json}`))
			signature := base64.RawURLEncoding.EncodeToString([]byte("sig"))
			token := fmt.Sprintf("%s.%s.%s", header, payload, signature)

			_, err := extractClusterNameFromToken(token)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to parse JWT claims"))
		})
	})

	Context("extractClusterNameFromAudience", func() {
		It("should extract cluster name from valid AKS audience", func() {
			name, err := extractClusterNameFromAudience("https://my-cluster-dns-hash.hcp.eastus.azmk8s.io")
			Expect(err).NotTo(HaveOccurred())
			Expect(name).To(Equal("my-cluster"))
		})

		It("should handle cluster names with multiple hyphens", func() {
			name, err := extractClusterNameFromAudience("https://prod-k8s-cluster-v2-dns-hash.hcp.westus.azmk8s.io")
			Expect(err).NotTo(HaveOccurred())
			Expect(name).To(Equal("prod-k8s-cluster-v2"))
		})

		It("should return error for non-AKS audience", func() {
			_, err := extractClusterNameFromAudience("https://kubernetes.default.svc")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("does not contain .hcp."))
		})

		It("should return error for audience without https", func() {
			_, err := extractClusterNameFromAudience("http://my-cluster-dns-hash.hcp.eastus.azmk8s.io")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("does not start with https://"))
		})

		It("should return error for audience without .hcp.", func() {
			_, err := extractClusterNameFromAudience("https://my-cluster-dns-hash.eastus.azmk8s.io")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("does not contain .hcp."))
		})

		It("should return error for audience without -dns-", func() {
			_, err := extractClusterNameFromAudience("https://my-cluster.hcp.eastus.azmk8s.io")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("does not contain -dns-"))
		})
	})

	Context("NewResolver", func() {
		It("should create a resolver with os.Getenv and os.ReadFile", func() {
			resolver := NewResolver()
			Expect(resolver).NotTo(BeNil())
			Expect(resolver.getEnv).NotTo(BeNil())
			Expect(resolver.readFile).NotTo(BeNil())
		})
	})
})
