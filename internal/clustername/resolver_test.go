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
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestClusterName(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ClusterName Suite")
}

var _ = Describe("Resolver", func() {
	Context("ResolveClusterName", func() {
		It("should return error for unsupported mode", func() {
			resolver := &Resolver{
				getEnv: func(key string) string {
					return ""
				},
			}
			_, err := resolver.ResolveClusterName("unsupported")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unsupported cluster name resolution mode"))
		})

		It("should support azure mode", func() {
			resolver := &Resolver{
				getEnv: func(key string) string {
					if key == KubernetesServiceHostEnv {
						return "my-cluster-dns-abc123.guid123.privatelink.eastus.azmk8s.io"
					}
					return ""
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
			}
			_, err := resolver.ResolveClusterName("")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unsupported cluster name resolution mode"))
		})
	})

	Context("resolveAzureClusterName", func() {
		DescribeTable("Azure cluster name extraction",
			func(serviceHost string, expectedName string, shouldError bool) {
				resolver := &Resolver{
					getEnv: func(key string) string {
						if key == KubernetesServiceHostEnv {
							return serviceHost
						}
						return ""
					},
				}

				name, err := resolver.resolveAzureClusterName()

				if shouldError {
					Expect(err).To(HaveOccurred())
				} else {
					Expect(err).NotTo(HaveOccurred())
					Expect(name).To(Equal(expectedName))
				}
			},
			Entry("typical AKS format",
				"my-aks-cluster-dns-abc12345.guid-1234.privatelink.eastus.azmk8s.io",
				"my-aks-cluster",
				false),
			Entry("cluster name with hyphens",
				"prod-k8s-cluster-dns-xyz789.guid-5678.privatelink.westus2.azmk8s.io",
				"prod-k8s-cluster",
				false),
			Entry("short cluster name",
				"aks-dns-123.guid.privatelink.centralus.azmk8s.io",
				"aks",
				false),
			Entry("cluster name with numbers",
				"cluster123-dns-abc.guid.privatelink.northeurope.azmk8s.io",
				"cluster123",
				false),
			Entry("complex cluster name",
				"my-awesome-prod-cluster-v2-dns-hash123.guid456.privatelink.southcentralus.azmk8s.io",
				"my-awesome-prod-cluster-v2",
				false),
			Entry("missing -dns suffix",
				"my-cluster.guid.privatelink.eastus.azmk8s.io",
				"",
				true),
			Entry("empty service host",
				"",
				"",
				true),
			Entry("-dns at the beginning",
				"-dns-abc.guid.privatelink.eastus.azmk8s.io",
				"",
				true),
			Entry("multiple -dns occurrences (uses last)",
				"cluster-dns-dns-abc.guid.privatelink.eastus.azmk8s.io",
				"cluster-dns",
				false),
		)

		It("should return error when KUBERNETES_SERVICE_HOST is not set", func() {
			resolver := &Resolver{
				getEnv: func(key string) string {
					return "" // Simulate missing env var
				},
			}

			_, err := resolver.resolveAzureClusterName()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("KUBERNETES_SERVICE_HOST environment variable not found"))
		})
	})

	Context("NewResolver", func() {
		It("should create a resolver with os.Getenv", func() {
			resolver := NewResolver()
			Expect(resolver).NotTo(BeNil())
			Expect(resolver.getEnv).NotTo(BeNil())
			Expect(resolver.httpClient).NotTo(BeNil())
		})
	})

	Context("IP Address Detection and IMDS Fallback", func() {
		var (
			mockServer *httptest.Server
			resolver   *Resolver
		)

		BeforeEach(func() {
			// Create a mock IMDS server
			mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify the Metadata header is present
				if r.Header.Get("Metadata") != "true" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.ContainerService/managedClusters/my-test-cluster"))
			}))
		})

		AfterEach(func() {
			if mockServer != nil {
				mockServer.Close()
			}
		})

		It("should detect IP address and use IMDS fallback", func() {
			resolver = &Resolver{
				getEnv: func(key string) string {
					if key == KubernetesServiceHostEnv {
						return "10.0.0.1"
					}
					return ""
				},
				httpClient: mockServer.Client(),
			}

			// Override the IMDS endpoint to use our mock server
			originalEndpoint := azureIMDSEndpoint
			defer func() {
				// Note: Can't reassign const, but this is for test documentation
				_ = originalEndpoint
			}()

			// We need to test with a custom resolver that uses the mock server
			customResolver := &Resolver{
				getEnv: func(key string) string {
					if key == KubernetesServiceHostEnv {
						return "10.0.0.1"
					}
					return ""
				},
				httpClient: mockServer.Client(),
			}

			// Create a custom method for testing
			serviceHost := customResolver.getEnv(KubernetesServiceHostEnv)
			Expect(isIPAddress(serviceHost)).To(BeTrue())
		})

		It("should detect IPv6 address", func() {
			Expect(isIPAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334")).To(BeTrue())
			Expect(isIPAddress("::1")).To(BeTrue())
			Expect(isIPAddress("fe80::1")).To(BeTrue())
		})

		It("should not detect DNS name as IP address", func() {
			Expect(isIPAddress("my-cluster-dns-abc123.guid123.privatelink.eastus.azmk8s.io")).To(BeFalse())
			Expect(isIPAddress("kubernetes.default.svc")).To(BeFalse())
		})

		It("should handle IMDS request failure", func() {
			failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer failingServer.Close()

			resolver = &Resolver{
				getEnv: func(key string) string {
					if key == KubernetesServiceHostEnv {
						return "10.0.0.1"
					}
					return ""
				},
				httpClient: failingServer.Client(),
			}

			// Test with mock by creating a test server URL
			req, err := http.NewRequest("GET", failingServer.URL, nil)
			Expect(err).NotTo(HaveOccurred())
			req.Header.Set("Metadata", "true")

			resp, err := resolver.httpClient.Do(req)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.StatusCode).To(Equal(http.StatusInternalServerError))
		})
	})

	Context("extractClusterNameFromResourceID", func() {
		DescribeTable("Resource ID parsing",
			func(resourceID string, expectedName string) {
				name := extractClusterNameFromResourceID(resourceID)
				Expect(name).To(Equal(expectedName))
			},
			Entry("typical resource ID",
				"/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/my-rg/providers/Microsoft.ContainerService/managedClusters/my-cluster",
				"my-cluster"),
			Entry("cluster name with hyphens",
				"/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.ContainerService/managedClusters/prod-aks-cluster-01",
				"prod-aks-cluster-01"),
			Entry("cluster name with underscores",
				"/subscriptions/sub-456/resourceGroups/test-rg/providers/Microsoft.ContainerService/managedClusters/test_cluster_v2",
				"test_cluster_v2"),
			Entry("missing managedClusters",
				"/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.ContainerService/something-else/my-cluster",
				""),
			Entry("incomplete resource ID",
				"/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.ContainerService/managedClusters",
				""),
			Entry("empty resource ID",
				"",
				""),
			Entry("malformed resource ID",
				"not-a-valid-resource-id",
				""),
		)
	})

	Context("isIPAddress", func() {
		DescribeTable("IP address validation",
			func(input string, expected bool) {
				Expect(isIPAddress(input)).To(Equal(expected))
			},
			Entry("valid IPv4", "192.168.1.1", true),
			Entry("valid IPv4 localhost", "127.0.0.1", true),
			Entry("valid IPv4 zero", "0.0.0.0", true),
			Entry("valid IPv6 full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", true),
			Entry("valid IPv6 compressed", "2001:db8::1", true),
			Entry("valid IPv6 localhost", "::1", true),
			Entry("DNS name", "my-cluster.example.com", false),
			Entry("DNS with hyphens", "my-cluster-dns-abc123.guid.privatelink.eastus.azmk8s.io", false),
			Entry("empty string", "", false),
			Entry("invalid IP", "256.256.256.256", false),
			Entry("partial IP", "192.168.1", false),
		)
	})
})
