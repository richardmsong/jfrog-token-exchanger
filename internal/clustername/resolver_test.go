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
			resolver := NewResolver()
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
			resolver := NewResolver()
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
			Entry("multiple -dns occurrences (uses first)",
				"cluster-dns-dns-abc.guid.privatelink.eastus.azmk8s.io",
				"cluster",
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
		})
	})
})
