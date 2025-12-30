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

package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	return s
}

// MockJFrogClient implements JFrogClient for testing
type MockJFrogClient struct {
	ExchangeTokenFunc func(ctx context.Context, saToken string) (*JFrogTokenResponse, error)
	CallCount         int
}

func (m *MockJFrogClient) ExchangeToken(ctx context.Context, saToken string) (*JFrogTokenResponse, error) {
	m.CallCount++
	if m.ExchangeTokenFunc != nil {
		return m.ExchangeTokenFunc(ctx, saToken)
	}
	return &JFrogTokenResponse{
		AccessToken: "mock-access-token",
		ExpiresIn:   3600,
		Scope:       "applied-permissions/groups:readers",
		TokenType:   "Bearer",
	}, nil
}

// MockTokenRequester implements TokenRequester for testing
type MockTokenRequester struct {
	RequestTokenFunc func(ctx context.Context, namespace, name string, expirationSeconds int64) (string, error)
	CallCount        int
}

func (m *MockTokenRequester) RequestToken(ctx context.Context, namespace, name string, expirationSeconds int64) (string, error) {
	m.CallCount++
	if m.RequestTokenFunc != nil {
		return m.RequestTokenFunc(ctx, namespace, name, expirationSeconds)
	}
	return "mock-sa-token", nil
}

var _ = Describe("ServiceAccountReconciler", func() {
	Context("shouldReconcile", func() {
		var reconciler *ServiceAccountReconciler

		BeforeEach(func() {
			reconciler = &ServiceAccountReconciler{}
		})

		DescribeTable("annotation checking",
			func(annotations map[string]string, expected bool) {
				sa := &corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: annotations,
					},
				}
				Expect(reconciler.shouldReconcile(sa)).To(Equal(expected))
			},
			Entry("nil annotations", nil, false),
			Entry("empty annotations", map[string]string{}, false),
			Entry("annotation set to disabled", map[string]string{AnnotationJFrogToken: "disabled"}, false),
			Entry("annotation set to enabled", map[string]string{AnnotationJFrogToken: AnnotationValueEnabled}, true),
			Entry("annotation with different case", map[string]string{AnnotationJFrogToken: "Enabled"}, false),
			Entry("other annotations present", map[string]string{"other": "value"}, false),
			Entry("mixed annotations with enabled", map[string]string{"other": "value", AnnotationJFrogToken: AnnotationValueEnabled}, true),
		)
	})

	Context("needsTokenRenewal", func() {
		var reconciler *ServiceAccountReconciler

		DescribeTable("renewal decision",
			func(annotations map[string]string, threshold time.Duration, expected bool) {
				reconciler = &ServiceAccountReconciler{
					RenewalThreshold: threshold,
				}
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Annotations: annotations,
					},
				}
				Expect(reconciler.needsTokenRenewal(secret)).To(Equal(expected))
			},
			Entry("nil annotations", nil, DefaultRenewalThreshold, true),
			Entry("empty annotations", map[string]string{}, DefaultRenewalThreshold, true),
			Entry("missing expiry annotation", map[string]string{"other": "value"}, DefaultRenewalThreshold, true),
			Entry("invalid expiry format", map[string]string{AnnotationSecretExpiry: "invalid"}, DefaultRenewalThreshold, true),
			Entry("expiry in the past",
				map[string]string{AnnotationSecretExpiry: time.Now().Add(-1 * time.Hour).Format(time.RFC3339)},
				DefaultRenewalThreshold, true),
			Entry("expiry within threshold",
				map[string]string{AnnotationSecretExpiry: time.Now().Add(3 * time.Minute).Format(time.RFC3339)},
				5*time.Minute, true),
			Entry("expiry exactly at threshold",
				map[string]string{AnnotationSecretExpiry: time.Now().Add(5 * time.Minute).Format(time.RFC3339)},
				5*time.Minute, true),
			Entry("expiry beyond threshold",
				map[string]string{AnnotationSecretExpiry: time.Now().Add(1 * time.Hour).Format(time.RFC3339)},
				5*time.Minute, false),
			Entry("custom threshold - needs renewal",
				map[string]string{AnnotationSecretExpiry: time.Now().Add(15 * time.Minute).Format(time.RFC3339)},
				20*time.Minute, true),
			Entry("custom threshold - no renewal needed",
				map[string]string{AnnotationSecretExpiry: time.Now().Add(30 * time.Minute).Format(time.RFC3339)},
				20*time.Minute, false),
		)
	})

	Context("getRenewalThreshold", func() {
		DescribeTable("threshold values",
			func(configured time.Duration, expected time.Duration) {
				reconciler := &ServiceAccountReconciler{
					RenewalThreshold: configured,
				}
				Expect(reconciler.getRenewalThreshold()).To(Equal(expected))
			},
			Entry("zero returns default", time.Duration(0), DefaultRenewalThreshold),
			Entry("custom threshold", 10*time.Minute, 10*time.Minute),
			Entry("very short threshold", 1*time.Second, 1*time.Second),
		)
	})

	Context("createDockerConfigSecret", func() {
		var reconciler *ServiceAccountReconciler

		BeforeEach(func() {
			reconciler = &ServiceAccountReconciler{
				JFrogRegistry: "mycompany.jfrog.io",
			}
		})

		It("should create a valid dockerconfigjson secret", func() {
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "default",
				},
			}
			expiryTime := time.Now().Add(1 * time.Hour)

			secret, err := reconciler.createDockerConfigSecret(sa, "test-sa-jfrog-token", "test-token-123", expiryTime)

			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Name).To(Equal("test-sa-jfrog-token"))
			Expect(secret.Namespace).To(Equal("default"))
			Expect(secret.Type).To(Equal(corev1.SecretTypeDockerConfigJson))
		})

		It("should set the expiry annotation", func() {
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "default",
				},
			}
			expiryTime := time.Now().Add(2 * time.Hour)

			secret, err := reconciler.createDockerConfigSecret(sa, "test-sa-jfrog-token", "test-token", expiryTime)

			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Annotations).To(HaveKey(AnnotationSecretExpiry))

			parsedExpiry, err := time.Parse(time.RFC3339, secret.Annotations[AnnotationSecretExpiry])
			Expect(err).NotTo(HaveOccurred())
			Expect(parsedExpiry.Unix()).To(BeNumerically("~", expiryTime.Unix(), 1))
		})

		It("should create valid docker config JSON structure", func() {
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "default",
				},
			}

			secret, err := reconciler.createDockerConfigSecret(sa, "test-sa-jfrog-token", "my-access-token", time.Now())

			Expect(err).NotTo(HaveOccurred())
			Expect(secret.Data).To(HaveKey(corev1.DockerConfigJsonKey))

			var dockerConfig DockerConfigJSON
			err = json.Unmarshal(secret.Data[corev1.DockerConfigJsonKey], &dockerConfig)
			Expect(err).NotTo(HaveOccurred())
			Expect(dockerConfig.Auths).To(HaveKey("mycompany.jfrog.io"))

			// JFrog format: empty username with token as password
			expectedAuth := base64.StdEncoding.EncodeToString([]byte(":my-access-token"))
			Expect(dockerConfig.Auths["mycompany.jfrog.io"].Auth).To(Equal(expectedAuth))
		})

		It("should use the configured registry", func() {
			reconciler.JFrogRegistry = "custom.registry.io"
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "production",
				},
			}

			secret, err := reconciler.createDockerConfigSecret(sa, "test-sa-jfrog-token", "token", time.Now())

			Expect(err).NotTo(HaveOccurred())

			var dockerConfig DockerConfigJSON
			err = json.Unmarshal(secret.Data[corev1.DockerConfigJsonKey], &dockerConfig)
			Expect(err).NotTo(HaveOccurred())
			Expect(dockerConfig.Auths).To(HaveKey("custom.registry.io"))
		})
	})

	Context("ensureImagePullSecret", func() {
		var (
			reconciler *ServiceAccountReconciler
			fakeClient client.Client
			ctx        context.Context
		)

		BeforeEach(func() {
			ctx = context.Background()
		})

		DescribeTable("adding imagePullSecret",
			func(existingSecrets []corev1.LocalObjectReference, secretName string, expectSecretsCount int) {
				sa := &corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-sa",
						Namespace: "default",
					},
					ImagePullSecrets: existingSecrets,
				}

				testScheme := newTestScheme()
				fakeClient = fakeclient.NewClientBuilder().
					WithScheme(testScheme).
					WithObjects(sa).
					Build()

				reconciler = &ServiceAccountReconciler{
					Client: fakeClient,
					Scheme: testScheme,
				}

				err := reconciler.ensureImagePullSecret(ctx, sa, secretName)
				Expect(err).NotTo(HaveOccurred())

				updatedSA := &corev1.ServiceAccount{}
				err = fakeClient.Get(ctx, types.NamespacedName{Name: "test-sa", Namespace: "default"}, updatedSA)
				Expect(err).NotTo(HaveOccurred())
				Expect(updatedSA.ImagePullSecrets).To(HaveLen(expectSecretsCount))

				found := false
				for _, ref := range updatedSA.ImagePullSecrets {
					if ref.Name == secretName {
						found = true
						break
					}
				}
				Expect(found).To(BeTrue())
			},
			Entry("no existing secrets", nil, "my-jfrog-token", 1),
			Entry("empty secrets list", []corev1.LocalObjectReference{}, "my-jfrog-token", 1),
			Entry("secret already present", []corev1.LocalObjectReference{{Name: "my-jfrog-token"}}, "my-jfrog-token", 1),
			Entry("other secrets present", []corev1.LocalObjectReference{{Name: "other-secret"}}, "my-jfrog-token", 2),
			Entry("multiple secrets with ours present", []corev1.LocalObjectReference{{Name: "other"}, {Name: "my-jfrog-token"}}, "my-jfrog-token", 2),
		)
	})

	Context("Reconcile", func() {
		var (
			reconciler   *ServiceAccountReconciler
			fakeClient   client.Client
			mockTokenReq *MockTokenRequester
			mockJFrog    *MockJFrogClient
			ctx          context.Context
			testScheme   *runtime.Scheme
		)

		BeforeEach(func() {
			ctx = context.Background()
			mockJFrog = &MockJFrogClient{}
			mockTokenReq = &MockTokenRequester{}
			testScheme = newTestScheme()
		})

		It("should skip ServiceAccount without annotation", func() {
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "default",
				},
			}

			fakeClient = fakeclient.NewClientBuilder().
				WithScheme(testScheme).
				WithObjects(sa).
				Build()

			reconciler = &ServiceAccountReconciler{
				Client:      fakeClient,
				Scheme:      testScheme,
				JFrogClient: mockJFrog,
			}

			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: "test-sa", Namespace: "default"},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(time.Duration(0)))
			Expect(mockJFrog.CallCount).To(Equal(0))

			// Verify no secret created
			secretList := &corev1.SecretList{}
			Expect(fakeClient.List(ctx, secretList, client.InNamespace("default"))).To(Succeed())
			Expect(secretList.Items).To(BeEmpty())
		})

		It("should handle non-existent ServiceAccount gracefully", func() {
			fakeClient = fakeclient.NewClientBuilder().
				WithScheme(testScheme).
				Build()

			reconciler = &ServiceAccountReconciler{
				Client:      fakeClient,
				Scheme:      testScheme,
				JFrogClient: mockJFrog,
			}

			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: "nonexistent", Namespace: "default"},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(time.Duration(0)))
		})

		It("should skip token renewal when token is still valid", func() {
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "default",
					Annotations: map[string]string{
						AnnotationJFrogToken: AnnotationValueEnabled,
					},
					UID: "test-uid-123",
				},
			}

			expiryTime := time.Now().Add(2 * time.Hour)
			existingSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa-jfrog-token",
					Namespace: "default",
					Annotations: map[string]string{
						AnnotationSecretExpiry: expiryTime.Format(time.RFC3339),
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "v1",
							Kind:       "ServiceAccount",
							Name:       "test-sa",
							UID:        "test-uid-123",
							Controller: boolPtr(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: []byte(`{"auths":{"test.jfrog.io":{"auth":"dGVzdA=="}}}`),
				},
			}

			fakeClient = fakeclient.NewClientBuilder().
				WithScheme(testScheme).
				WithObjects(sa, existingSecret).
				Build()

			reconciler = &ServiceAccountReconciler{
				Client:           fakeClient,
				Scheme:           testScheme,
				TokenRequester:   mockTokenReq,
				JFrogClient:      mockJFrog,
				JFrogRegistry:    "test.jfrog.io",
				RenewalThreshold: 5 * time.Minute,
			}

			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: "test-sa", Namespace: "default"},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(mockJFrog.CallCount).To(Equal(0))
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))
		})

		It("should renew token when expired", func() {
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "default",
					Annotations: map[string]string{
						AnnotationJFrogToken: AnnotationValueEnabled,
					},
					UID: "test-uid-123",
				},
			}

			expiryTime := time.Now().Add(-1 * time.Hour)
			existingSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa-jfrog-token",
					Namespace: "default",
					Annotations: map[string]string{
						AnnotationSecretExpiry: expiryTime.Format(time.RFC3339),
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "v1",
							Kind:       "ServiceAccount",
							Name:       "test-sa",
							UID:        "test-uid-123",
							Controller: boolPtr(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: []byte(`{"auths":{"test.jfrog.io":{"auth":"b2xk"}}}`),
				},
			}

			fakeClient = fakeclient.NewClientBuilder().
				WithScheme(testScheme).
				WithObjects(sa, existingSecret).
				Build()

			mockJFrog.ExchangeTokenFunc = func(ctx context.Context, saToken string) (*JFrogTokenResponse, error) {
				return &JFrogTokenResponse{
					AccessToken: "new-access-token",
					ExpiresIn:   7200,
				}, nil
			}

			reconciler = &ServiceAccountReconciler{
				Client:           fakeClient,
				Scheme:           testScheme,
				TokenRequester:   mockTokenReq,
				JFrogClient:      mockJFrog,
				JFrogRegistry:    "test.jfrog.io",
				RenewalThreshold: 5 * time.Minute,
			}

			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: "test-sa", Namespace: "default"},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(mockJFrog.CallCount).To(Equal(1))

			// Verify secret was updated
			updatedSecret := &corev1.Secret{}
			Expect(fakeClient.Get(ctx, types.NamespacedName{Name: "test-sa-jfrog-token", Namespace: "default"}, updatedSecret)).To(Succeed())

			newExpiryStr := updatedSecret.Annotations[AnnotationSecretExpiry]
			newExpiry, err := time.Parse(time.RFC3339, newExpiryStr)
			Expect(err).NotTo(HaveOccurred())
			Expect(newExpiry).To(BeTemporally(">", time.Now()))
		})

		It("should create new secret when none exists", func() {
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "default",
					Annotations: map[string]string{
						AnnotationJFrogToken: AnnotationValueEnabled,
					},
					UID: "test-uid-123",
				},
			}

			fakeClient = fakeclient.NewClientBuilder().
				WithScheme(testScheme).
				WithObjects(sa).
				Build()

			mockJFrog.ExchangeTokenFunc = func(ctx context.Context, saToken string) (*JFrogTokenResponse, error) {
				return &JFrogTokenResponse{
					AccessToken: "brand-new-token",
					ExpiresIn:   3600,
				}, nil
			}

			reconciler = &ServiceAccountReconciler{
				Client:           fakeClient,
				Scheme:           testScheme,
				TokenRequester:   mockTokenReq,
				JFrogClient:      mockJFrog,
				JFrogRegistry:    "mycompany.jfrog.io",
				RenewalThreshold: 5 * time.Minute,
			}

			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: "test-sa", Namespace: "default"},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))
			Expect(mockJFrog.CallCount).To(Equal(1))

			// Verify secret was created
			createdSecret := &corev1.Secret{}
			Expect(fakeClient.Get(ctx, types.NamespacedName{Name: "test-sa-jfrog-token", Namespace: "default"}, createdSecret)).To(Succeed())
			Expect(createdSecret.Type).To(Equal(corev1.SecretTypeDockerConfigJson))
			Expect(createdSecret.OwnerReferences).To(HaveLen(1))
			Expect(createdSecret.OwnerReferences[0].Name).To(Equal("test-sa"))

			// Verify SA has imagePullSecret
			updatedSA := &corev1.ServiceAccount{}
			Expect(fakeClient.Get(ctx, types.NamespacedName{Name: "test-sa", Namespace: "default"}, updatedSA)).To(Succeed())

			found := false
			for _, ref := range updatedSA.ImagePullSecrets {
				if ref.Name == "test-sa-jfrog-token" {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue())
		})

		It("should renew when token is within threshold", func() {
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "default",
					Annotations: map[string]string{
						AnnotationJFrogToken: AnnotationValueEnabled,
					},
					UID: "test-uid-123",
				},
			}

			// Token expires in 3 minutes, threshold is 5 minutes - should renew
			expiryTime := time.Now().Add(3 * time.Minute)
			existingSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa-jfrog-token",
					Namespace: "default",
					Annotations: map[string]string{
						AnnotationSecretExpiry: expiryTime.Format(time.RFC3339),
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "v1",
							Kind:       "ServiceAccount",
							Name:       "test-sa",
							UID:        "test-uid-123",
							Controller: boolPtr(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: []byte(`{"auths":{"test.jfrog.io":{"auth":"b2xk"}}}`),
				},
			}

			fakeClient = fakeclient.NewClientBuilder().
				WithScheme(testScheme).
				WithObjects(sa, existingSecret).
				Build()

			reconciler = &ServiceAccountReconciler{
				Client:           fakeClient,
				Scheme:           testScheme,
				TokenRequester:   mockTokenReq,
				JFrogClient:      mockJFrog,
				JFrogRegistry:    "test.jfrog.io",
				RenewalThreshold: 5 * time.Minute,
			}

			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: "test-sa", Namespace: "default"},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(mockJFrog.CallCount).To(Equal(1))
		})

		It("should still attach imagePullSecret even when not renewing", func() {
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "default",
					Annotations: map[string]string{
						AnnotationJFrogToken: AnnotationValueEnabled,
					},
					UID: "test-uid-123",
				},
				// No imagePullSecrets yet
			}

			expiryTime := time.Now().Add(2 * time.Hour)
			existingSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa-jfrog-token",
					Namespace: "default",
					Annotations: map[string]string{
						AnnotationSecretExpiry: expiryTime.Format(time.RFC3339),
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "v1",
							Kind:       "ServiceAccount",
							Name:       "test-sa",
							UID:        "test-uid-123",
							Controller: boolPtr(true),
						},
					},
				},
				Type: corev1.SecretTypeDockerConfigJson,
				Data: map[string][]byte{
					corev1.DockerConfigJsonKey: []byte(`{"auths":{"test.jfrog.io":{"auth":"dGVzdA=="}}}`),
				},
			}

			fakeClient = fakeclient.NewClientBuilder().
				WithScheme(testScheme).
				WithObjects(sa, existingSecret).
				Build()

			reconciler = &ServiceAccountReconciler{
				Client:           fakeClient,
				Scheme:           testScheme,
				TokenRequester:   mockTokenReq,
				JFrogClient:      mockJFrog,
				JFrogRegistry:    "test.jfrog.io",
				RenewalThreshold: 5 * time.Minute,
			}

			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{Name: "test-sa", Namespace: "default"},
			})

			Expect(err).NotTo(HaveOccurred())
			// Token should NOT be renewed
			Expect(mockJFrog.CallCount).To(Equal(0))

			// But SA should have imagePullSecret attached
			updatedSA := &corev1.ServiceAccount{}
			Expect(fakeClient.Get(ctx, types.NamespacedName{Name: "test-sa", Namespace: "default"}, updatedSA)).To(Succeed())
			Expect(updatedSA.ImagePullSecrets).To(ContainElement(corev1.LocalObjectReference{Name: "test-sa-jfrog-token"}))
		})
	})
})

var _ = Describe("DefaultJFrogClient", func() {
	Context("ExchangeToken", func() {
		It("should successfully exchange token", func() {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				Expect(r.Method).To(Equal(http.MethodPost))
				Expect(r.URL.Path).To(Equal("/access/api/v1/oidc/token"))
				Expect(r.Header.Get("Content-Type")).To(Equal("application/x-www-form-urlencoded"))

				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"access_token":"jfrog-token-123","expires_in":3600,"scope":"read","token_type":"Bearer"}`))
			}))
			defer server.Close()

			client := &DefaultJFrogClient{
				HTTPClient:   server.Client(),
				JFrogURL:     server.URL,
				ProviderName: "kubernetes",
			}

			resp, err := client.ExchangeToken(context.Background(), "test-sa-token")

			Expect(err).NotTo(HaveOccurred())
			Expect(resp.AccessToken).To(Equal("jfrog-token-123"))
			Expect(resp.ExpiresIn).To(Equal(int64(3600)))
			Expect(resp.TokenType).To(Equal("Bearer"))
		})

		DescribeTable("error handling",
			func(statusCode int, responseBody string) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(statusCode)
					w.Write([]byte(responseBody))
				}))
				defer server.Close()

				client := &DefaultJFrogClient{
					HTTPClient:   server.Client(),
					JFrogURL:     server.URL,
					ProviderName: "kubernetes",
				}

				_, err := client.ExchangeToken(context.Background(), "test-token")
				Expect(err).To(HaveOccurred())
			},
			Entry("server error", http.StatusInternalServerError, `{"error":"internal error"}`),
			Entry("unauthorized", http.StatusUnauthorized, `{"error":"invalid token"}`),
			Entry("bad request", http.StatusBadRequest, `{"error":"invalid grant"}`),
			Entry("forbidden", http.StatusForbidden, `{"error":"access denied"}`),
		)

		It("should send correct request body", func() {
			var receivedBody string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				bodyBytes := make([]byte, r.ContentLength)
				r.Body.Read(bodyBytes)
				receivedBody = string(bodyBytes)

				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			}))
			defer server.Close()

			client := &DefaultJFrogClient{
				HTTPClient:   server.Client(),
				JFrogURL:     server.URL,
				ProviderName: "my-k8s-cluster",
			}

			_, err := client.ExchangeToken(context.Background(), "my-sa-token")
			Expect(err).NotTo(HaveOccurred())

			Expect(receivedBody).To(ContainSubstring("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"))
			Expect(receivedBody).To(ContainSubstring("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token"))
			Expect(receivedBody).To(ContainSubstring("subject_token=my-sa-token"))
			Expect(receivedBody).To(ContainSubstring("provider_name=my-k8s-cluster"))
		})

		It("should handle URL with trailing slash", func() {
			var receivedPath string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			}))
			defer server.Close()

			client := &DefaultJFrogClient{
				HTTPClient:   server.Client(),
				JFrogURL:     server.URL + "/",
				ProviderName: "test",
			}

			_, err := client.ExchangeToken(context.Background(), "token")
			Expect(err).NotTo(HaveOccurred())
			Expect(receivedPath).To(Equal("/access/api/v1/oidc/token"))
			Expect(strings.Contains(receivedPath, "//")).To(BeFalse())
		})

		It("should handle URL without trailing slash", func() {
			var receivedPath string

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"access_token":"token","expires_in":3600}`))
			}))
			defer server.Close()

			client := &DefaultJFrogClient{
				HTTPClient:   server.Client(),
				JFrogURL:     server.URL,
				ProviderName: "test",
			}

			_, err := client.ExchangeToken(context.Background(), "token")
			Expect(err).NotTo(HaveOccurred())
			Expect(receivedPath).To(Equal("/access/api/v1/oidc/token"))
		})
	})
})

func boolPtr(b bool) *bool {
	return &b
}
