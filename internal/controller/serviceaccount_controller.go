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
	"fmt"
	"math"
	"time"

	"github.com/jfrog/jfrog-client-go/access"
	"github.com/jfrog/jfrog-client-go/access/services"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// AnnotationJFrogToken is the annotation key to enable JFrog token exchange
	AnnotationJFrogToken = "jfrog.io/token" // #nosec G101 -- This is an annotation key, not a credential
	// AnnotationValueEnabled is the value to enable token exchange
	AnnotationValueEnabled = "enabled"
	// AnnotationSecretExpiry is the annotation key for token expiry time
	AnnotationSecretExpiry = "jfrog.io/token-expiry" // #nosec G101 -- This is an annotation key, not a credential
	// SecretNameSuffix is the suffix for the generated secret name
	SecretNameSuffix = "-jfrog-token"
	// DefaultTokenExpirationSeconds is the default token expiration for ServiceAccount tokens
	DefaultTokenExpirationSeconds = 3600
	// DefaultRenewalThreshold is the default threshold before expiry to renew the token
	DefaultRenewalThreshold = 5 * time.Minute
)

// JFrogTokenResponse represents the response from JFrog OIDC token exchange
type JFrogTokenResponse struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// DockerConfigJSON represents the Docker config.json format
type DockerConfigJSON struct {
	Auths map[string]DockerConfigEntry `json:"auths"`
}

// DockerConfigEntry represents an entry in the Docker config
type DockerConfigEntry struct {
	Auth string `json:"auth"`
}

// JFrogClient defines the interface for JFrog API operations
type JFrogClient interface {
	ExchangeToken(ctx context.Context, saToken string) (*JFrogTokenResponse, error)
}

// TokenRequester defines the interface for requesting ServiceAccount tokens
type TokenRequester interface {
	RequestToken(ctx context.Context, namespace, name string, expirationSeconds int64) (string, error)
}

// DefaultTokenRequester implements TokenRequester using the Kubernetes API
type DefaultTokenRequester struct {
	Clientset kubernetes.Interface
}

// RequestToken requests a token for the ServiceAccount using TokenRequest API
func (r *DefaultTokenRequester) RequestToken(ctx context.Context, namespace, name string, expirationSeconds int64) (string, error) {
	tokenRequest := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &expirationSeconds,
		},
	}

	result, err := r.Clientset.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, name, tokenRequest, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create token: %w", err)
	}

	return result.Status.Token, nil
}

// DefaultJFrogClient implements JFrogClient using the JFrog Go SDK
type DefaultJFrogClient struct {
	AccessManager *access.AccessServicesManager
	ProviderName  string
}

// ExchangeToken exchanges a Kubernetes ServiceAccount token for a JFrog access token
func (c *DefaultJFrogClient) ExchangeToken(ctx context.Context, saToken string) (*JFrogTokenResponse, error) {
	params := services.CreateOidcTokenParams{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:id_token",
		OidcTokenID:      saToken,
		ProviderName:     c.ProviderName,
	}

	response, err := c.AccessManager.ExchangeOidcToken(params)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	var expiresIn int64
	if response.ExpiresIn != nil {
		// Validate ExpiresIn fits within int64 max value
		// uint is either 32-bit (max 2^32-1) or 64-bit (max 2^64-1)
		// int64 max is 2^63-1, so we need to check for overflow on 64-bit systems
		if *response.ExpiresIn > math.MaxInt64 {
			return nil, fmt.Errorf("token expiration too large to convert safely: %d", *response.ExpiresIn)
		}
		expiresIn = int64(*response.ExpiresIn) // #nosec G115 -- validated above to be <= math.MaxInt64
	}

	// Validate we received a non-empty access token
	if response.AccessToken == "" {
		return nil, fmt.Errorf("received empty access token from JFrog")
	}

	return &JFrogTokenResponse{
		AccessToken: response.AccessToken,
		ExpiresIn:   expiresIn,
		Scope:       response.Scope,
		TokenType:   response.TokenType,
	}, nil
}

// ServiceAccountReconciler reconciles a ServiceAccount object
type ServiceAccountReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	TokenRequester   TokenRequester
	JFrogClient      JFrogClient
	JFrogRegistry    string
	RenewalThreshold time.Duration
}

//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=core,resources=serviceaccounts/token,verbs=create
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ServiceAccountReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Fetch the ServiceAccount
	var sa corev1.ServiceAccount
	if err := r.Get(ctx, req.NamespacedName, &sa); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	secretName := sa.Name + SecretNameSuffix

	// Check if the annotation is set to enabled
	if !r.shouldReconcile(&sa) {
		logger.V(1).Info("ServiceAccount does not have jfrog.io/token=enabled annotation")

		// Clean up the secret if annotation was removed (owner reference only handles SA deletion, not annotation changes)
		var existingSecret corev1.Secret
		err := r.Get(ctx, client.ObjectKey{Namespace: sa.Namespace, Name: secretName}, &existingSecret)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("failed to check for existing secret: %w", err)
			}
			logger.V(1).Info("No secret found to clean up")
		}

		if err == nil {
			// Secret exists but annotation is gone - delete it
			logger.Info("Deleting JFrog token secret as annotation was removed")
			if err := r.Delete(ctx, &existingSecret); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("failed to delete orphaned secret: %w", err)
			}
		}

		// Remove from imagePullSecrets if present (regardless of whether secret was found)
		if err := r.removeImagePullSecret(ctx, &sa, secretName); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to remove imagePullSecret: %w", err)
		}

		return ctrl.Result{}, nil
	}

	logger.Info("Reconciling ServiceAccount for JFrog token exchange")

	// Check if secret already exists and if token needs renewal
	var existingSecret corev1.Secret
	secretExists := false
	needsRenewal := true

	err := r.Get(ctx, client.ObjectKey{Namespace: sa.Namespace, Name: secretName}, &existingSecret)
	if err == nil {
		secretExists = true
		needsRenewal = r.needsTokenRenewal(&existingSecret)
	} else if !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("failed to get existing secret: %w", err)
	}

	var secret *corev1.Secret
	var expiryTime time.Time

	if needsRenewal {
		logger.Info("Token needs renewal, exchanging new token")

		// Request a token from Kubernetes
		saToken, err := r.requestServiceAccountToken(ctx, &sa)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to request service account token: %w", err)
		}

		// Exchange token with JFrog
		jfrogToken, err := r.JFrogClient.ExchangeToken(ctx, saToken)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to exchange token with JFrog: %w", err)
		}

		expiryTime = time.Now().Add(time.Duration(jfrogToken.ExpiresIn) * time.Second)

		// Create the dockerconfigjson secret
		secret, err = r.createDockerConfigSecret(&sa, secretName, jfrogToken.AccessToken, expiryTime)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create docker config secret: %w", err)
		}
	} else {
		logger.Info("Token still valid, skipping renewal")
		secret = &existingSecret
		// Parse existing expiry time
		if expiryStr, ok := existingSecret.Annotations[AnnotationSecretExpiry]; ok {
			if parsedTime, err := time.Parse(time.RFC3339, expiryStr); err == nil {
				expiryTime = parsedTime
			}
		}
	}

	// Create or update the secret
	if secretExists {
		if needsRenewal {
			// Update the existing secret with new token data
			existingSecret.Data = secret.Data
			if existingSecret.Annotations == nil {
				existingSecret.Annotations = make(map[string]string)
			}
			existingSecret.Annotations[AnnotationSecretExpiry] = expiryTime.Format(time.RFC3339)
			if err := r.Update(ctx, &existingSecret); err != nil {
				if apierrors.IsConflict(err) {
					return ctrl.Result{Requeue: true}, nil
				}
				return ctrl.Result{}, fmt.Errorf("failed to update secret: %w", err)
			}
		}
	} else {
		// Set owner reference so the secret is garbage collected when the SA is deleted
		if err = controllerutil.SetControllerReference(&sa, secret, r.Scheme); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to set owner reference: %w", err)
		}
		if err = r.Create(ctx, secret); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create secret: %w", err)
		}
	}

	// Attach imagePullSecret to ServiceAccount if not already attached
	if err := r.ensureImagePullSecret(ctx, &sa, secretName); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to ensure image pull secret: %w", err)
	}

	// Calculate requeue time based on token expiry
	requeueAfter := time.Until(expiryTime) - r.getRenewalThreshold()
	if requeueAfter < 0 {
		requeueAfter = time.Minute // Requeue in 1 minute if already past threshold
	}

	logger.Info("Reconciliation complete", "requeueAfter", requeueAfter)
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// shouldReconcile checks if the ServiceAccount should be reconciled
func (r *ServiceAccountReconciler) shouldReconcile(sa *corev1.ServiceAccount) bool {
	if sa.Annotations == nil {
		return false
	}
	return sa.Annotations[AnnotationJFrogToken] == AnnotationValueEnabled
}

// needsTokenRenewal checks if the token needs to be renewed based on expiry annotation
func (r *ServiceAccountReconciler) needsTokenRenewal(secret *corev1.Secret) bool {
	if secret.Annotations == nil {
		return true
	}

	expiryStr, ok := secret.Annotations[AnnotationSecretExpiry]
	if !ok {
		return true
	}

	expiryTime, err := time.Parse(time.RFC3339, expiryStr)
	if err != nil {
		return true
	}

	threshold := r.getRenewalThreshold()
	return time.Until(expiryTime) <= threshold
}

// getRenewalThreshold returns the renewal threshold
func (r *ServiceAccountReconciler) getRenewalThreshold() time.Duration {
	if r.RenewalThreshold == 0 {
		return DefaultRenewalThreshold
	}
	return r.RenewalThreshold
}

// requestServiceAccountToken requests a token for the ServiceAccount using TokenRequest API
func (r *ServiceAccountReconciler) requestServiceAccountToken(ctx context.Context, sa *corev1.ServiceAccount) (string, error) {
	return r.TokenRequester.RequestToken(ctx, sa.Namespace, sa.Name, DefaultTokenExpirationSeconds)
}

// createDockerConfigSecret creates a dockerconfigjson secret with the JFrog token
func (r *ServiceAccountReconciler) createDockerConfigSecret(sa *corev1.ServiceAccount, secretName, accessToken string, expiryTime time.Time) (*corev1.Secret, error) {
	// Create Docker config JSON with JFrog format (token as password)
	// For JFrog Artifactory, the access token is used directly as the password.
	// The auth field format is base64(username:password). Since JFrog doesn't require
	// a username when using tokens, we use a space character as the username because
	// an empty username (":token") is invalid in the Docker config format.
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(" :%s", accessToken)))
	dockerConfig := DockerConfigJSON{
		Auths: map[string]DockerConfigEntry{
			r.JFrogRegistry: {
				Auth: auth,
			},
		},
	}

	dockerConfigBytes, err := json.Marshal(dockerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal docker config: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: sa.Namespace,
			Annotations: map[string]string{
				AnnotationSecretExpiry: expiryTime.Format(time.RFC3339),
			},
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			corev1.DockerConfigJsonKey: dockerConfigBytes,
		},
	}

	return secret, nil
}

// ensureImagePullSecret ensures the secret is attached as an imagePullSecret to the ServiceAccount
func (r *ServiceAccountReconciler) ensureImagePullSecret(ctx context.Context, sa *corev1.ServiceAccount, secretName string) error {
	// Check if already attached
	for _, ref := range sa.ImagePullSecrets {
		if ref.Name == secretName {
			return nil
		}
	}

	// Add the imagePullSecret
	sa.ImagePullSecrets = append(sa.ImagePullSecrets, corev1.LocalObjectReference{Name: secretName})
	if err := r.Update(ctx, sa); err != nil {
		return fmt.Errorf("failed to update service account: %w", err)
	}

	return nil
}

// removeImagePullSecret removes the secret from the ServiceAccount's imagePullSecrets if present
func (r *ServiceAccountReconciler) removeImagePullSecret(ctx context.Context, sa *corev1.ServiceAccount, secretName string) error {
	// Check if the secret is in the list
	found := false
	newSecrets := []corev1.LocalObjectReference{}
	for _, ref := range sa.ImagePullSecrets {
		if ref.Name == secretName {
			found = true
			// Skip this secret (effectively removing it)
			continue
		}
		newSecrets = append(newSecrets, ref)
	}

	// If not found, nothing to do
	if !found {
		return nil
	}

	// Update the ServiceAccount with the secret removed
	sa.ImagePullSecrets = newSecrets
	if err := r.Update(ctx, sa); err != nil {
		return fmt.Errorf("failed to update service account: %w", err)
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ServiceAccountReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ServiceAccount{}).
		Owns(&corev1.Secret{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(), &corev1.ServiceAccount{}, handler.OnlyControllerOwner())).
		Complete(r)
}
