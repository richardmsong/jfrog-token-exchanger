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

package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"

	"github.com/jfrog/jfrog-client-go/access"
	accessAuth "github.com/jfrog/jfrog-client-go/access/auth"
	clientConfig "github.com/jfrog/jfrog-client-go/config"
	"github.com/spf13/viper"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/richardmcsong/jfrog-token-exchanger/internal/controller"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Configure Viper to read environment variables
	viper.AutomaticEnv()
	viper.SetEnvPrefix("JTE") // Use JTE prefix to prevent environment variable collisions

	// Read required configuration
	jfrogURL := viper.GetString("JFROG_URL")
	if jfrogURL == "" {
		setupLog.Error(fmt.Errorf("missing required configuration"), "JFROG_URL environment variable is required")
		os.Exit(1)
	}

	// Validate that JFROG_URL is a valid URL
	if _, err := url.Parse(jfrogURL); err != nil {
		setupLog.Error(err, "JFROG_URL must be a valid URL", "jfrogURL", jfrogURL)
		os.Exit(1)
	}

	jfrogRegistry := viper.GetString("JFROG_REGISTRY")
	if jfrogRegistry == "" {
		setupLog.Error(fmt.Errorf("missing required configuration"), "JFROG_REGISTRY environment variable is required")
		os.Exit(1)
	}

	providerName := viper.GetString("PROVIDER_NAME")
	if providerName == "" {
		setupLog.Error(fmt.Errorf("missing required configuration"), "PROVIDER_NAME environment variable is required")
		os.Exit(1)
	}

	setupLog.Info("JFrog configuration loaded",
		"jfrogURL", jfrogURL,
		"jfrogRegistry", jfrogRegistry,
		"providerName", providerName)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "b90e027b.jfrog.io",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Create clientset for TokenRequest API
	clientset, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "unable to create clientset")
		os.Exit(1)
	}

	// Create JFrog Access Manager using the SDK
	accessDetails := accessAuth.NewAccessDetails()
	accessURL, err := url.JoinPath(jfrogURL, "access")
	if err != nil {
		setupLog.Error(err, "failed to construct JFrog access URL", "jfrogURL", jfrogURL)
		os.Exit(1)
	}
	accessDetails.SetUrl(accessURL)

	serviceConfig, err := clientConfig.NewConfigBuilder().
		SetServiceDetails(accessDetails).
		Build()
	if err != nil {
		setupLog.Error(err, "unable to create JFrog service config")
		os.Exit(1)
	}

	accessManager, err := access.New(serviceConfig)
	if err != nil {
		setupLog.Error(err, "unable to create JFrog access manager")
		os.Exit(1)
	}

	jfrogClient := &controller.DefaultJFrogClient{
		AccessManager: accessManager,
		ProviderName:  providerName,
	}

	if err = (&controller.ServiceAccountReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		TokenRequester: &controller.DefaultTokenRequester{
			Clientset: clientset,
		},
		JFrogClient:   jfrogClient,
		JFrogRegistry: jfrogRegistry,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ServiceAccount")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
