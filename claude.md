# Claude Development Notes

## Project Conventions

### Use Make for All Lifecycle Commands

**IMPORTANT:** Always use `make` commands instead of bare Go commands. The Makefile ensures proper environment setup and runs all necessary pre-steps.

#### Available Make Targets

**Development:**
- `make test` - Run tests (includes setup-envtest, coverage, formatting, vetting)
- `make build` - Build the manager binary
- `make fmt` - Format code with go fmt
- `make fmt-check` - Check if code is formatted
- `make vet` - Run go vet against code
- `make manifests` - Generate WebhookConfiguration, ClusterRole and CRD objects
- `make generate` - Generate DeepCopy, DeepCopyInto, and DeepCopyObject methods

**Build & Deploy:**
- `make docker-build` - Build Docker image
- `make docker-push` - Push Docker image
- `make docker-buildx` - Build and push for cross-platform support
- `make deploy` - Deploy controller to K8s cluster
- `make undeploy` - Remove controller from K8s cluster

**Installation:**
- `make install` - Install CRDs into K8s cluster
- `make uninstall` - Uninstall CRDs from K8s cluster

**Why use Make instead of bare commands:**
- Ensures KUBEBUILDER_ASSETS environment is properly configured
- Runs code generation, formatting, and vetting before tests/builds
- Downloads and manages tool versions (controller-gen, setup-envtest, kustomize)
- Maintains consistency across different development environments

## Development History

### 2025-12-31: Refactored to Use JFrog Go Client SDK

Refactored the codebase to use the official JFrog Go client library instead of manual HTTP client implementation.

#### Changes Made

**1. Dependencies** ([go.mod](go.mod))
- Added `github.com/jfrog/jfrog-client-go v1.55.0`
- All transitive dependencies automatically resolved via `go mod tidy`

**2. Controller Refactoring** ([internal/controller/serviceaccount_controller.go](internal/controller/serviceaccount_controller.go))
- **Before:** `DefaultJFrogClient` used manual HTTP client with custom request handling
- **After:** Uses SDK's `access.AccessServicesManager`
- Removed ~30 lines of manual HTTP request construction, URL encoding, and JSON parsing
- `ExchangeToken` method now uses SDK's `ExchangeOidcToken` API
- Properly handles SDK's `auth.OidcTokenResponseData` with embedded `CommonTokenParams`
- Handles SDK's pointer-based `ExpiresIn` field (`*uint`)

**3. Main Initialization** ([cmd/main.go](cmd/main.go))
- Created `AccessDetails` using `accessAuth.NewAccessDetails()`
- Built service config with `clientConfig.NewConfigBuilder()`
- Initialized Access Manager using `access.New(serviceConfig)`
- Removed manual HTTP client and TLS configuration (SDK handles this)

**4. Test Updates** ([internal/controller/serviceaccount_controller_test.go](internal/controller/serviceaccount_controller_test.go))
- Removed HTTP-level mock tests (SDK handles this internally)
- Kept high-level `MockJFrogClient` integration tests
- Tests pass with 72.1% code coverage

#### Benefits

- **Maintainability:** Using official SDK means automatic updates and bug fixes
- **Reliability:** SDK is tested and maintained by JFrog
- **Simplicity:** Removed manual HTTP/JSON handling code
- **Type Safety:** SDK provides proper type definitions and validation
- **Future-proof:** Easy to adopt new SDK features as they're released

#### Testing

All tests pass successfully:
```bash
make test
# ✅ internal/controller: 72.1% coverage
# ✅ All formatting and linting checks pass
```

#### SDK Documentation

- **GitHub:** https://github.com/jfrog/jfrog-client-go
- **Go Package:** https://pkg.go.dev/github.com/jfrog/jfrog-client-go
- **Official Docs:** https://docs.jfrog-applications.jfrog.io/ci-and-sdks/sdks/jfrog-go-client

#### Key SDK Types Used

- `access.AccessServicesManager` - Main SDK manager for Access API operations
- `services.CreateOidcTokenParams` - Parameters for OIDC token exchange
- `auth.OidcTokenResponseData` - Response from token exchange
- `auth.CommonTokenParams` - Common token fields (AccessToken, ExpiresIn, Scope, TokenType)

#### CI Issue Resolution: Go 1.24.6 Type Checker Bug

**Problem:** CI tests were failing with `controller-gen` panic during object generation:
```
panic: runtime error: invalid memory address or nil pointer dereference
go/types.(*StdSizes).Sizeof(0x0, ...)
```

**Root Cause:**
- Go 1.24.6 has a type checker bug where `StdSizes` can be nil when analyzing structs containing external package types
- `controller-gen` runs Go's type checker on all structs in `./...` including `DefaultJFrogClient`
- When it encounters `access.AccessServicesManager` (external SDK type), the nil pointer bug is triggered
- The panic occurs during the `make test` → `make generate` → `controller-gen object:...` phase

**Why It Only Failed in CI:**
- Local environment: Go 1.25.5 (has the bug fix) ✅
- CI environment: Go 1.24.6 from `go.mod` (has the bug) ❌
- Different Go versions = different type checker behavior

**Solution:**
Updated `go.mod` from `go 1.24.6` to `go 1.25`
- Go 1.25 includes the type checker fix
- No code changes required
- Addresses root cause rather than working around it

**Alternative Solutions Considered:**
1. Add `// +kubebuilder:object:generate=false` markers (workaround)
2. Move types to separate package excluded from controller-gen (complex)
3. Update Go version (chosen - simplest and most correct)

#### golangci-lint Configuration: Go 1.25 Compatibility

**Problem:** After updating to Go 1.25, golangci-lint v2.7.2 flagged several issues:
1. **gosec G101**: False positive on annotation constants (`AnnotationJFrogToken`, `AnnotationSecretExpiry`)
2. **fieldalignment**: `JFrogTokenResponse` struct had suboptimal field ordering (48 pointer bytes instead of 40)

**Solutions:**

1. **gosec false positives** ([internal/controller/serviceaccount_controller.go](internal/controller/serviceaccount_controller.go:43-47))
   - Added `// #nosec G101 -- This is an annotation key, not a credential` inline comments
   - gosec incorrectly flags string constants containing "token" as potential hardcoded credentials
   - These are Kubernetes annotation keys, not actual credentials

2. **fieldalignment optimization** ([internal/controller/serviceaccount_controller.go](internal/controller/serviceaccount_controller.go:57-62))
   - Reordered `JFrogTokenResponse` struct fields to minimize memory padding
   - Placed `int64` field first, then string fields
   - Before: `AccessToken, Scope, TokenType, ExpiresIn` (48 pointer bytes)
   - After: `ExpiresIn, AccessToken, Scope, TokenType` (40 pointer bytes)
   - Tests still pass with 72.1% coverage ✅

#### Migration Notes for Future Reference

When working with the SDK:
1. `ExpiresIn` is returned as `*uint` (pointer to unsigned int), convert to `int64` for our API
2. Response type is `auth.OidcTokenResponseData` with embedded `CommonTokenParams`
3. The SDK handles all HTTP-level details (TLS, retries, error handling)
4. No need to manually construct URLs or handle URL encoding - SDK does this
5. Requires Go 1.25+ due to type checker bug in earlier versions when embedding external SDK types
6. Struct field ordering matters for memory efficiency - place larger fields (int64, pointers) before smaller ones (strings)
