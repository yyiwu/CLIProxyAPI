package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const (
	// MetadataMaxConcurrency is the canonical auth-file key for a credential's local concurrency limit.
	MetadataMaxConcurrency = "max_concurrency"
	// MaxCredentialConcurrency bounds operator input while remaining effectively unlimited in practice.
	MaxCredentialConcurrency          int64 = 1_000_000
	credentialConcurrencyExceededCode       = "credential_concurrency_exceeded"
)

// CredentialConcurrencyStatus is the current local in-flight usage for one credential.
// A nil Limit means unlimited.
type CredentialConcurrencyStatus struct {
	Current int64  `json:"current"`
	Limit   *int64 `json:"limit"`
}

type credentialConcurrencyTracker struct {
	mu      sync.Mutex
	current map[string]int64
}

func newCredentialConcurrencyTracker() *credentialConcurrencyTracker {
	return &credentialConcurrencyTracker{current: make(map[string]int64)}
}

// ParseCredentialConcurrencyLimit parses an optional JSON-compatible limit.
// Missing values and zero mean unlimited.
func ParseCredentialConcurrencyLimit(value any) (int64, error) {
	if value == nil {
		return 0, nil
	}
	var limit int64
	switch typed := value.(type) {
	case int:
		limit = int64(typed)
	case int8:
		limit = int64(typed)
	case int16:
		limit = int64(typed)
	case int32:
		limit = int64(typed)
	case int64:
		limit = typed
	case uint:
		if uint64(typed) > uint64(MaxCredentialConcurrency) {
			return 0, fmt.Errorf("max_concurrency must not exceed %d", MaxCredentialConcurrency)
		}
		limit = int64(typed)
	case uint8:
		limit = int64(typed)
	case uint16:
		limit = int64(typed)
	case uint32:
		limit = int64(typed)
	case uint64:
		if typed > uint64(MaxCredentialConcurrency) {
			return 0, fmt.Errorf("max_concurrency must not exceed %d", MaxCredentialConcurrency)
		}
		limit = int64(typed)
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) || math.Trunc(typed) != typed {
			return 0, fmt.Errorf("max_concurrency must be an integer")
		}
		if typed > float64(MaxCredentialConcurrency) {
			return 0, fmt.Errorf("max_concurrency must not exceed %d", MaxCredentialConcurrency)
		}
		limit = int64(typed)
	case float32:
		return ParseCredentialConcurrencyLimit(float64(typed))
	case json.Number:
		parsed, errParse := typed.Int64()
		if errParse != nil {
			return 0, fmt.Errorf("max_concurrency must be an integer")
		}
		limit = parsed
	default:
		return 0, fmt.Errorf("max_concurrency must be an integer")
	}
	if limit < 0 {
		return 0, fmt.Errorf("max_concurrency must not be negative")
	}
	if limit > MaxCredentialConcurrency {
		return 0, fmt.Errorf("max_concurrency must not exceed %d", MaxCredentialConcurrency)
	}
	return limit, nil
}

// CredentialConcurrencyLimit returns the configured limit for an auth.
func CredentialConcurrencyLimit(auth *Auth) (int64, error) {
	if auth == nil || auth.Metadata == nil {
		return 0, nil
	}
	return ParseCredentialConcurrencyLimit(auth.Metadata[MetadataMaxConcurrency])
}

// ValidateAuthConcurrency validates a credential's optional local concurrency limit.
func ValidateAuthConcurrency(auth *Auth) error {
	_, err := CredentialConcurrencyLimit(auth)
	return err
}

// ApplyAuthConcurrencyMetadata validates and applies a source auth-file limit.
func ApplyAuthConcurrencyMetadata(auth *Auth, metadata map[string]any) error {
	if auth == nil || metadata == nil {
		return nil
	}
	rawLimit, ok := metadata[MetadataMaxConcurrency]
	if !ok {
		return ValidateAuthConcurrency(auth)
	}
	limit, errLimit := ParseCredentialConcurrencyLimit(rawLimit)
	if errLimit != nil {
		return errLimit
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata[MetadataMaxConcurrency] = limit
	return nil
}

func (t *credentialConcurrencyTracker) acquire(auth *Auth) (func(), error) {
	limit, errLimit := CredentialConcurrencyLimit(auth)
	if errLimit != nil {
		return nil, errLimit
	}
	if auth == nil || strings.TrimSpace(auth.ID) == "" {
		return func() {}, nil
	}
	authID := strings.TrimSpace(auth.ID)
	// ponytail: one short global lock keeps acquisition atomic; shard only if profiling shows contention.
	t.mu.Lock()
	current := t.current[authID]
	if limit > 0 && current >= limit {
		t.mu.Unlock()
		return nil, &Error{
			Code:       credentialConcurrencyExceededCode,
			Message:    "credential concurrency limit reached",
			Retryable:  true,
			HTTPStatus: http.StatusTooManyRequests,
		}
	}
	t.current[authID] = current + 1
	t.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			remaining := t.current[authID] - 1
			if remaining <= 0 {
				delete(t.current, authID)
			} else {
				t.current[authID] = remaining
			}
			t.mu.Unlock()
		})
	}, nil
}

func (t *credentialConcurrencyTracker) status(auth *Auth) CredentialConcurrencyStatus {
	status := CredentialConcurrencyStatus{}
	if auth == nil {
		return status
	}
	limit, errLimit := CredentialConcurrencyLimit(auth)
	if errLimit == nil && limit > 0 {
		status.Limit = &limit
	}
	t.mu.Lock()
	status.Current = t.current[strings.TrimSpace(auth.ID)]
	t.mu.Unlock()
	return status
}

// CredentialConcurrency returns the current local concurrency status for an auth.
func (m *Manager) CredentialConcurrency(auth *Auth) CredentialConcurrencyStatus {
	if m == nil || m.credentialConcurrency == nil {
		return CredentialConcurrencyStatus{}
	}
	return m.credentialConcurrency.status(auth)
}

func (m *Manager) acquireCredentialConcurrency(auth *Auth) (func(), error) {
	if m == nil || m.HomeEnabled() || m.credentialConcurrency == nil {
		return func() {}, nil
	}
	return m.credentialConcurrency.acquire(auth)
}

func isCredentialConcurrencyExceeded(err error) bool {
	var authErr *Error
	return err != nil && errors.As(err, &authErr) && authErr != nil && authErr.Code == credentialConcurrencyExceededCode
}

func (m *Manager) executeWithCredentialConcurrency(ctx context.Context, executor ProviderExecutor, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	release, errAcquire := m.acquireCredentialConcurrency(auth)
	if errAcquire != nil {
		return cliproxyexecutor.Response{}, errAcquire
	}
	defer release()
	return executor.Execute(ctx, auth, req, opts)
}

func (m *Manager) countTokensWithCredentialConcurrency(ctx context.Context, executor ProviderExecutor, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	release, errAcquire := m.acquireCredentialConcurrency(auth)
	if errAcquire != nil {
		return cliproxyexecutor.Response{}, errAcquire
	}
	defer release()
	return executor.CountTokens(ctx, auth, req, opts)
}

func (m *Manager) executeStreamWithCredentialConcurrency(ctx context.Context, executor ProviderExecutor, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if m == nil || m.HomeEnabled() || m.credentialConcurrency == nil {
		return executor.ExecuteStream(ctx, auth, req, opts)
	}
	release, errAcquire := m.acquireCredentialConcurrency(auth)
	if errAcquire != nil {
		return nil, errAcquire
	}
	result, errExecute := executor.ExecuteStream(ctx, auth, req, opts)
	if errExecute != nil || result == nil || result.Chunks == nil {
		release()
		return result, errExecute
	}
	source := result.Chunks
	out := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(out)
		defer release()
		for chunk := range source {
			out <- chunk
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: result.Headers, Chunks: out}, nil
}

type concurrencyReleaseReadCloser struct {
	io.ReadCloser
	release func()
}

func (r *concurrencyReleaseReadCloser) Close() error {
	errClose := r.ReadCloser.Close()
	r.release()
	return errClose
}

func (m *Manager) httpRequestWithCredentialConcurrency(ctx context.Context, executor ProviderExecutor, auth *Auth, req *http.Request) (*http.Response, error) {
	release, errAcquire := m.acquireCredentialConcurrency(auth)
	if errAcquire != nil {
		return nil, errAcquire
	}
	response, errExecute := executor.HttpRequest(ctx, auth, req)
	if errExecute != nil || response == nil || response.Body == nil {
		release()
		return response, errExecute
	}
	response.Body = &concurrencyReleaseReadCloser{ReadCloser: response.Body, release: release}
	return response, nil
}
