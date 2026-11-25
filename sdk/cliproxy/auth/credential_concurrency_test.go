package auth

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type credentialConcurrencyTestExecutor struct {
	started chan string
	release chan struct{}
	stream  chan cliproxyexecutor.StreamChunk
}

func (e *credentialConcurrencyTestExecutor) Identifier() string { return "concurrency-test" }

func (e *credentialConcurrencyTestExecutor) Execute(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if auth.ID == "auth-a" && e.release != nil {
		e.started <- auth.ID
		select {
		case <-ctx.Done():
			return cliproxyexecutor.Response{}, ctx.Err()
		case <-e.release:
		}
	}
	return cliproxyexecutor.Response{Payload: []byte(auth.ID)}, nil
}

func (e *credentialConcurrencyTestExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if e.stream == nil {
		e.stream = make(chan cliproxyexecutor.StreamChunk)
	}
	return &cliproxyexecutor.StreamResult{Chunks: e.stream}, nil
}

func (e *credentialConcurrencyTestExecutor) Refresh(context.Context, *Auth) (*Auth, error) {
	return nil, nil
}

func (e *credentialConcurrencyTestExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, auth, req, opts)
}

func (e *credentialConcurrencyTestExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
}

func TestParseCredentialConcurrencyLimit(t *testing.T) {
	for _, test := range []struct {
		value any
		want  int64
		ok    bool
	}{
		{value: nil, want: 0, ok: true},
		{value: float64(4), want: 4, ok: true},
		{value: -1, ok: false},
		{value: 1.5, ok: false},
		{value: MaxCredentialConcurrency + 1, ok: false},
		{value: "4", ok: false},
	} {
		got, errParse := ParseCredentialConcurrencyLimit(test.value)
		if (errParse == nil) != test.ok || (test.ok && got != test.want) {
			t.Fatalf("ParseCredentialConcurrencyLimit(%v) = %d, %v; want %d, ok=%v", test.value, got, errParse, test.want, test.ok)
		}
	}
}

func TestCredentialConcurrencyTrackerLimitedAndUnlimited(t *testing.T) {
	tracker := newCredentialConcurrencyTracker()
	limited := &Auth{ID: "limited", Metadata: map[string]any{MetadataMaxConcurrency: 1}}
	release, errAcquire := tracker.acquire(limited)
	if errAcquire != nil {
		t.Fatalf("first acquire: %v", errAcquire)
	}
	if _, errBusy := tracker.acquire(limited); !isCredentialConcurrencyExceeded(errBusy) {
		t.Fatalf("second acquire error = %v, want concurrency exceeded", errBusy)
	} else if got := errBusy.(*Error).Message; got != "credential concurrency limit reached" {
		t.Fatalf("second acquire message = %q", got)
	}
	if status := tracker.status(limited); status.Current != 1 || status.Limit == nil || *status.Limit != 1 {
		t.Fatalf("limited status = %#v", status)
	}
	release()

	unlimited := &Auth{ID: "unlimited"}
	releaseA, _ := tracker.acquire(unlimited)
	releaseB, _ := tracker.acquire(unlimited)
	if status := tracker.status(unlimited); status.Current != 2 || status.Limit != nil {
		t.Fatalf("unlimited status = %#v", status)
	}
	releaseA()
	releaseB()
}

func TestCacheFirstCredentialConcurrencySpillsToNextAuth(t *testing.T) {
	const model = "concurrency-model"
	executor := &credentialConcurrencyTestExecutor{started: make(chan string, 1), release: make(chan struct{})}
	selector := NewSessionAffinitySelector(&FillFirstSelector{})
	t.Cleanup(selector.Stop)
	manager := NewManager(nil, selector, nil)
	manager.SetRetryConfig(0, 0, 1)
	manager.RegisterExecutor(executor)
	reg := registry.GetGlobalRegistry()
	for _, authID := range []string{"auth-a", "auth-b"} {
		reg.RegisterClient(authID, executor.Identifier(), []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { reg.UnregisterClient(authID) })
		metadata := map[string]any{MetadataMaxConcurrency: 1}
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: authID, Provider: executor.Identifier(), Metadata: metadata}); errRegister != nil {
			t.Fatalf("register %s: %v", authID, errRegister)
		}
	}

	newOpts := func() cliproxyexecutor.Options {
		return cliproxyexecutor.Options{Metadata: map[string]any{
			cliproxyexecutor.DerivedSessionIDMetadataKey: "shared-cache-session",
		}}
	}
	firstDone := make(chan error, 1)
	go func() {
		_, errExecute := manager.Execute(context.Background(), []string{executor.Identifier()}, cliproxyexecutor.Request{Model: model}, newOpts())
		firstDone <- errExecute
	}()
	<-executor.started

	second, errSecond := manager.Execute(context.Background(), []string{executor.Identifier()}, cliproxyexecutor.Request{Model: model}, newOpts())
	if errSecond != nil {
		t.Fatalf("second execute: %v", errSecond)
	}
	if got := string(second.Payload); got != "auth-b" {
		t.Fatalf("second execute auth = %q, want auth-b", got)
	}
	other, _ := manager.GetByID("auth-b")
	releaseOther, errAcquire := manager.acquireCredentialConcurrency(other)
	if errAcquire != nil {
		t.Fatal(errAcquire)
	}
	defer releaseOther()
	_, errFull := manager.ExecuteCount(context.Background(), []string{executor.Identifier()}, cliproxyexecutor.Request{Model: model}, newOpts())
	if !isCredentialConcurrencyExceeded(errFull) || statusCodeFromError(errFull) != http.StatusTooManyRequests {
		t.Fatalf("all credentials full: %v, want concurrency 429", errFull)
	}
	if updated, _ := manager.GetByID("auth-b"); updated.Failed != 0 || updated.Unavailable {
		t.Fatal("saturation marked a credential as failed")
	}
	close(executor.release)
	if errFirst := <-firstDone; errFirst != nil {
		t.Fatalf("first execute: %v", errFirst)
	}
}

func TestVerifyInferenceRespectsCredentialConcurrency(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	executor := &credentialConcurrencyTestExecutor{}
	manager.RegisterExecutor(executor)
	auth, errRegister := manager.Register(t.Context(), &Auth{
		ID: "verify", Provider: executor.Identifier(), Metadata: map[string]any{MetadataMaxConcurrency: 1},
	})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	release, errAcquire := manager.acquireCredentialConcurrency(auth)
	if errAcquire != nil {
		t.Fatal(errAcquire)
	}
	defer release()
	if _, errVerify := manager.VerifyInference(t.Context(), auth.ID, "verify-model"); !isCredentialConcurrencyExceeded(errVerify) {
		t.Fatalf("verify error = %v, want concurrency exceeded", errVerify)
	}
	if executor.stream != nil {
		t.Fatal("verification opened a stream for a saturated credential")
	}
}

func TestExecuteStreamCredentialConcurrencyReleasesOnClose(t *testing.T) {
	const model = "concurrency-stream-model"
	manager := NewManager(nil, nil, nil)
	executor := &credentialConcurrencyTestExecutor{stream: make(chan cliproxyexecutor.StreamChunk, 1)}
	manager.RegisterExecutor(executor)
	auth, errRegister := manager.Register(t.Context(), &Auth{
		ID: "stream", Provider: executor.Identifier(), Metadata: map[string]any{MetadataMaxConcurrency: 1},
	})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, executor.Identifier(), []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })
	request := cliproxyexecutor.Request{Model: model}
	options := cliproxyexecutor.Options{Stream: true}
	executor.stream <- cliproxyexecutor.StreamChunk{Payload: []byte("first")}
	result, errExecute := manager.ExecuteStream(t.Context(), []string{executor.Identifier()}, request, options)
	if errExecute != nil {
		t.Fatalf("execute stream: %v", errExecute)
	}
	if chunk := <-result.Chunks; string(chunk.Payload) != "first" {
		t.Fatalf("first chunk = %#v", chunk)
	}
	if status := manager.CredentialConcurrency(auth); status.Current != 1 {
		t.Fatalf("current while stream open = %d, want 1", status.Current)
	}
	if _, errBusy := manager.ExecuteStream(t.Context(), []string{executor.Identifier()}, request, options); !isCredentialConcurrencyExceeded(errBusy) {
		t.Fatalf("second stream = %v, want concurrency exceeded", errBusy)
	}
	close(executor.stream)
	for range result.Chunks {
	}
	if status := manager.CredentialConcurrency(auth); status.Current != 0 {
		t.Fatalf("current after stream close = %d, want 0", status.Current)
	}
}

func TestCredentialConcurrencySurvivesConcurrentRefresh(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, nil, nil)
	base, errRegister := manager.Register(ctx, &Auth{ID: "refresh", Provider: "codex", Metadata: map[string]any{MetadataMaxConcurrency: 1}})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	userUpdate := base.Clone()
	userUpdate.Metadata[MetadataMaxConcurrency] = 2
	if _, errUpdate := manager.Update(ctx, userUpdate); errUpdate != nil {
		t.Fatal(errUpdate)
	}
	refreshed := base.Clone()
	refreshed.Metadata["access_token"] = "refreshed-token"
	merged, errRefresh := manager.UpdateRefreshedAuth(ctx, base, refreshed)
	if errRefresh != nil {
		t.Fatal(errRefresh)
	}
	if limit, errLimit := CredentialConcurrencyLimit(merged); errLimit != nil || limit != 2 {
		t.Fatalf("concurrent user limit lost: %d, %v", limit, errLimit)
	}
}
