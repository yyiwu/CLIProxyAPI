package auth

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
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
	manager.RegisterExecutor(executor)
	reg := registry.GetGlobalRegistry()
	for _, authID := range []string{"auth-a", "auth-b"} {
		reg.RegisterClient(authID, executor.Identifier(), []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { reg.UnregisterClient(authID) })
		metadata := map[string]any{}
		if authID == "auth-a" {
			metadata[MetadataMaxConcurrency] = 1
		}
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
	close(executor.release)
	if errFirst := <-firstDone; errFirst != nil {
		t.Fatalf("first execute: %v", errFirst)
	}
}

func TestExecuteStreamCredentialConcurrencyReleasesOnClose(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	auth := &Auth{ID: "stream", Metadata: map[string]any{MetadataMaxConcurrency: 1}}
	executor := &credentialConcurrencyTestExecutor{stream: make(chan cliproxyexecutor.StreamChunk)}
	result, errExecute := manager.executeStreamWithCredentialConcurrency(context.Background(), executor, auth, cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if errExecute != nil {
		t.Fatalf("execute stream: %v", errExecute)
	}
	if status := manager.CredentialConcurrency(auth); status.Current != 1 {
		t.Fatalf("current while stream open = %d, want 1", status.Current)
	}
	close(executor.stream)
	for range result.Chunks {
	}
	if status := manager.CredentialConcurrency(auth); status.Current != 0 {
		t.Fatalf("current after stream close = %d, want 0", status.Current)
	}
}
