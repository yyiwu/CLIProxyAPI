package cliproxy

import (
	"context"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestCacheFirstRoutingUsesSessionAffinityWithFillFirstFallback(t *testing.T) {
	state := normalizedRoutingRuntimeState(&internalconfig.Config{Routing: internalconfig.RoutingConfig{Strategy: "cf"}})
	if state.strategy != "cache-first" {
		t.Fatalf("strategy = %q, want cache-first", state.strategy)
	}
	selector, ok := newRoutingSelector(state).(*coreauth.SessionAffinitySelector)
	if !ok {
		t.Fatalf("selector type = %T, want SessionAffinitySelector", newRoutingSelector(state))
	}
	t.Cleanup(selector.Stop)
	auths := []*coreauth.Auth{
		{ID: "auth-b", Provider: "codex"},
		{ID: "auth-a", Provider: "codex"},
	}
	selected, errPick := selector.Pick(context.Background(), "codex", "model", cliproxyexecutor.Options{}, auths)
	if errPick != nil {
		t.Fatalf("pick: %v", errPick)
	}
	if selected.ID != "auth-a" {
		t.Fatalf("selected = %q, want auth-a", selected.ID)
	}
}
