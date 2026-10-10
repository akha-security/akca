package modules

import (
	"context"
	"testing"
)

func TestClassifyTargetRunKeepsUsableCoverageDespiteFailedVariant(t *testing.T) {
	state := &targetRun{}
	state.requests.Store(2)
	state.responses.Store(1)
	state.usableResponses.Store(1)
	state.usableResponse.Store(true)
	state.evidence.Store(true)
	state.failures.Store(1)
	state.transportErrors.Store(1)

	status, _ := classifyTargetRun(state, false, 0, nil)
	if status != "completed" {
		t.Fatalf("a failed payload variant masked usable target coverage: %q", status)
	}
}

func TestClassifyTargetRunKeepsFindingDespiteFailedVariant(t *testing.T) {
	state := &targetRun{}
	state.failures.Store(1)

	status, _ := classifyTargetRun(state, false, 1, nil)
	if status != "completed" {
		t.Fatalf("a failed payload variant masked a confirmed finding: %q", status)
	}
}

func TestClassifyTargetRunExplicitFailedControlIsError(t *testing.T) {
	state := &targetRun{}
	state.usableResponse.Store(true)
	state.evidence.Store(true)
	state.failures.Store(1)
	state.skipped("raw protocol negative control failed")

	status, reason := classifyTargetRun(state, false, 0, nil)
	if status != "error" {
		t.Fatalf("failed required control status = %q, want error", status)
	}
	if reason != "raw protocol negative control failed" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestClassifyTargetRunTreatsBlockedTargetAsInapplicable(t *testing.T) {
	state := &targetRun{}
	state.requests.Store(1)
	state.responses.Store(1)
	state.evidence.Store(true)
	state.blockedResponse.Store(true)
	state.authBlocks.Store(1)

	status, reason := classifyTargetRun(state, false, 0, nil)
	if status != "blocked" {
		t.Fatalf("an access-controlled target should not fail the whole module: %q", status)
	}
	if reason == "" {
		t.Fatal("blocked target omitted its diagnostic reason")
	}
}

func TestClassifyTargetRunStillReportsRealIncompleteWork(t *testing.T) {
	t.Run("transport failure without evidence", func(t *testing.T) {
		state := &targetRun{}
		state.failures.Store(1)
		state.transportErrors.Store(1)
		status, _ := classifyTargetRun(state, false, 0, nil)
		if status != "error" {
			t.Fatalf("unusable transport failure status = %q", status)
		}
	})

	t.Run("interrupted verification", func(t *testing.T) {
		state := &targetRun{}
		state.interrupted.Store(true)
		status, reason := classifyTargetRun(state, false, 0, context.Canceled)
		if status != "incomplete" || reason != context.Canceled.Error() {
			t.Fatalf("interrupted status=%q reason=%q", status, reason)
		}
	})

	t.Run("budget exhaustion", func(t *testing.T) {
		state := &targetRun{}
		state.budgetExhausted.Store(true)
		status, _ := classifyTargetRun(state, false, 0, nil)
		if status != "incomplete" {
			t.Fatalf("budget exhaustion status = %q", status)
		}
	})
}
