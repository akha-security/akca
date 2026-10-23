package app

import (
	"context"
	"errors"
	"testing"
)

func TestCancelledReflectionPhaseCannotComplete(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := new(Engine).runReflectionPayloadPhase(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel swallowed: %v", err)
	}
}
