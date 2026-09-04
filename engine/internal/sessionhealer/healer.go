package sessionhealer

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ReauthFunc is the callback that executes the actual login/token refresh flow.
type ReauthFunc func(ctx context.Context) (SessionCredentials, error)

// SessionHealer coordinates thread-safe session monitoring and auto-reauthentication.
type SessionHealer struct {
	mu         sync.RWMutex
	cond       *sync.Cond
	state      SessionState
	creds      SessionCredentials
	reauth     ReauthFunc
	events     []HealEvent
	healCount  int
	maxRetries int
}

// New creates a new SessionHealer instance.
func New(initialCreds SessionCredentials, reauth ReauthFunc) *SessionHealer {
	sh := &SessionHealer{
		state:      StateActive,
		creds:      initialCreds,
		reauth:     reauth,
		maxRetries: 3,
	}
	sh.cond = sync.NewCond(&sh.mu)
	return sh
}

// GetCredentials returns current session credentials, waiting if a healing process is in flight.
func (sh *SessionHealer) GetCredentials(ctx context.Context) (SessionCredentials, error) {
	sh.mu.Lock()
	defer sh.mu.Unlock()

	for sh.state == StateHealing {
		if ctx.Err() != nil {
			return SessionCredentials{}, ctx.Err()
		}
		sh.cond.Wait()
	}

	if sh.state == StateExpired {
		return SessionCredentials{}, fmt.Errorf("session is expired and auto-healing failed")
	}

	return sh.copyCredentials(sh.creds), nil
}

// HandleResponse checks an HTTP response for session loss and triggers healing if needed.
// Returns true if healing was triggered and completed successfully.
func (sh *SessionHealer) HandleResponse(ctx context.Context, statusCode int, headers map[string]string, body, triggerURL string) (bool, error) {
	lost, reason := DetectSessionLoss(statusCode, headers, body)
	if !lost {
		return false, nil
	}

	sh.mu.Lock()
	// If another goroutine is already healing, wait for it to complete
	if sh.state == StateHealing {
		for sh.state == StateHealing {
			if ctx.Err() != nil {
				sh.mu.Unlock()
				return false, ctx.Err()
			}
			sh.cond.Wait()
		}
		sh.mu.Unlock()
		return true, nil
	}

	if sh.reauth == nil {
		sh.state = StateExpired
		sh.mu.Unlock()
		return false, fmt.Errorf("no reauth handler registered")
	}

	// Begin healing
	sh.state = StateHealing
	sh.mu.Unlock()

	start := time.Now()
	newCreds, err := sh.reauth(ctx)
	duration := time.Since(start).Milliseconds()

	sh.mu.Lock()
	defer sh.mu.Unlock()

	if err != nil {
		sh.state = StateExpired
		sh.events = append(sh.events, HealEvent{
			Timestamp:  time.Now().UTC(),
			Reason:     reason,
			TriggerURL: triggerURL,
			Success:    false,
			DurationMs: duration,
		})
		sh.cond.Broadcast()
		return false, fmt.Errorf("auto-healing failed: %w", err)
	}

	// Update credentials and resume workers
	sh.creds = newCreds
	sh.state = StateActive
	sh.healCount++
	sh.events = append(sh.events, HealEvent{
		Timestamp:  time.Now().UTC(),
		Reason:     reason,
		TriggerURL: triggerURL,
		Success:    true,
		DurationMs: duration,
	})

	sh.cond.Broadcast() // Unblock all waiting goroutines
	return true, nil
}

// HealCount returns the total number of successful session heals.
func (sh *SessionHealer) HealCount() int {
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	return sh.healCount
}

// Events returns the history of healing events.
func (sh *SessionHealer) Events() []HealEvent {
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	out := make([]HealEvent, len(sh.events))
	copy(out, sh.events)
	return out
}

func (sh *SessionHealer) copyCredentials(c SessionCredentials) SessionCredentials {
	res := SessionCredentials{
		Headers: make(map[string]string, len(c.Headers)),
		Cookies: make(map[string]string, len(c.Cookies)),
	}
	for k, v := range c.Headers {
		res.Headers[k] = v
	}
	for k, v := range c.Cookies {
		res.Cookies[k] = v
	}
	return res
}
