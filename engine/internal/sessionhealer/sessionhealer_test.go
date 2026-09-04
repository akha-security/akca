package sessionhealer

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestDetectSessionLoss(t *testing.T) {
	// Test 401
	lost, reason := DetectSessionLoss(401, nil, "Unauthorized")
	if !lost || reason != ReasonHTTP401 {
		t.Errorf("expected ReasonHTTP401, got %v (%s)", lost, reason)
	}

	// Test Login Redirect
	lost, reason = DetectSessionLoss(302, map[string]string{"Location": "https://example.com/auth/login?return=/dashboard"}, "")
	if !lost || reason != ReasonLoginRedirect {
		t.Errorf("expected ReasonLoginRedirect, got %v (%s)", lost, reason)
	}

	// Test JSON Token Expired
	lost, reason = DetectSessionLoss(403, nil, `{"error":"token_expired","message":"The access token has expired"}`)
	if !lost || reason != ReasonTokenExpired {
		t.Errorf("expected ReasonTokenExpired, got %v (%s)", lost, reason)
	}

	// Test Normal 200 OK
	lost, _ = DetectSessionLoss(200, nil, `{"status":"ok"}`)
	if lost {
		t.Error("expected no session loss for 200 OK")
	}
}

func TestConcurrentSessionHealing(t *testing.T) {
	initialCreds := SessionCredentials{
		Headers: map[string]string{"Authorization": "Bearer old_expired_token"},
		Cookies: map[string]string{"session_id": "old_session_123"},
	}

	healCalls := 0
	var healMu sync.Mutex

	reauthMock := func(ctx context.Context) (SessionCredentials, error) {
		healMu.Lock()
		healCalls++
		healMu.Unlock()
		time.Sleep(50 * time.Millisecond) // simulate login latency

		return SessionCredentials{
			Headers: map[string]string{"Authorization": "Bearer fresh_valid_token_456"},
			Cookies: map[string]string{"session_id": "fresh_session_789"},
		}, nil
	}

	healer := New(initialCreds, reauthMock)

	// Simulate 10 parallel workers hitting 401 Unauthorized simultaneously
	var wg sync.WaitGroup
	workers := 10
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(id int) {
			defer wg.Done()
			// Handle response triggers healing
			_, _ = healer.HandleResponse(context.Background(), 401, nil, "Unauthorized", "https://example.com/api/v1/profile")

			// Fetch updated credentials
			creds, err := healer.GetCredentials(context.Background())
			if err != nil {
				t.Errorf("worker %d failed to get credentials: %v", id, err)
				return
			}
			if creds.Headers["Authorization"] != "Bearer fresh_valid_token_456" {
				t.Errorf("worker %d got wrong token: %s", id, creds.Headers["Authorization"])
			}
		}(i)
	}

	wg.Wait()

	if healCalls != 1 {
		t.Fatalf("expected exactly 1 reauth call due to mutex locking, got %d", healCalls)
	}
	if healer.HealCount() != 1 {
		t.Fatalf("expected healCount 1, got %d", healer.HealCount())
	}
	if len(healer.Events()) != 1 {
		t.Fatalf("expected 1 heal event, got %d", len(healer.Events()))
	}
}
