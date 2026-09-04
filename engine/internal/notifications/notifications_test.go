package notifications

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSendAlertPlatforms(t *testing.T) {
	alert := FindingAlert{
		ScanID:      "scan-123",
		FindingID:   42,
		Title:       "SQL Injection in /api/users",
		Severity:    "critical",
		VulnClass:   "sqli",
		Endpoint:    "https://example.com/api/users",
		Parameter:   "id",
		Confidence:  "Confirmed",
		Description: "Time-based blind SQL injection confirmed.",
		Timestamp:   time.Now(),
	}

	platforms := []WebhookType{WebhookSlack, WebhookDiscord, WebhookTelegram, WebhookGeneric}

	for _, p := range platforms {
		t.Run(string(p), func(t *testing.T) {
			received := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received = true
				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("expected application/json content-type")
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			n := NewNotifier()
			err := n.SendAlert(context.Background(), server.URL, p, alert)
			if err != nil {
				t.Fatalf("unexpected error sending %s alert: %v", p, err)
			}
			if !received {
				t.Fatalf("server did not receive %s request", p)
			}
		})
	}
}

func TestBuildSlackAndDiscordPayloads(t *testing.T) {
	alert := FindingAlert{
		Title:    "RCE",
		Severity: "critical",
	}

	slack, err := buildSlackPayload(alert)
	if err != nil || !strings.Contains(string(slack), "#ff0000") {
		t.Errorf("expected red color in slack payload: %s", string(slack))
	}

	discord, err := buildDiscordPayload(alert)
	if err != nil || !strings.Contains(string(discord), "16711680") { // 0xff0000 = 16711680
		t.Errorf("expected red color in discord payload: %s", string(discord))
	}
}
