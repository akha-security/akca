package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/branding"
)

type Notifier struct {
	client *http.Client
}

func NewNotifier() *Notifier {
	return &Notifier{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// SendAlert delivers an alert to the target webhook according to its platform formatting.
func (n *Notifier) SendAlert(ctx context.Context, webhookURL string, wType WebhookType, alert FindingAlert) error {
	if strings.TrimSpace(webhookURL) == "" {
		return fmt.Errorf("empty webhook URL")
	}

	var payload []byte
	var err error

	switch wType {
	case WebhookSlack:
		payload, err = buildSlackPayload(alert)
	case WebhookDiscord:
		payload, err = buildDiscordPayload(alert)
	case WebhookTelegram:
		payload, err = buildTelegramPayload(alert)
	default:
		payload, err = json.Marshal(alert)
	}

	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook responded with HTTP status %d", resp.StatusCode)
	}

	return nil
}

func buildSlackPayload(alert FindingAlert) ([]byte, error) {
	color := "#36a64f"
	switch strings.ToLower(alert.Severity) {
	case "critical":
		color = "#ff0000"
	case "high":
		color = "#ff6600"
	case "medium":
		color = "#ffcc00"
	}

	msg := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"title": fmt.Sprintf("🚨 [%s] %s", strings.ToUpper(alert.Severity), alert.Title),
				"fields": []map[string]interface{}{
					{"title": "Endpoint", "value": alert.Endpoint, "short": false},
					{"title": "Parameter", "value": alert.Parameter, "short": true},
					{"title": "Confidence", "value": alert.Confidence, "short": true},
					{"title": "Description", "value": alert.Description, "short": false},
				},
				"footer": branding.ProductName,
				"ts":     alert.Timestamp.Unix(),
			},
		},
	}
	return json.Marshal(msg)
}

func buildDiscordPayload(alert FindingAlert) ([]byte, error) {
	color := 0x36a64f
	switch strings.ToLower(alert.Severity) {
	case "critical":
		color = 0xff0000
	case "high":
		color = 0xff6600
	case "medium":
		color = 0xffcc00
	}

	msg := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("🚨 [%s] %s", strings.ToUpper(alert.Severity), alert.Title),
				"description": alert.Description,
				"color":       color,
				"fields": []map[string]interface{}{
					{"name": "Endpoint", "value": alert.Endpoint, "inline": false},
					{"name": "Parameter", "value": alert.Parameter, "inline": true},
					{"name": "Confidence", "value": alert.Confidence, "inline": true},
				},
				"footer": map[string]string{"text": branding.ProductName},
			},
		},
	}
	return json.Marshal(msg)
}

func buildTelegramPayload(alert FindingAlert) ([]byte, error) {
	text := fmt.Sprintf("🚨 <b>[%s] %s</b>\n\n<b>Endpoint:</b> %s\n<b>Parameter:</b> %s\n<b>Confidence:</b> %s\n\n%s",
		strings.ToUpper(alert.Severity),
		htmlEscape(alert.Title),
		htmlEscape(alert.Endpoint),
		htmlEscape(alert.Parameter),
		htmlEscape(alert.Confidence),
		htmlEscape(alert.Description),
	)

	msg := map[string]interface{}{
		"text":       text,
		"parse_mode": "HTML",
	}
	return json.Marshal(msg)
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
