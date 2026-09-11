package browserpool

import (
	"context"
	"encoding/json"
	"strings"
)

// SetRequestGuard binds browser HTTP traffic to the scanner's scope and budget.
// Configure it before starting browser workers.
func (r *HeadlessRenderer) SetRequestGuard(guard func(context.Context, string, string) error) {
	r.requestGuard = guard
}

func (r *HeadlessRenderer) guardBrowserRequests(ctx context.Context, c *cdpClient) error {
	if r.requestGuard == nil {
		return nil
	}
	c.mu.Lock()
	c.requestHandler = func(message cdpMessage) {
		var event struct {
			RequestID string `json:"requestId"`
			Request   struct {
				URL string `json:"url"`
			} `json:"request"`
		}
		if json.Unmarshal(message.Params, &event) != nil {
			return
		}
		method := "Fetch.continueRequest"
		params := map[string]interface{}{"requestId": event.RequestID}
		if strings.HasPrefix(event.Request.URL, "http:") || strings.HasPrefix(event.Request.URL, "https:") {
			if err := r.requestGuard(ctx, event.Request.URL, "browser"); err != nil {
				method = "Fetch.failRequest"
				params["errorReason"] = "BlockedByClient"
			}
		}
		_ = c.call(ctx, method, params, nil)
	}
	c.mu.Unlock()
	return c.call(ctx, "Fetch.enable", map[string]interface{}{"patterns": []map[string]string{{"urlPattern": "*", "requestStage": "Request"}}}, nil)
}
