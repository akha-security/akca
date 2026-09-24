package browserpool

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
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
			RequestID    string `json:"requestId"`
			ResourceType string `json:"resourceType"`
			Request      struct {
				URL     string            `json:"url"`
				Method  string            `json:"method"`
				Headers map[string]string `json:"headers"`
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
				if errors.Is(err, httpclient.ErrOutsideScope) && r.resourceGuard != nil && passiveBrowserResource(event.ResourceType, event.Request.Method) && r.resourceGuard(ctx, event.Request.URL, "browser_resource") == nil {
					method = "Fetch.continueRequest"
					delete(params, "errorReason")
					params["headers"] = passiveResourceHeaders(event.Request.Headers)
				}
			}
		}
		if method == "Fetch.failRequest" {
			r.blockedMu.Lock()
			if len(r.blockedResources) < 100 {
				r.blockedResources = append(r.blockedResources, event.Request.URL)
			}
			r.blockedMu.Unlock()
		}
		_ = c.call(ctx, method, params, nil)
	}
	c.mu.Unlock()
	return c.call(ctx, "Fetch.enable", map[string]interface{}{"patterns": []map[string]string{{"urlPattern": "*", "requestStage": "Request"}}}, nil)
}

func passiveBrowserResource(kind, method string) bool {
	if method != "GET" && method != "HEAD" {
		return false
	}
	switch kind {
	case "Script", "Stylesheet", "Image", "Font", "Media":
		return true
	}
	return false
}

func passiveResourceHeaders(headers map[string]string) []map[string]string {
	out := []map[string]string{}
	for name, value := range headers {
		switch strings.ToLower(name) {
		case "accept", "accept-language", "user-agent", "origin", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site":
			out = append(out, map[string]string{"name": name, "value": value})
		}
	}
	return out
}
