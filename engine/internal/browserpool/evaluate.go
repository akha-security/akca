package browserpool

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// EvaluatePage opens a fresh isolated browser context, navigates to rawURL and
// returns a by-value JavaScript expression result. A fresh context is important
// for prototype-pollution proof so state from one probe cannot contaminate the
// next independent run.
func (r *HeadlessRenderer) EvaluatePage(ctx context.Context, rawURL, expression string) (string, error) {
	if !r.Available() {
		return "", fmt.Errorf("browser unavailable")
	}
	if r.sem != nil {
		select {
		case r.sem <- struct{}{}:
			defer func() { <-r.sem }()
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if r.persistent {
		r.crawlMu.Lock()
		defer r.crawlMu.Unlock()
	}
	evalCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	session := r.session
	var err error
	if session == nil {
		session, err = r.startBrowser(evalCtx)
		if err != nil {
			return "", err
		}
		if r.persistent {
			r.session = session
		} else {
			defer session.close()
		}
	}
	healthy := false
	if r.persistent {
		defer func() {
			if !healthy && r.session == session {
				session.close()
				r.session = nil
			}
		}()
	}
	client := session.client
	for _, domain := range []string{"Page.enable", "Network.enable", "Runtime.enable"} {
		if err = client.call(evalCtx, domain, map[string]interface{}{}, nil); err != nil {
			return "", err
		}
	}
	if len(r.headers) > 0 {
		if err = client.call(evalCtx, "Network.setExtraHTTPHeaders",
			map[string]interface{}{"headers": redactOutboundHeaders(r.headers)}, nil); err != nil {
			return "", err
		}
	}
	for name, value := range r.cookies {
		if err = client.call(evalCtx, "Network.setCookie",
			map[string]interface{}{"name": name, "value": value, "url": rawURL}, nil); err != nil {
			return "", err
		}
	}
	if err = r.guardBrowserRequests(evalCtx, client); err != nil {
		return "", err
	}
	if err = navigateAndWait(evalCtx, client, rawURL); err != nil {
		return "", err
	}
	settle := time.NewTimer(500 * time.Millisecond)
	defer settle.Stop()
	select {
	case <-evalCtx.Done():
		return "", evalCtx.Err()
	case <-settle.C:
	}
	var result struct {
		Result struct {
			Value interface{} `json:"value"`
		} `json:"result"`
		ExceptionDetails json.RawMessage `json:"exceptionDetails"`
	}
	if err = client.call(evalCtx, "Runtime.evaluate", map[string]interface{}{
		"expression": expression, "awaitPromise": true, "returnByValue": true,
	}, &result); err != nil {
		return "", err
	}
	if len(result.ExceptionDetails) > 0 {
		return "", fmt.Errorf("browser expression raised an exception")
	}
	if value, ok := result.Result.Value.(string); ok {
		healthy = true
		return value, nil
	}
	raw, err := json.Marshal(result.Result.Value)
	if err != nil {
		return "", err
	}
	healthy = true
	return string(raw), nil
}
