package browserpool

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ReadCrossOrigin observes data available to script in an opaque-origin page.
// Authentication headers are never applied to the cross-site request. Only
// browser-managed cookies can accompany the JSONP/WebSocket request.
func (r *HeadlessRenderer) ReadCrossOrigin(ctx context.Context, rawURL, kind, callback string, authenticated bool) (string, error) {
	if !r.Available() {
		return "", fmt.Errorf("browser unavailable")
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("invalid cross-origin target")
	}
	if kind != "jsonp" && kind != "websocket" {
		return "", fmt.Errorf("unsupported cross-origin protocol")
	}
	if r.sem != nil {
		select {
		case r.sem <- struct{}{}:
			defer func() { <-r.sem }()
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	profile, err := os.MkdirTemp("", "akca-cross-origin-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(profile)
	cmd := exec.CommandContext(ctx, r.binary, r.cdpArgs(profile)...)
	if err = cmd.Start(); err != nil {
		return "", err
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	port, err := waitDebugPort(ctx, profile)
	if err != nil {
		return "", err
	}
	debugURL, err := waitPageDebuggerURL(ctx, port)
	if err != nil {
		return "", err
	}
	c, err := dialCDP(debugURL)
	if err != nil {
		return "", err
	}
	defer c.close()
	for _, domain := range []string{"Page.enable", "Network.enable", "Runtime.enable"} {
		if err = c.call(ctx, domain, map[string]interface{}{}, nil); err != nil {
			return "", err
		}
	}
	if err = r.guardBrowserRequests(ctx, c); err != nil {
		return "", err
	}

	if authenticated {
		for name, value := range r.cookies {
			if err = c.call(ctx, "Network.setCookie", map[string]interface{}{"name": name, "value": value, "url": rawURL}, nil); err != nil {
				return "", err
			}
		}
		// Obtain the target's cookie attributes using an ordinary same-origin read.
		// Custom headers are confined to this setup navigation.
		if err = c.call(ctx, "Network.setExtraHTTPHeaders", map[string]interface{}{"headers": cloneStrings(r.headers)}, nil); err != nil {
			return "", err
		}
		if err = navigateAndWait(ctx, c, rawURL); err != nil {
			return "", err
		}
	}
	if err = c.call(ctx, "Network.setExtraHTTPHeaders", map[string]interface{}{"headers": map[string]string{}}, nil); err != nil {
		return "", err
	}
	if err = navigateAndWait(ctx, c, "data:text/html,<html><body>AKCA cross-origin proof</body></html>"); err != nil {
		return "", err
	}
	value := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	var expression string
	if kind == "jsonp" {
		if callback == "" {
			return "", fmt.Errorf("callback required")
		}
		expression = `new Promise((resolve,reject)=>{let done=false;const finish=x=>{if(!done){done=true;resolve(x)}};window[` + value(callback) + `]=x=>finish(JSON.stringify(x));let s=document.createElement('script');s.src=` + value(rawURL) + `;s.onerror=()=>reject(new Error('script load failed'));document.body.appendChild(s);setTimeout(()=>reject(new Error('read timed out')),5000)})`
	} else {
		if r.requestGuard != nil {
			if err = r.requestGuard(ctx, rawURL, "websocket"); err != nil {
				return "", err
			}
		}
		wsURL := "ws" + strings.TrimPrefix(rawURL, "http")
		expression = `new Promise((resolve,reject)=>{let done=false;let ws;const finish=x=>{if(!done){done=true;if(ws)ws.close();resolve(x)}};try{ws=new WebSocket(` + value(wsURL) + `);ws.onmessage=e=>finish(typeof e.data==='string'?e.data:'');ws.onerror=()=>reject(new Error('script load failed'));setTimeout(()=>reject(new Error('read timed out')),5000)}catch(e){reject(e)}})`
	}
	var result struct {
		Result struct {
			Value string `json:"value"`
		} `json:"result"`
		ExceptionDetails json.RawMessage `json:"exceptionDetails"`
	}
	if err = c.call(ctx, "Runtime.evaluate", map[string]interface{}{"expression": expression, "awaitPromise": true, "returnByValue": true}, &result); err != nil {
		return "", err
	}
	if len(result.ExceptionDetails) > 0 {
		return "", fmt.Errorf("cross-origin script could not complete")
	}
	return result.Result.Value, nil
}

func navigateAndWait(ctx context.Context, c *cdpClient, rawURL string) error {
	// Consume previous navigation events before initiating the next navigation.
	for {
		select {
		case _, ok := <-c.events:
			if !ok {
				return fmt.Errorf("browser closed")
			}
		default:
			goto drained
		}
	}
drained:
	var result struct {
		ErrorText string `json:"errorText"`
	}
	if err := c.call(ctx, "Page.navigate", map[string]interface{}{"url": rawURL}, &result); err != nil {
		return err
	}
	if result.ErrorText != "" {
		return fmt.Errorf("navigation: %s", result.ErrorText)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-c.events:
			if !ok {
				return fmt.Errorf("browser closed")
			}
			if e.Method == "Page.loadEventFired" {
				return nil
			}
		}
	}
}
