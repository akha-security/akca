package browserpool

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akha-security/akca/engine/internal/crawler"
	"github.com/gorilla/websocket"
)

type cdpMessage struct {
	ID     int             `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type synchronizedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *synchronizedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(value)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

type cdpClient struct {
	conn           *websocket.Conn
	sendMu         sync.Mutex
	mu             sync.Mutex
	nextID         int
	pending        map[int]chan cdpMessage
	events         chan cdpMessage
	done           chan struct{}
	readErr        error
	requestHandler func(cdpMessage)
}

func dialCDP(rawURL string) (*cdpClient, error) {
	conn, _, err := websocket.DefaultDialer.Dial(rawURL, nil)
	if err != nil {
		return nil, err
	}
	client := &cdpClient{
		conn: conn, pending: make(map[int]chan cdpMessage), events: make(chan cdpMessage, 2048),
		done: make(chan struct{}),
	}
	go client.readLoop()
	return client, nil
}

func (c *cdpClient) readLoop() {
	defer close(c.events)
	defer close(c.done)
	for {
		var message cdpMessage
		if err := c.conn.ReadJSON(&message); err != nil {
			c.mu.Lock()
			c.readErr = err
			c.mu.Unlock()
			return
		}
		if message.ID != 0 {
			c.mu.Lock()
			waiter := c.pending[message.ID]
			delete(c.pending, message.ID)
			c.mu.Unlock()
			if waiter != nil {
				waiter <- message
			}
			continue
		}
		c.mu.Lock()
		handler := c.requestHandler
		c.mu.Unlock()
		if message.Method == "Fetch.requestPaused" && handler != nil {
			go handler(message)
			continue
		}
		select {
		case c.events <- message:
		default:
			// Command responses are dispatched independently; dropping a noisy
			// nonessential event is safer than deadlocking the CDP socket.
		}
	}
}

func (c *cdpClient) call(ctx context.Context, method string, params interface{}, out interface{}) error {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	waiter := make(chan cdpMessage, 1)
	c.pending[id] = waiter
	c.mu.Unlock()
	message := map[string]interface{}{"id": id, "method": method}
	if params != nil {
		message["params"] = params
	}
	c.sendMu.Lock()
	err := c.conn.WriteJSON(message)
	c.sendMu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return fmt.Errorf("CDP %s send: %w", method, err)
	}
	select {
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return fmt.Errorf("CDP %s wait: %w", method, ctx.Err())
	case <-c.done:
		c.mu.Lock()
		readErr := c.readErr
		delete(c.pending, id)
		c.mu.Unlock()
		if readErr == nil {
			return fmt.Errorf("CDP %s connection closed", method)
		}
		return fmt.Errorf("CDP %s connection closed: %w", method, readErr)
	case response := <-waiter:
		if response.Error != nil {
			return fmt.Errorf("CDP %s: %s", method, response.Error.Message)
		}
		if out != nil && len(response.Result) > 0 {
			return json.Unmarshal(response.Result, out)
		}
		return nil
	}
}

func (c *cdpClient) close() {
	if c != nil && c.conn != nil {
		_ = c.conn.Close()
	}
}

type cdpCapture struct {
	network        map[string]*crawler.BrowserNetworkEvent
	websockets     map[string]struct{}
	serviceWorkers map[string]struct{}
	console        []crawler.BrowserConsoleEntry
	loaded         bool
}

func newCDPCapture() *cdpCapture {
	return &cdpCapture{
		network:    make(map[string]*crawler.BrowserNetworkEvent),
		websockets: make(map[string]struct{}), serviceWorkers: make(map[string]struct{}),
	}
}

func (c *cdpCapture) handle(message cdpMessage) {
	switch message.Method {
	case "Page.loadEventFired":
		c.loaded = true
	case "Network.requestWillBeSent":
		var event struct {
			RequestID string `json:"requestId"`
			Type      string `json:"type"`
			Request   struct {
				URL      string                 `json:"url"`
				Method   string                 `json:"method"`
				Headers  map[string]interface{} `json:"headers"`
				PostData string                 `json:"postData"`
			} `json:"request"`
		}
		if json.Unmarshal(message.Params, &event) == nil && event.RequestID != "" {
			c.network[event.RequestID] = &crawler.BrowserNetworkEvent{
				RequestID: event.RequestID, URL: event.Request.URL, Method: event.Request.Method,
				ResourceType: event.Type, RequestHeaders: stringMap(event.Request.Headers),
				RequestBody: event.Request.PostData,
			}
		}
	case "Network.responseReceived":
		var event struct {
			RequestID string `json:"requestId"`
			Type      string `json:"type"`
			Response  struct {
				URL     string                 `json:"url"`
				Status  float64                `json:"status"`
				Headers map[string]interface{} `json:"headers"`
			} `json:"response"`
		}
		if json.Unmarshal(message.Params, &event) == nil {
			record := c.network[event.RequestID]
			if record == nil {
				record = &crawler.BrowserNetworkEvent{RequestID: event.RequestID, URL: event.Response.URL}
				c.network[event.RequestID] = record
			}
			record.StatusCode = int(event.Response.Status)
			record.ResourceType = event.Type
			record.ResponseHeaders = stringMap(event.Response.Headers)
		}
	case "Network.webSocketCreated":
		var event struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(message.Params, &event) == nil && event.URL != "" {
			c.websockets[event.URL] = struct{}{}
		}
	case "ServiceWorker.workerRegistrationUpdated":
		var event struct {
			Registrations []struct {
				ScopeURL string `json:"scopeURL"`
			} `json:"registrations"`
		}
		if json.Unmarshal(message.Params, &event) == nil {
			for _, registration := range event.Registrations {
				if registration.ScopeURL != "" {
					c.serviceWorkers[registration.ScopeURL] = struct{}{}
				}
			}
		}
	case "ServiceWorker.workerVersionUpdated":
		var event struct {
			Versions []struct {
				ScriptURL string `json:"scriptURL"`
			} `json:"versions"`
		}
		if json.Unmarshal(message.Params, &event) == nil {
			for _, version := range event.Versions {
				if version.ScriptURL != "" {
					c.serviceWorkers[version.ScriptURL] = struct{}{}
				}
			}
		}
	case "Runtime.consoleAPICalled":
		var event struct {
			Type string `json:"type"`
			Args []struct {
				Type        string      `json:"type"`
				Value       interface{} `json:"value"`
				Description string      `json:"description"`
			} `json:"args"`
			StackTrace struct {
				CallFrames []struct {
					URL        string `json:"url"`
					LineNumber int    `json:"lineNumber"`
				} `json:"callFrames"`
			} `json:"stackTrace"`
		}
		if json.Unmarshal(message.Params, &event) == nil {
			parts := make([]string, 0, len(event.Args))
			for _, arg := range event.Args {
				value := fmt.Sprint(arg.Value)
				if value == "<nil>" || value == "" {
					value = arg.Description
				}
				if value != "" {
					parts = append(parts, value)
				}
			}
			entry := crawler.BrowserConsoleEntry{Level: event.Type, Text: truncateString(strings.Join(parts, " "), 2048), Source: "console"}
			if len(event.StackTrace.CallFrames) > 0 {
				entry.URL = event.StackTrace.CallFrames[0].URL
				entry.Line = event.StackTrace.CallFrames[0].LineNumber + 1
			}
			c.addConsole(entry)
		}
	case "Runtime.exceptionThrown":
		var event struct {
			ExceptionDetails struct {
				Text       string `json:"text"`
				URL        string `json:"url"`
				LineNumber int    `json:"lineNumber"`
				Exception  struct {
					Description string `json:"description"`
				} `json:"exception"`
			} `json:"exceptionDetails"`
		}
		if json.Unmarshal(message.Params, &event) == nil {
			text := event.ExceptionDetails.Exception.Description
			if text == "" {
				text = event.ExceptionDetails.Text
			}
			c.addConsole(crawler.BrowserConsoleEntry{Level: "error", Text: truncateString(text, 2048), Source: "exception", URL: event.ExceptionDetails.URL, Line: event.ExceptionDetails.LineNumber + 1})
		}
	case "Log.entryAdded":
		var event struct {
			Entry struct {
				Source     string `json:"source"`
				Level      string `json:"level"`
				Text       string `json:"text"`
				URL        string `json:"url"`
				LineNumber int    `json:"lineNumber"`
			} `json:"entry"`
		}
		if json.Unmarshal(message.Params, &event) == nil {
			c.addConsole(crawler.BrowserConsoleEntry{Level: event.Entry.Level, Text: truncateString(event.Entry.Text, 2048), Source: event.Entry.Source, URL: event.Entry.URL, Line: event.Entry.LineNumber})
		}
	}
}

func (c *cdpCapture) addConsole(entry crawler.BrowserConsoleEntry) {
	if strings.TrimSpace(entry.Text) == "" || len(c.console) >= 200 {
		return
	}
	entry.Text = redactCDPBody(entry.Text)
	c.console = append(c.console, entry)
}

type browserSession struct {
	client      *cdpClient
	cmd         *exec.Cmd
	profile     string
	initialized bool
}

func (s *browserSession) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = s.client.call(ctx, "Browser.close", map[string]interface{}{}, nil)
	cancel()
	s.client.close()
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	_ = s.cmd.Wait()
	_ = os.RemoveAll(s.profile)
}

func (r *HeadlessRenderer) Close() {
	r.crawlMu.Lock()
	defer r.crawlMu.Unlock()
	if r.session != nil {
		r.session.close()
		r.session = nil
	}
}

func (r *HeadlessRenderer) startBrowser(ctx context.Context) (*browserSession, error) {
	profile, err := os.MkdirTemp("", "akca-cdp-")
	if err != nil {
		return nil, err
	}
	// Lifetime belongs to Close, not the per-navigation timeout.
	cmd := exec.Command(r.binary, r.cdpArgs(profile)...)
	// Chromium children can inherit stderr. Bound pipe cleanup even if the
	// browser exits before its descendants close those handles on Windows.
	cmd.WaitDelay = 2 * time.Second
	var stderr synchronizedBuffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		_ = os.RemoveAll(profile)
		return nil, err
	}
	cleanup := func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = os.RemoveAll(profile) }
	port, err := waitDebugPort(ctx, profile)
	if err != nil {
		cleanup()
		return nil, err
	}
	debugURL, err := waitPageDebuggerURL(ctx, port)
	if err != nil {
		cleanup()
		return nil, err
	}
	client, err := dialCDP(debugURL)
	if err != nil {
		cleanup()
		return nil, err
	}
	return &browserSession{client: client, cmd: cmd, profile: profile}, nil
}

func (r *HeadlessRenderer) Capture(ctx context.Context, rawURL string) (crawler.BrowserSnapshot, error) {
	if !r.Available() {
		return crawler.BrowserSnapshot{}, fmt.Errorf("no Chromium-compatible browser found")
	}
	if r.persistent {
		r.crawlMu.Lock()
		defer r.crawlMu.Unlock()
	}
	if r.sem != nil {
		select {
		case r.sem <- struct{}{}:
			defer func() { <-r.sem }()
		case <-ctx.Done():
			return crawler.BrowserSnapshot{}, ctx.Err()
		}
	}
	captureCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	session := r.session
	if session == nil {
		var err error
		session, err = r.startBrowser(captureCtx)
		if err != nil {
			return crawler.BrowserSnapshot{}, err
		}
		if r.persistent {
			r.session = session
		} else {
			defer session.close()
		}
	}
	client := session.client

	for _, domain := range []string{"Page.enable", "Network.enable", "Runtime.enable"} {
		if err := client.call(captureCtx, domain, map[string]interface{}{}, nil); err != nil {
			return crawler.BrowserSnapshot{}, err
		}
	}
	for _, optionalDomain := range []string{"DOMStorage.enable", "ServiceWorker.enable", "Log.enable"} {
		_ = client.call(captureCtx, optionalDomain, map[string]interface{}{}, nil)
	}
	if len(r.headers) > 0 {
		_ = client.call(captureCtx, "Network.setExtraHTTPHeaders",
			map[string]interface{}{"headers": redactOutboundHeaders(r.headers)}, nil)
	}
	if !session.initialized {
		for name, value := range r.cookies {
			_ = client.call(captureCtx, "Network.setCookie",
				map[string]interface{}{"name": name, "value": value, "url": rawURL}, nil)
		}
		_ = client.call(captureCtx, "Page.addScriptToEvaluateOnNewDocument",
			map[string]interface{}{"source": domInstrumentationScript}, nil)
	}
	session.initialized = true

	state := newCDPCapture()
	r.blockedMu.Lock()
	r.blockedResources = nil
	r.blockedMu.Unlock()
	if err := r.guardBrowserRequests(captureCtx, client); err != nil {
		return crawler.BrowserSnapshot{}, err
	}
	if err := client.call(captureCtx, "Page.navigate", map[string]interface{}{"url": rawURL}, nil); err != nil {
		return crawler.BrowserSnapshot{}, err
	}
	idle := time.NewTimer(1500 * time.Millisecond)
	defer idle.Stop()
	settle := idle.C
	actionsRun := !r.interactive
	maxWait := time.NewTimer(12 * time.Second)
	defer maxWait.Stop()
collect:
	for {
		select {
		case <-captureCtx.Done():
			return crawler.BrowserSnapshot{}, captureCtx.Err()
		case <-maxWait.C:
			break collect
		case <-settle:
			if !state.loaded {
				idle.Reset(1500 * time.Millisecond)
				continue
			}
			if !actionsRun {
				actionsRun = true
				_ = client.call(captureCtx, "Runtime.evaluate", map[string]interface{}{"expression": crawler.GenerateSmartActionScript(crawler.DefaultSmartActionConfig()), "returnByValue": true, "awaitPromise": true}, nil)
				idle.Reset(1500 * time.Millisecond)
				continue
			}
			break collect
		case event, ok := <-client.events:
			if !ok {
				break collect
			}
			state.handle(event)
			if event.Method == "Network.requestWillBeSent" || event.Method == "Network.loadingFinished" || event.Method == "Network.loadingFailed" || event.Method == "Page.loadEventFired" {
				if !idle.Stop() {
					select {
					case <-idle.C:
					default:
					}
				}
				idle.Reset(1500 * time.Millisecond)
			}
		}
	}
	snapshot, err := r.buildCDPSnapshot(captureCtx, client, rawURL, state)
	r.blockedMu.Lock()
	snapshot.BlockedResources = append([]string(nil), r.blockedResources...)
	r.blockedMu.Unlock()
	return snapshot, err
}

func (r *HeadlessRenderer) cdpArgs(profile string) []string {
	args := []string{
		"--headless=new", "--disable-gpu", "--disable-gpu-sandbox", "--disable-gpu-compositing",
		"--use-angle=swiftshader-webgl", "--use-gl=angle", "--disable-extensions", "--disable-dev-shm-usage",
		"--no-first-run", "--no-default-browser-check", "--remote-debugging-port=0",
		"--disable-background-networking", "--disable-sync", "--disable-component-update", "--disable-default-apps",
		"--disable-features=Translate,BackForwardCache,AcceptCHFrame,MediaRouter,OptimizationHints,WebOTP,MicrosoftAccount,EdgeSignin,Sync",
		"--identity-provider-disabled", "--disable-single-click-autofill", "--disable-autofill", "--guest",
		"--remote-allow-origins=*", "--user-data-dir=" + profile, "about:blank",
	}
	if r.proxyURL != "" {
		args = append(args, "--proxy-server="+r.proxyURL)
	}
	if r.insecureTLS {
		args = append(args, "--ignore-certificate-errors")
	}
	if os.Getenv("AKCA_BROWSER_DISABLE_SANDBOX") == "1" {
		args = append(args, "--no-sandbox")
	}
	return args
}

func waitDebugPort(ctx context.Context, profile string) (int, error) {
	path := filepath.Join(profile, "DevToolsActivePort")
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		raw, err := os.ReadFile(path)
		if err == nil {
			lines := strings.Fields(string(raw))
			if len(lines) > 0 {
				port, parseErr := strconv.Atoi(lines[0])
				if parseErr == nil && port > 0 {
					return port, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}
	}
}

func waitPageDebuggerURL(ctx context.Context, port int) (string, error) {
	endpoint := fmt.Sprintf("http://127.0.0.1:%d/json/list", port)
	client := &http.Client{Timeout: time.Second}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if response, err := client.Do(request); err == nil {
			var targets []struct {
				Type                 string `json:"type"`
				WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
			}
			decodeErr := json.NewDecoder(response.Body).Decode(&targets)
			response.Body.Close()
			if decodeErr == nil {
				for _, target := range targets {
					if target.Type == "page" && target.WebSocketDebuggerURL != "" {
						return target.WebSocketDebuggerURL, nil
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}

type cdpPageState struct {
	URL            string            `json:"url"`
	DOM            string            `json:"dom"`
	LocalStorage   map[string]string `json:"localStorage"`
	SessionStorage map[string]string `json:"sessionStorage"`
	DOMSinkEvents  []string          `json:"domSinkEvents"`
}

func (r *HeadlessRenderer) buildCDPSnapshot(ctx context.Context, client *cdpClient, rawURL string,
	capture *cdpCapture) (crawler.BrowserSnapshot, error) {
	var evaluated struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
	}
	err := client.call(ctx, "Runtime.evaluate", map[string]interface{}{
		"expression": pageStateExpression, "returnByValue": true, "awaitPromise": true,
	}, &evaluated)
	if err != nil {
		return crawler.BrowserSnapshot{}, err
	}
	var page cdpPageState
	if err := json.Unmarshal(evaluated.Result.Value, &page); err != nil {
		return crawler.BrowserSnapshot{}, err
	}

	var cookieResult struct {
		Cookies []struct {
			Name   string `json:"name"`
			Value  string `json:"value"`
			Domain string `json:"domain"`
		} `json:"cookies"`
	}
	_ = client.call(ctx, "Network.getCookies", map[string]interface{}{"urls": []string{rawURL}}, &cookieResult)
	cookies := make(map[string]string)
	for _, cookie := range cookieResult.Cookies {
		key := cookie.Name
		if _, duplicate := cookies[key]; duplicate {
			key = cookie.Domain + "|" + cookie.Name
		}
		cookies[key] = cookie.Value
	}

	ids := make([]string, 0, len(capture.network))
	for id := range capture.network {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	networkEvents := make([]crawler.BrowserNetworkEvent, 0, len(ids))
	var calls []crawler.DiscoveredEndpoint
	for _, id := range ids {
		event := capture.network[id]
		if event == nil || event.URL == "" {
			continue
		}
		if browserAPICall(*event) {
			var body struct {
				Body          string `json:"body"`
				Base64Encoded bool   `json:"base64Encoded"`
			}
			if client.call(ctx, "Network.getResponseBody", map[string]interface{}{"requestId": id}, &body) == nil &&
				!body.Base64Encoded {
				event.ResponseBody = truncateString(redactCDPBody(body.Body), 4096)
			}
			if event.RequestBody == "" && (event.Method == "POST" || event.Method == "PUT" || event.Method == "PATCH") {
				var postData struct {
					PostData string `json:"postData"`
				}
				if client.call(ctx, "Network.getRequestPostData", map[string]interface{}{"requestId": id}, &postData) == nil && postData.PostData != "" {
					event.RequestBody = postData.PostData
				}
			}
			calls = append(calls, endpointFromNetwork(*event))
		}
		redactedEvent := *event
		redactedEvent.RequestHeaders = event.RequestHeaders
		redactedEvent.RequestBody = truncateString(event.RequestBody, 16<<10)
		networkEvents = append(networkEvents, redactedEvent)
		if len(networkEvents) >= 500 {
			break
		}
	}
	for _, websocketURL := range mapKeys(capture.websockets) {
		calls = append(calls, crawler.DiscoveredEndpoint{
			URL: websocketURL, Method: http.MethodGet, NormalizedURL: websocketURL,
			Source: crawler.SourceWebSocket, Confidence: 1,
			WhyDiscovered: "observed through Chromium CDP WebSocket",
		})
	}
	for _, workerURL := range mapKeys(capture.serviceWorkers) {
		calls = append(calls, crawler.DiscoveredEndpoint{
			URL: workerURL, Method: http.MethodGet, NormalizedURL: workerURL,
			Source: crawler.SourceScript, Confidence: 1,
			WhyDiscovered: "observed through Chromium CDP service worker",
		})
	}
	pageURL := page.URL
	if pageURL == "" {
		pageURL = rawURL
	}
	snapshot := crawler.BuildBrowserSnapshot(pageURL, page.DOM, calls)
	for _, event := range networkEvents {
		if event.ResourceType == "Document" && event.URL == pageURL {
			snapshot.DocumentStatus = event.StatusCode
		}
	}
	snapshot.NetworkEvents = networkEvents
	snapshot.ConsoleEntries = append([]crawler.BrowserConsoleEntry(nil), capture.console...)
	snapshot.Cookies = cookies
	snapshot.LocalStorage = page.LocalStorage
	snapshot.SessionStorage = page.SessionStorage
	snapshot.DOMSinkEvents = uniqueSorted(append(snapshot.DOMSinkEvents, page.DOMSinkEvents...))
	snapshot.WebSockets = uniqueSorted(mapKeys(capture.websockets))
	snapshot.ServiceWorkers = uniqueSorted(mapKeys(capture.serviceWorkers))
	return snapshot, nil
}

func endpointFromNetwork(event crawler.BrowserNetworkEvent) crawler.DiscoveredEndpoint {
	source := crawler.SourceBrowserXHR
	switch strings.ToLower(event.ResourceType) {
	case "websocket":
		source = crawler.SourceWebSocket
	case "eventsource":
		source = crawler.SourceEventSource
	}
	contentType := headerLookup(event.RequestHeaders, "Content-Type")
	return crawler.DiscoveredEndpoint{
		URL: event.URL, Method: event.Method, NormalizedURL: event.URL, Source: source,
		Confidence: 1, WhyDiscovered: "observed through Chromium CDP " + event.ResourceType,
		RequestTemplate: &crawler.RequestTemplate{
			Method: event.Method, URL: event.URL, Headers: event.RequestHeaders,
			Body: event.RequestBody, ContentType: contentType, ResponseStatus: event.StatusCode,
			ResponseHeaders: event.ResponseHeaders, ResponseBody: event.ResponseBody,
		},
	}
}

func browserAPICall(event crawler.BrowserNetworkEvent) bool {
	switch strings.ToLower(event.ResourceType) {
	case "xhr", "fetch", "websocket", "eventsource":
		return true
	}
	if method := strings.ToUpper(event.Method); method != "" && method != http.MethodGet &&
		method != http.MethodHead && method != http.MethodOptions {
		return true
	}
	parsed, err := url.Parse(event.URL)
	if err != nil {
		return false
	}
	lower := strings.ToLower(parsed.Path)
	return strings.Contains(lower, "/api/") || strings.Contains(lower, "/graphql") ||
		strings.Contains(lower, "/v1/") || strings.Contains(lower, "/v2/")
}

func stringMap(values map[string]interface{}) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = fmt.Sprint(value)
	}
	return out
}

func redactCDPHeaders(headers map[string]string) map[string]string {
	return headers
}

func redactOutboundHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		if strings.EqualFold(key, "Cookie") || strings.EqualFold(key, "Host") ||
			strings.EqualFold(key, "Content-Length") {
			continue
		}
		out[key] = value
	}
	return out
}

func redactCDPBody(body string) string {
	return truncateString(body, 16<<10)
}

func headerLookup(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func truncateString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "...[truncated]"
}

func mapKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	return out
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

const domInstrumentationScript = `(() => {
  const install = () => {
    if (window.__akcaDOMSinkEvents) return;
    Object.defineProperty(window, "__akcaDOMSinkEvents", {value: [], configurable: false});
    const push = value => {
      if (window.__akcaDOMSinkEvents.length < 200) window.__akcaDOMSinkEvents.push(value);
    };
    new MutationObserver(records => {
      for (const record of records) push("dom_mutation:" + record.type);
    }).observe(document.documentElement, {subtree: true, childList: true, attributes: true, characterData: true});
  };
  if (document.documentElement) install();
  else document.addEventListener("DOMContentLoaded", install, {once: true});
})();`

const pageStateExpression = `(() => ({
	url: location.href,
  dom: document.documentElement ? document.documentElement.outerHTML : "",
  localStorage: Object.fromEntries(Object.keys(localStorage).map(k => [k, localStorage.getItem(k)])),
  sessionStorage: Object.fromEntries(Object.keys(sessionStorage).map(k => [k, sessionStorage.getItem(k)])),
  domSinkEvents: Array.isArray(window.__akcaDOMSinkEvents) ? window.__akcaDOMSinkEvents : []
}))()`
