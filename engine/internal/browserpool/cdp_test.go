package browserpool

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/crawler"
)

func cdpEvent(method, params string) cdpMessage {
	return cdpMessage{Method: method, Params: json.RawMessage(params)}
}

func TestCDPCaptureBuildsTypedNetworkAndRuntimeSurfaces(t *testing.T) {
	capture := newCDPCapture()
	capture.handle(cdpEvent("Network.requestWillBeSent", `{
	  "requestId":"xhr-1","type":"XHR",
	  "request":{"url":"https://app.test/api/orders","method":"POST",
	    "headers":{"Authorization":"Bearer secret","Content-Type":"application/json"},
	    "postData":"{\"password\":\"secret\"}"}
	}`))
	capture.handle(cdpEvent("Network.responseReceived", `{
	  "requestId":"xhr-1","type":"XHR",
	  "response":{"url":"https://app.test/api/orders","status":201,
	    "headers":{"Content-Type":"application/json","Set-Cookie":"session=secret"}}
	}`))
	capture.handle(cdpEvent("Network.webSocketCreated", `{"url":"wss://app.test/live"}`))
	capture.handle(cdpEvent("ServiceWorker.workerVersionUpdated",
		`{"versions":[{"scriptURL":"https://app.test/sw.js"}]}`))
	capture.handle(cdpEvent("Page.loadEventFired", `{}`))

	event := capture.network["xhr-1"]
	if event == nil || event.StatusCode != 201 || event.ResourceType != "XHR" {
		t.Fatalf("typed CDP request/response correlation missing: %+v", event)
	}
	if event.RequestHeaders["Authorization"] != "Bearer secret" ||
		event.ResponseHeaders["Set-Cookie"] != "session=secret" {
		t.Fatalf("CDP network event execution headers mismatch: %+v", event)
	}
	if !capture.loaded || len(capture.websockets) != 1 || len(capture.serviceWorkers) != 1 {
		t.Fatalf("runtime browser surfaces missing: %+v", capture)
	}
	endpoint := endpointFromNetwork(*event)
	if endpoint.Source != crawler.SourceBrowserXHR || endpoint.RequestTemplate == nil ||
		endpoint.RequestTemplate.ResponseStatus != 201 {
		t.Fatalf("CDP event was not converted to a crawler endpoint: %+v", endpoint)
	}
}

func TestBrowserAPICallFilterAvoidsStaticAssetNoise(t *testing.T) {
	if browserAPICall(crawler.BrowserNetworkEvent{
		URL: "https://app.test/static/logo.png", Method: "GET", ResourceType: "Image",
	}) {
		t.Fatal("ordinary static image must not enter the API discovery queue")
	}
	if !browserAPICall(crawler.BrowserNetworkEvent{
		URL: "https://app.test/internal/export", Method: "GET", ResourceType: "Fetch",
	}) {
		t.Fatal("actual fetch call must enter the runtime API inventory")
	}
}

func TestCDPArgsUseIsolatedProfileAndDebugging(t *testing.T) {
	t.Setenv("AKCA_BROWSER_DISABLE_SANDBOX", "")
	renderer := &HeadlessRenderer{proxyURL: "http://127.0.0.1:8080", insecureTLS: true}
	args := strings.Join(renderer.cdpArgs(`C:\temp\akca-profile`), " ")
	for _, expected := range []string{
		"--remote-debugging-port=0", "--user-data-dir=C:\\temp\\akca-profile",
		"--proxy-server=http://127.0.0.1:8080", "--ignore-certificate-errors",
	} {
		if !strings.Contains(args, expected) {
			t.Fatalf("missing CDP argument %q in %s", expected, args)
		}
	}
	if strings.Contains(args, "--no-sandbox") {
		t.Fatal("browser sandbox must remain enabled by default")
	}
}
