package browserpool

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCDPRealBrowserCapturesSPAState(t *testing.T) {
	if testing.Short() {
		t.Skip("real Chromium integration test")
	}
	renderer := NewHeadlessRenderer()
	if !renderer.Available() {
		t.Skip("Chromium/Chrome/Edge is unavailable")
	}
	renderer.SetSession(
		map[string]string{"Authorization": "Bearer browser-session-token"},
		map[string]string{"preset_session": "authenticated"},
	)
	// Local/CI environments can run inside a restricted Windows job that prevents the
	// nested Chromium renderer sandbox from starting. This opt-in is test-only;
	// production scans retain Chromium's sandbox by default.
	t.Setenv("AKCA_BROWSER_DISABLE_SANDBOX", "1")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		preset, _ := r.Cookie("preset_session")
		if r.Header.Get("Authorization") != "Bearer browser-session-token" ||
			preset == nil || preset.Value != "authenticated" {
			http.Error(w, "missing preloaded browser session", http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "akca_session", Value: "cookie-value", Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><body><main id="result">loading</main>
<script>
localStorage.setItem("tenant", "acme");
sessionStorage.setItem("step", "checkout");
fetch("/api/state", {headers: {"X-Test": "cdp"}})
  .then(r => r.json()).then(v => document.querySelector("#result").textContent = v.state);
if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js");
</script></body></html>`))
	})
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"state":"rendered-by-fetch"}`))
	})
	mux.HandleFunc("/sw.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`self.addEventListener("fetch", () => {});`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	snapshot, err := renderer.Capture(ctx, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(snapshot.DOM, "rendered-by-fetch") {
		t.Fatalf("post-JavaScript DOM was not captured: %s", snapshot.DOM)
	}
	rootAuthorized := false
	for _, event := range snapshot.NetworkEvents {
		if strings.TrimRight(event.URL, "/") == strings.TrimRight(server.URL, "/") &&
			event.StatusCode == http.StatusOK {
			rootAuthorized = true
		}
	}
	if !rootAuthorized {
		t.Fatal("preloaded browser authorization header/cookie were not applied")
	}
	if snapshot.LocalStorage["tenant"] != "acme" || snapshot.SessionStorage["step"] != "checkout" {
		t.Fatalf("browser storage was not captured: local=%v session=%v", snapshot.LocalStorage, snapshot.SessionStorage)
	}
	if snapshot.Cookies["akca_session"] != "cookie-value" {
		t.Fatalf("browser cookie was not captured: %v", snapshot.Cookies)
	}
	foundAPI := false
	for _, call := range snapshot.NetworkCalls {
		if strings.Contains(call.URL, "/api/state") && call.RequestTemplate != nil &&
			call.RequestTemplate.ResponseStatus == http.StatusOK {
			foundAPI = true
		}
	}
	if !foundAPI {
		t.Fatalf("real fetch request/response was not captured: %+v", snapshot.NetworkCalls)
	}
	if len(snapshot.DOMSinkEvents) == 0 {
		t.Fatal("runtime DOM mutation instrumentation produced no events")
	}
}
