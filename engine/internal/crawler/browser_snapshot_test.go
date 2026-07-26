package crawler

import "testing"

func TestBuildBrowserSnapshotCapturesStateAndRuntimeSurfaces(t *testing.T) {
	dom := `<form action="/checkout"><button aria-label="Pay">Pay</button></form>
<script>
localStorage.setItem("tenant","acme");
sessionStorage.setItem("step","payment");
document.body.innerHTML = "done";
</script>`
	calls := []DiscoveredEndpoint{
		{URL: "wss://example.com/live", Source: SourceWebSocket},
		{URL: "https://example.com/sw.js", Source: SourceScript, WhyDiscovered: "service worker registration"},
	}
	snapshot := BuildBrowserSnapshot("https://example.com/cart", dom, calls)
	if snapshot.LocalStorage["tenant"] != "acme" || snapshot.SessionStorage["step"] != "payment" {
		t.Fatalf("storage instrumentation missing: %+v", snapshot)
	}
	if len(snapshot.Forms) == 0 || len(snapshot.VisibleActions) == 0 ||
		len(snapshot.WebSockets) != 1 || len(snapshot.ServiceWorkers) != 1 ||
		len(snapshot.DOMSinkEvents) == 0 {
		t.Fatalf("browser instrumentation incomplete: %+v", snapshot)
	}
}
