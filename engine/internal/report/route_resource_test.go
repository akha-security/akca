package report

import (
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/storage"
)

func TestRouteBypassReportShowsReferenceAndHeaderControls(t *testing.T) {
	raw := `{
	  "module":"route_auth_bypass",
	  "request":{"method":"GET","url":"https://example.test/","headers":{"X-Original-URL":"/dashboard/account"}},
	  "response":{"status_code":200,"body":"private account customer-731"},
	  "private_resource_reference":{"status_code":200,"body":"private account customer-731 <script>untrusted()</script>","headers":{"Content-Type":"text/html"}},
	  "replay_plan":[
	    {"role":"negative_control","request":{"method":"GET","url":"https://example.test/","headers":{"X-Original-URL":"/dashboard/account/__akca_nonexistent_route_9f812"}}},
	    {"role":"role_a","request":{"method":"GET","url":"https://example.test/dashboard/account","headers":{"Authorization":"Bearer test-owner"}}}
	  ]
	}`
	ev := httpEvidenceFromRecord(storage.FindingRecord{EvidenceJSON: raw})
	if !strings.Contains(ev.ResourceReference, "customer-731") || len(ev.ControlRequests) != 1 ||
		!strings.Contains(ev.ControlRequests[0], "X-Original-URL: /dashboard/account/__akca_nonexistent_route_") {
		t.Fatalf("resource reference or header control was discarded: %+v", ev)
	}
	html := httpEvidenceHTML(ev)
	for _, want := range []string{"Authenticated private-resource reference", "Negative control requests", "customer-731", "__akca_nonexistent_route_", "&lt;script&gt;untrusted()&lt;/script&gt;"} {
		if !strings.Contains(html, want) {
			t.Errorf("report missing %q", want)
		}
	}
	if strings.Contains(html, "<script>untrusted()") || strings.Contains(html, "Bearer test-owner") {
		t.Fatal("reference HTML was executed or authenticated request was shown as an anonymous control")
	}
}
