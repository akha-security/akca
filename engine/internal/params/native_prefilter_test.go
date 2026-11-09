package params

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestNativePrefilterReducesIgnoredNamesAndKeepsRealSignals(t *testing.T) {
	for _, location := range []Location{LocationJSON, LocationForm} {
		for _, hidden := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/hidden=%t", location, hidden), func(t *testing.T) {
				method, ct, body := http.MethodPut, "application/json", `{"required":"keep"}`
				if location == LocationForm {
					method, ct, body = http.MethodPost, "application/x-www-form-urlencoded", "required=keep"
				}
				requests := 0
				client := performanceDoer(func(_ context.Context, m, u string, b []byte, h map[string]string) (httpclient.RequestResponse, error) {
					requests++
					if m != method || u != "https://example.test/api/save" || headerValue(h, "Authorization") != "Bearer keep" {
						t.Fatal("native method or authentication changed")
					}
					fields := map[string]string{}
					if location == LocationJSON {
						if err := json.Unmarshal(b, &fields); err != nil {
							t.Fatal(err)
						}
					} else {
						v, err := url.ParseQuery(string(b))
						if err != nil {
							t.Fatal(err)
						}
						for k := range v {
							fields[k] = v.Get(k)
						}
					}
					if fields["required"] != "keep" || len(fields) != 13 {
						t.Fatalf("native siblings/group lost: %s", b)
					}
					status, response := 200, "baseline"
					if hidden && fields["candidate_5"] != "" {
						status, response = 202, "accepted"
					}
					return httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: status, Body: response}}, nil
				})
				cfg := config.DefaultScanConfig()
				cfg.IncludeDomains = []string{"example.test"}
				d := NewDiscoverer("prefilter", client, scope.NewEngine(cfg), nil, nil)
				var candidates []string
				for i := 0; i < 48; i++ {
					candidates = append(candidates, fmt.Sprintf("candidate_%d", i))
				}
				base := Fingerprint(200, "baseline", 0, nil)
				kept, used := d.prefilterNativeCandidates(context.Background(), method, "https://example.test/api/save", map[string]string{"Authorization": "Bearer keep"}, storage.DiscoveryRequestTemplate{Body: body, ContentType: ct}, candidates, base, base, false, 20)
				want := 0
				if hidden {
					want = 12
				}
				if used != 4 || requests != 4 || len(kept) != want {
					t.Fatalf("requests=%d used=%d kept=%v", requests, used, kept)
				}
			})
		}
	}
}

func TestPrefilterKeepsRejectedGroupsAndSkipsUnstableControls(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.IncludeDomains = []string{"example.test"}
	requests := 0
	d := NewDiscoverer("rejected", performanceDoer(func(context.Context, string, string, []byte, map[string]string) (httpclient.RequestResponse, error) {
		requests++
		return httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 403, Body: "blocked"}}, nil
	}), scope.NewEngine(cfg), nil, nil)
	var names []string
	for i := 0; i < 24; i++ {
		names = append(names, fmt.Sprintf("name_%d", i))
	}
	base := Fingerprint(200, "baseline", 0, nil)
	kept, _ := d.prefilterQueryCandidates(context.Background(), "https://example.test/search", nil, names, base, "baseline", base, "baseline", "control", false, 10)
	if len(kept) != 24 {
		t.Fatal("WAF rejection discarded untested candidates")
	}
	requests = 0
	control := Fingerprint(400, "unknown field", 0, nil)
	kept, _ = d.prefilterNativeCandidates(context.Background(), "POST", "https://example.test/api", nil, storage.DiscoveryRequestTemplate{Body: "{}", ContentType: "application/json"}, names, base, control, false, 10)
	if len(kept) != 24 || requests != 0 {
		t.Fatal("strict-schema control enabled unsafe batch elimination")
	}
}
