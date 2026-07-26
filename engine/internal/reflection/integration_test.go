package reflection

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

type reflectDoer struct{}

func (r *reflectDoer) Do(_ context.Context, _, rawURL string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
	u, _ := url.Parse(rawURL)
	canary := u.Query().Get("q")
	body := `<html><body>search: ` + canary + `</body></html>`
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{URL: rawURL},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: body, Headers: map[string]string{"Content-Type": "text/html"}},
	}, nil
}

type formReflectionDoer struct {
	methods []string
}

func (r *formReflectionDoer) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	r.methods = append(r.methods, method)
	values, _ := url.ParseQuery(string(body))
	canary := values.Get("q")
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{
			Method: method, URL: rawURL, Body: string(body), Headers: headers,
		},
		Response: httpclient.ResponseRecord{
			StatusCode: http.StatusOK,
			Body:       `<html><body>` + canary + `</body></html>`,
			Headers:    map[string]string{"Content-Type": "text/html"},
		},
	}, nil
}

func TestAnalyzerStabilityReprobe(t *testing.T) {
	cfg := config.DefaultScanConfig()
	scopeEngine := scope.NewEngine(cfg)
	client := &reflectDoer{}

	db, err := storage.Open(t.TempDir() + "/refl.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = db.Migrate()
	_ = db.EnsureScan("scan-r")
	_ = db.SaveDiscoveredEndpoint("scan-r", map[string]interface{}{
		"url": "http://example.com/search", "method": "GET", "normalized_url": "http://example.com/search", "source": "seed",
	})
	epID, _ := db.GetEndpointID("scan-r", "http://example.com/search", "GET")
	_ = db.SaveParameter(epID, "q", "query", 10)

	ra := NewAnalyzer("scan-r", client, scopeEngine, db, func(string, string, map[string]interface{}) error { return nil })
	profiles, err := ra.Run(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) == 0 {
		t.Fatal("expected reflection profiles")
	}
	if !profiles[0].Stable {
		t.Fatal("expected stable reflection after reprobe")
	}
}

func TestAnalyzerUsesPOSTForFormReflection(t *testing.T) {
	cfg := config.DefaultScanConfig()
	client := &formReflectionDoer{}
	analyzer := NewAnalyzer(
		"scan-form", client, scope.NewEngine(cfg), nil,
		func(string, string, map[string]interface{}) error { return nil },
	)

	profile, err := analyzer.AnalyzeParameter(
		context.Background(), "http://example.com/search", http.MethodGet, "q", "form",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(client.methods) != 2 {
		t.Fatalf("reflection requests = %d, want 2", len(client.methods))
	}
	for _, method := range client.methods {
		if method != http.MethodPost {
			t.Fatalf("form reflection used %s, want POST", method)
		}
	}
	if profile.Method != http.MethodPost || profile.ReflectionKind != ReflectionRaw || !profile.Stable {
		t.Fatalf("unexpected form reflection profile: %+v", profile)
	}
	if !strings.EqualFold(profile.ParameterLocation, "form") {
		t.Fatalf("profile location = %q, want form", profile.ParameterLocation)
	}
}
