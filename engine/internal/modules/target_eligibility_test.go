package modules

import (
	"context"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/reflection"
)

func TestStaticResourcesProduceNoInjectionRequests(t *testing.T) {
	for _, raw := range []string{
		"https://example.com/assets", "https://example.com/assets/", "https://example.com/assets/app.js?v=123",
		"https://example.com/static/123/chunk.js", "https://example.com/icons/logo.svg", "https://example.com/app.js.map",
		"https://example.com/robots.txt?debug=1", "https://example.com/dashboard/%26%26%28j=E,E=null%29",
	} {
		t.Run(raw, func(t *testing.T) {
			calls := 0
			r := newActiveRunner(t, auditDoer(func(context.Context, string, string, []byte, map[string]string) (httpclient.RequestResponse, error) {
				calls++
				return httpclient.RequestResponse{}, nil
			}))
			for _, location := range []string{"query", "path", "header"} {
				target := ScanTarget{EndpointURL: raw, Method: "GET", Parameter: "v", Location: location}
				r.runSQLi(context.Background(), target)
				r.runXSS(context.Background(), target)
				r.runSSRF(context.Background(), target)
			}
			if calls != 0 {
				t.Fatalf("static resource generated %d injection requests", calls)
			}
		})
	}
}

func TestDynamicResourcesAndExactOverridesRemainEligible(t *testing.T) {
	r := newActiveRunner(t, auditDoer(func(context.Context, string, string, []byte, map[string]string) (httpclient.RequestResponse, error) {
		return httpclient.RequestResponse{}, nil
	}))
	for _, target := range []ScanTarget{
		{EndpointURL: "https://example.com/search?q=test", Method: "GET", Parameter: "q", Location: "query"},
		{EndpointURL: "https://example.com/api/preview?url=https://origin.test", Method: "GET", Parameter: "url", Location: "query"},
		{EndpointURL: "https://example.com/assets/query.js", Method: "POST", Parameter: "query", Location: "json", BodyTemplate: `{"query":"native"}`},
		{EndpointURL: "https://example.com/assets/api?name=native", Method: "GET", Parameter: "name", Location: "query", ObservedResponse: &httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"user_id":123}`}}},
		{EndpointURL: "https://example.com/dynamic.js?q=native", Method: "GET", Parameter: "q", Location: "query", Profile: reflection.ReflectionProfile{Confidence: 1, ReflectionKind: reflection.ReflectionRaw}},
	} {
		for _, module := range []string{"sqli", "xss", "ssrf"} {
			if ok, reason := r.shouldRunModule(module, target); !ok {
				t.Errorf("%s lost dynamic surface %s: %s", module, target.EndpointURL, reason)
			}
		}
	}
	r.cfg.ForceActiveScanURLs = []string{"https://example.com/assets"}
	if ok, reason := r.shouldRunModule("sqli", ScanTarget{EndpointURL: "https://example.com/assets", Method: "GET", Parameter: "q"}); !ok {
		t.Fatalf("explicit override rejected: %s", reason)
	}
	if ok, _ := r.shouldRunModule("sqli", ScanTarget{EndpointURL: "https://example.com/assets/other", Method: "GET", Parameter: "q"}); ok {
		t.Fatal("exact override leaked to child paths")
	}
	if ok, _ := r.shouldRunModule("sqli", ScanTarget{EndpointURL: "https://example.com/assets", Method: "GET", Parameter: "q", ObservedResponse: &httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 404}}}); ok {
		t.Fatal("override admitted known 404")
	}
}

func TestCompletedWorkRetainsNewParametersAndFailedTargets(t *testing.T) {
	r := newActiveRunner(t, nil)
	old := ScanTarget{EndpointURL: "https://example.com/search", Method: "GET", Parameter: "q", Location: "query"}
	fresh := old
	fresh.Parameter = "hidden"
	r.markCompletedWork("sqli", old)
	restored := newActiveRunner(t, nil)
	restored.RestoreCompletedWork(r.CompletedWork())
	pending := restored.PendingTargets("sqli", []ScanTarget{old, fresh})
	if len(pending) != 1 || pending[0].Parameter != "hidden" {
		t.Fatalf("incremental work lost new input: %+v", pending)
	}
	if len(restored.PendingTargets("xss", []ScanTarget{old})) != 1 {
		t.Fatal("completion leaked across modules")
	}
}

func TestPendingTargetsDeduplicatesAndDetectsRunnableInputs(t *testing.T) {
	r := newActiveRunner(t, nil)
	query := ScanTarget{EndpointURL: "https://example.com/search?q=one", Method: "GET", Parameter: "q", Location: "query"}
	noParameter := ScanTarget{EndpointURL: "https://example.com/search", Method: "GET"}
	pending := r.PendingTargets("xss", []ScanTarget{query, query, noParameter})
	if len(pending) != 2 {
		t.Fatalf("duplicate target was queued: %+v", pending)
	}
	if !r.HasRunnableTargets("xss", pending) {
		t.Fatal("new query input was not runnable")
	}
	r.markCompletedWork("xss", query)
	pending = r.PendingTargets("xss", []ScanTarget{query, noParameter})
	if len(pending) != 1 || r.HasRunnableTargets("xss", pending) {
		t.Fatalf("follow-up would display an XSS phase for parameterless input: %+v", pending)
	}
}

func TestSQLiRejectedBaselineIsNotRetriedInFollowup(t *testing.T) {
	requests := 0
	r := newActiveRunner(t, auditDoer(func(_ context.Context, method, raw string, _ []byte, headers map[string]string) (httpclient.RequestResponse, error) {
		requests++
		return httpclient.RequestResponse{
			Request:  httpclient.RequestRecord{Method: method, URL: raw, Headers: headers},
			Response: httpclient.ResponseRecord{StatusCode: 404, Body: "not found", Headers: map[string]string{"Content-Type": "text/html"}},
		}, nil
	}))
	target := ScanTarget{EndpointURL: "https://example.com/search?id=1", Method: "GET", Parameter: "id", Location: "query"}
	if _, err := r.RunModule(context.Background(), "sqli", []ScanTarget{target}); err != nil {
		t.Fatal(err)
	}
	if requests == 0 {
		t.Fatal("SQLi baseline was never requested")
	}
	if pending := r.PendingTargets("sqli", []ScanTarget{target}); len(pending) != 0 {
		t.Fatalf("rejected SQLi baseline would be requested again: %+v", pending)
	}
}
