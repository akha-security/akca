package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestPHP2ShellFullScanTargetsStayOnExplicitOrigins(t *testing.T) {
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{"https://example.test/app", "https://example.test/other", "https://second.test/"}
	r := NewRunner("php2shell-roots", nil, nil, nil, nil, nil, nil, cfg)
	root := &httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 200}}
	index := &httpclient.RequestResponse{Response: httpclient.ResponseRecord{StatusCode: 200}}
	selected := r.php2ShellFullScanTargets([]ScanTarget{
		{EndpointURL: "https://example.test/app/page", Method: "GET", ObservedResponse: root},
		{EndpointURL: "https://child.example.test/index.php", Method: "GET", ObservedResponse: root},
		{EndpointURL: "https://example.test/index.php?x=1", Method: "GET", ObservedResponse: root},
		{EndpointURL: "https://example.test/index.php", Method: "POST", ObservedResponse: root},
		{EndpointURL: "https://example.test/", Method: "GET", ObservedResponse: root},
		{EndpointURL: "https://example.test/index.php", Method: "GET", ObservedResponse: index},
	})
	if len(selected) != 2 {
		t.Fatalf("selected %d targets, want one per explicit origin: %+v", len(selected), selected)
	}
	if selected[0].EndpointURL != "https://example.test/index.php" || selected[0].ObservedResponse != index {
		t.Fatalf("first target = %+v, want observed /index.php", selected[0])
	}
	if selected[1].EndpointURL != "https://second.test/index.php" || selected[1].ObservedResponse != nil {
		t.Fatalf("second target = %+v, want direct /index.php fallback", selected[1])
	}
}

func TestPHP2ShellFullScanProbesOnlyIndexWithoutFollowingRedirect(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		hits[req.Method+" "+req.URL.Path]++
		mu.Unlock()
		if req.URL.Path == "/index.php" {
			http.Redirect(w, req, "/discovered", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := config.DefaultScanConfig()
	cfg.Targets = []string{srv.URL}
	cfg.PerHostRateLimit = 1000
	cfg.GlobalRateLimit = 1000
	sc := scope.NewEngine(cfg)
	client, err := httpclient.New(cfg, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	var finished map[string]interface{}
	r := NewRunner("php2shell-one-root", client, sc, nil, verification.NewEngine(nil, nil), nil,
		func(kind, _ string, data map[string]interface{}) error {
			if kind == "module_target_finished" {
				finished = data
			}
			return nil
		}, cfg)
	_, err = r.RunModule(context.Background(), "php2shell", []ScanTarget{
		{EndpointURL: srv.URL + "/app", Method: "GET"},
		{EndpointURL: srv.URL + "/other", Method: "GET"},
		{EndpointURL: srv.URL + "/index.php?item=1", Method: "GET"},
	})
	if err != nil {
		t.Fatalf("%v; target=%+v", err, finished)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(hits) != 1 || hits["GET /index.php"] != 1 {
		t.Fatalf("PHP2Shell requests = %+v, want only one direct GET /index.php", hits)
	}
}
