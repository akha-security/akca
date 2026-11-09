package storage

import "testing"

func TestPendingJSCrawlExcludesObservedAndScriptURLs(t *testing.T) {
	db, err := Open(t.TempDir() + "/pending-js.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	const scanID = "pending-js"
	for _, entry := range []struct {
		path, method string
		status       int
	}{
		{"/already", "GET", 200}, {"/missing", "GET", 404}, {"/blocked", "GET", 403},
		{"/chunk.mjs?v=1", "GET", 0}, {"/chunk.cjs?v=1", "GET", 0},
		{"/users/{id}", "GET", 0}, {"/users/:id", "GET", 0},
		{"/new", "GET", 0}, {"/save", "POST", 0},
	} {
		if err := db.SaveDiscoveredEndpoint(scanID, map[string]interface{}{
			"url": "https://example.test" + entry.path, "method": entry.method, "source": "js_analyzer", "confidence": .9,
			"request_template": map[string]interface{}{"response_status": entry.status},
		}); err != nil {
			t.Fatal(err)
		}
	}
	endpoints, err := db.ListPendingJSDiscoveredAPIEndpoints(scanID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 2 || endpoints[0].URL != "https://example.test/new" || endpoints[1].Method != "POST" {
		t.Fatalf("pending targets were limited before filtering or contained observed/script URLs: %+v", endpoints)
	}
	scripts, err := db.ListScriptEndpoints(scanID, 0)
	if err != nil || len(scripts) != 2 {
		t.Fatalf("module script URLs were lost: %v err=%v", scripts, err)
	}
}
