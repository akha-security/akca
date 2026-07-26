package fuzzing

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/storage"
)

func TestDiscoverTasksFromRobotsIsBoundedSafeAndSameOrigin(t *testing.T) {
	source := FuzzTask{URL: "https://example.com/robots.txt", Method: "GET", Path: "/robots.txt"}
	body := `
User-agent: *
Disallow: /admin
Allow: /public/
Disallow: /logout
Disallow: /search?q=secret
Disallow: /*.php$
Sitemap: https://example.com/sitemap-main.xml
Sitemap: https://evil.example/sitemap.xml
`
	tasks := DiscoverTasks(source, http.StatusOK, body, "text/plain")
	got := make(map[string]struct{}, len(tasks))
	for _, task := range tasks {
		got[task.URL] = struct{}{}
		if task.Method != http.MethodGet {
			t.Fatalf("adaptive task method = %s, want GET", task.Method)
		}
	}
	for _, expected := range []string{
		"https://example.com/admin",
		"https://example.com/public/",
		"https://example.com/search",
		"https://example.com/sitemap-main.xml",
	} {
		if _, ok := got[expected]; !ok {
			t.Errorf("missing adaptive task %s", expected)
		}
	}
	for _, rejected := range []string{
		"https://example.com/logout",
		"https://evil.example/sitemap.xml",
	} {
		if _, ok := got[rejected]; ok {
			t.Errorf("unsafe or off-origin task was accepted: %s", rejected)
		}
	}
}

func TestDiscoverTasksFromSitemap(t *testing.T) {
	source := FuzzTask{URL: "https://example.com/sitemap.xml", Method: "GET", Path: "/sitemap.xml"}
	body := `<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>https://example.com/internal/report</loc></url>
<url><loc>https://example.com/actuator/shutdown</loc></url>
<url><loc>https://other.example/private</loc></url>
</urlset>`
	tasks := DiscoverTasks(source, http.StatusOK, body, "application/xml")
	if len(tasks) != 1 || tasks[0].URL != "https://example.com/internal/report" {
		t.Fatalf("unexpected sitemap tasks: %+v", tasks)
	}
}

type adaptiveTestClient struct {
	bodies  map[string]string
	status  map[string]int
	visited map[string]int
}

func (c *adaptiveTestClient) Do(_ context.Context, method, rawURL string, _ []byte, _ map[string]string) (httpclient.RequestResponse, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return httpclient.RequestResponse{}, err
	}
	if c.visited == nil {
		c.visited = make(map[string]int)
	}
	c.visited[u.Path]++
	status := c.status[u.Path]
	if status == 0 {
		status = http.StatusNotFound
	}
	return httpclient.RequestResponse{
		Request: httpclient.RequestRecord{Method: method, URL: rawURL},
		Response: httpclient.ResponseRecord{
			StatusCode: status,
			Body:       c.bodies[u.Path],
			Headers:    map[string]string{"Content-Type": "text/plain"},
		},
	}, nil
}

func TestEngineFollowsRobotsHintsWithoutLearningFromLiveResults(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/adaptive.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}

	client := &adaptiveTestClient{
		bodies: map[string]string{
			"/robots.txt": "Disallow: /hidden-console",
			"/page-a":     "same legitimate page",
			"/page-b":     "same legitimate page",
		},
		status: map[string]int{
			"/robots.txt":     http.StatusOK,
			"/hidden-console": http.StatusForbidden,
			"/page-a":         http.StatusOK,
			"/page-b":         http.StatusOK,
		},
	}
	var results []FuzzResult
	emit := func(eventType, _ string, payload map[string]interface{}) error {
		if eventType == "fuzz_result_batch" {
			if batch, ok := payload["results"].([]FuzzResult); ok {
				results = append(results, batch...)
			}
		}
		return nil
	}
	engine := NewEngine("scan-adaptive", client, scope.NewEngine(config.DefaultScanConfig()), db, emit, 1)
	tasks := []FuzzTask{
		{URL: "http://127.0.0.1/robots.txt", Method: "GET", Category: CategoryGeneral, Path: "/robots.txt"},
		{URL: "http://127.0.0.1/page-a", Method: "GET", Category: CategoryGeneral, Path: "/page-a"},
		{URL: "http://127.0.0.1/page-b", Method: "GET", Category: CategoryGeneral, Path: "/page-b"},
	}
	if err := engine.RunTasks(context.Background(), tasks); err != nil {
		t.Fatal(err)
	}
	if client.visited["/hidden-console"] == 0 {
		t.Fatal("robots-discovered path was not tested")
	}
	for _, result := range results {
		if (result.URL == "http://127.0.0.1/page-a" || result.URL == "http://127.0.0.1/page-b") && result.IsSoft404 {
			t.Fatalf("live repeated response polluted soft-404 calibration: %+v", result)
		}
	}
}
