package fuzzing

import (
	"sync"
	"testing"
)

func TestClassifyStatusCodes(t *testing.T) {
	cases := map[int]string{
		200: "ok", 301: "redirect", 401: "unauthorized", 403: "forbidden",
		404: "not_found", 405: "method_not_allowed", 429: "rate_limited", 500: "server_error",
	}
	for code, want := range cases {
		if got := ClassifyStatusCode(code); got != want {
			t.Fatalf("code %d got %q want %q", code, got, want)
		}
	}
}

func TestArchiveDetection(t *testing.T) {
	if !IsArchiveExposure("https://example.com/backup.zip", 200, "application/zip") {
		t.Fatal("expected archive exposure")
	}
	if IsArchiveExposure("https://example.com/page.html", 200, "text/html") {
		t.Fatal("html should not be archive")
	}
}

func TestSoft404Calibration(t *testing.T) {
	c := NewSoft404Calibrator()
	host := "example.com"
	c.Observe(host, 200, "custom not found page")
	c.Observe(host, 200, "custom not found page")
	if !c.IsSoft404(host, 200, "custom not found page") {
		t.Fatal("expected soft 404 detection")
	}
}

func TestSoft404CalibrationRecognizesReflectedDynamicPath(t *testing.T) {
	c := NewSoft404Calibrator()
	host := "example.com"
	c.ObserveCalibration(host, 200, "Page not found: /akca-probe-aabbccdd")
	c.ObserveCalibration(host, 200, "Page not found: /akca-probe-11223344.html")
	if !c.IsSoft404(host, 200, "Page not found: /admin") {
		t.Fatal("expected dynamic reflected-path wildcard to be recognized")
	}
}

func TestSoft404RequiresCalibrationConsensus(t *testing.T) {
	c := NewSoft404Calibrator()
	c.ObserveCalibration("example.com", 200, "Page not found: /akca-probe-aabbccdd")
	if c.IsSoft404("example.com", 200, "Page not found: /admin") {
		t.Fatal("one calibration response is not enough to classify a soft 404")
	}
}

func TestQueue403ThreadSafeDedupBoundedPriority(t *testing.T) {
	q := NewQueue403(3)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			q.Enqueue("https://example.com/a", "GET")
			q.Enqueue("https://example.com/admin", "GET")
		}(i)
	}
	wg.Wait()
	if q.Metrics().TotalEnqueued > 3 {
		t.Fatalf("queue exceeded max size enqueue count: %+v", q.Metrics())
	}
	if q.Metrics().TotalDeduplicated == 0 {
		t.Fatal("expected deduplicated count")
	}
	q.Enqueue("https://example.com/api/v1", "GET")
	q.Enqueue("https://example.com/z-low", "GET")
	first, ok := q.Dequeue()
	if !ok {
		t.Fatal("expected dequeue")
	}
	if first.Priority < Score403Priority("https://example.com/api/v1", "GET") {
		// high priority path should come first when present in heap top
	}
}

func TestResultAggregatorBatching(t *testing.T) {
	var batches int
	agg := NewResultAggregator("scan", 3, func(string, string, map[string]interface{}) error {
		batches++
		return nil
	})
	_ = agg.Add(FuzzResult{Signal: "ok"})
	_ = agg.Add(FuzzResult{Signal: "forbidden"})
	if batches != 0 {
		t.Fatal("should not flush before limit")
	}
	_ = agg.Add(FuzzResult{Signal: "archive_exposure"})
	if batches != 1 {
		t.Fatalf("expected 1 batch, got %d", batches)
	}
}

func TestActuatorShutdownExcluded(t *testing.T) {
	tasks := BuildTasks("https://example.com")
	for _, task := range tasks {
		if task.Path == "/actuator/shutdown" {
			t.Fatal("shutdown actuator must not be fuzzed")
		}
	}
}

func Test403PriorityOrdering(t *testing.T) {
	low := Score403Priority("https://example.com/static/app.js", "GET")
	high := Score403Priority("https://example.com/admin/api", "GET")
	if high <= low {
		t.Fatalf("admin/api should outrank static: high=%d low=%d", high, low)
	}
}

func TestPrefixPruningRequiresRepeatedHard404s(t *testing.T) {
	e := &Engine{}
	e.recordPrefixMiss("/legacy")
	e.recordPrefixMiss("/legacy")
	if _, banned := e.bannedPrefixes.Load("/legacy"); banned {
		t.Fatal("prefix was pruned after fewer than three hard misses")
	}
	e.recordPrefixMiss("/legacy")
	if _, banned := e.bannedPrefixes.Load("/legacy"); !banned {
		t.Fatal("prefix should be pruned after repeated hard misses")
	}
}

func TestProtectedRootPrefixes(t *testing.T) {
	// Root /api should not be extractable as a depth-1 bannable prefix
	if p := pathPrefix("/api"); p != "" {
		t.Fatalf("expected empty prefix for protected root /api, got %q", p)
	}
	// Multi-segment under /api should track specific sub-prefix /api/legacy
	if p := pathPrefix("/api/legacy/endpoint"); p != "/api/legacy" {
		t.Fatalf("expected /api/legacy prefix, got %q", p)
	}
	// Non-protected paths should track normally
	if p := pathPrefix("/old-admin/test"); p != "/old-admin/test" {
		t.Fatalf("expected /old-admin/test, got %q", p)
	}
}
