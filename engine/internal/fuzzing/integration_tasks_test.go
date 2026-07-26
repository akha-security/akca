package fuzzing

import "testing"

func TestBuildIntegrationTasksBounded(t *testing.T) {
	tasks := BuildIntegrationTasks("http://127.0.0.1:1/")
	if len(tasks) == 0 || len(tasks) > 40 {
		t.Fatalf("expected bounded integration tasks, got %d", len(tasks))
	}
	seen := map[string]struct{}{}
	for _, task := range tasks {
		if _, ok := seen[task.URL]; ok {
			t.Fatalf("duplicate task url %s", task.URL)
		}
		seen[task.URL] = struct{}{}
		if task.Method != "GET" {
			t.Fatalf("expected GET, got %s", task.Method)
		}
	}
}
