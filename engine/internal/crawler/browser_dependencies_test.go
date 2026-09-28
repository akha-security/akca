package crawler

import "testing"

func TestPassiveDependencyLearningUsesOnlyResourceTagsAndCSP(t *testing.T) {
	hosts := passiveDependencyHosts("https://app.test/", `<html>
<a href="https://navigation.example/path">leave</a>
<script src="https://cdn.example/app.js"></script>
<link rel="stylesheet" href="https://style.example/app.css">
<img src="https://images.example/a.png">
</html>`, map[string]string{"Content-Security-Policy": "default-src 'self'; font-src https://fonts.example"})
	want := map[string]bool{"cdn.example": true, "style.example": true, "images.example": true, "fonts.example": true}
	if len(hosts) != len(want) {
		t.Fatalf("dependency hosts=%v", hosts)
	}
	for _, host := range hosts {
		if !want[host] {
			t.Fatalf("unexpected dependency %q in %v", host, hosts)
		}
	}
}
