package evidencemarkers

import (
	"strings"
	"testing"
)

func TestForResponseSSTIMath(t *testing.T) {
	markers := ForResponse("{{7*7}}", "math_evaluation", "", "result: 49 ok", "")
	found := false
	for _, m := range markers {
		if m == "49" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 49 in markers, got %v", markers)
	}
}

func TestForResponseUnionSentinel(t *testing.T) {
	payload := `' UNION SELECT 818533,828533,838533-- -`
	markers := ForResponse(payload, "union_signal", "baseline", "rows 818533 828533", "baseline")
	if len(markers) == 0 {
		t.Fatal("expected union sentinels in markers")
	}
}

func TestForResponseDoesNotUseGenericHTMLDiffAsProof(t *testing.T) {
	baseline := `<!DOCTYPE html><html><head><meta name="build" content="old-build"></head><body>same</body></html>`
	probe := `<!DOCTYPE html><html><head><meta name="build" content="674b8d5747-78dds">` +
		`<script src="https://cdn.example/app.bundle-a91cf778.js"></script></head><body>same</body></html>`
	markers := ForResponse(`;printf AKCA_CMD_7319`, "canary_output", baseline, probe, "")
	if len(markers) != 0 {
		t.Fatalf("generic HTML differences must not become proof: %v", markers)
	}
}

func TestForResponseUsesTypedSQLMarkerOnly(t *testing.T) {
	probe := `<!DOCTYPE html><script src="app.bundle-a91cf778.js"></script>` +
		`<p>You have an error in your SQL syntax</p>`
	markers := ForResponse(`'`, "error_based", "normal page", probe, "")
	joined := strings.ToLower(strings.Join(markers, "\n"))
	if !strings.Contains(joined, "error in your sql syntax") {
		t.Fatalf("expected typed SQL error marker, got %v", markers)
	}
	for _, noise := range []string{"doctype", "bundle", "a91cf778"} {
		if strings.Contains(joined, noise) {
			t.Fatalf("unexpected HTML noise %q in markers: %v", noise, markers)
		}
	}
}

func TestForReportDropsLegacyHTMLAndBundleMarkers(t *testing.T) {
	body := `<!DOCTYPE html><html><head><meta content="674b8d5747-78dds">` +
		`<img src="https://cdn.example/footer-etbis.png"></head><body>AKCA_CMD_7320</body></html>`
	persisted := []string{
		`<!DOCTYPE html><html><head>`,
		`674b8d5747-78dds`,
		`https://cdn.example/footer-etbis.png`,
		`AKCA_CMD_7320`,
	}
	markers := ForReport(`;printf 'AKCA_CMD_%d' $((7319+1))`, "canary_output", body, persisted)
	if len(markers) != 1 || markers[0] != "AKCA_CMD_7320" {
		t.Fatalf("expected only trusted canary marker, got %v", markers)
	}
}

func TestForResponseHighlightsReflectedPayloadWithoutHTMLScaffold(t *testing.T) {
	payload := `<svg onload=alert(7319)>`
	body := `<!DOCTYPE html><html><head><script src="bundle-8b19d0.js"></script></head><body>` + payload + `</body></html>`
	markers := ForResponse(payload, "reflected", "clean", body, "")
	joined := strings.Join(markers, "\n")
	if !strings.Contains(joined, payload) {
		t.Fatalf("expected reflected payload marker, got %v", markers)
	}
	if strings.Contains(strings.ToLower(joined), "doctype") || strings.Contains(strings.ToLower(joined), "bundle") {
		t.Fatalf("HTML scaffold leaked into typed markers: %v", markers)
	}
}
