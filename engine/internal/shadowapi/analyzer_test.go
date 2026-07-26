package shadowapi

import "testing"

func TestAnalyzeFindsRuntimeAndContractDrift(t *testing.T) {
	diffs := Analyze([]Operation{
		{URL: "https://api.test/v1/users/{id}", Method: "GET", Source: "api_import"},
		{URL: "https://api.test/v1/orders", Method: "POST", Source: "api_import"},
		{URL: "https://api.test/v1/legacy", Method: "DELETE", Source: "api_import"},
		{URL: "https://api.test/v1/users/42", Method: "GET", Source: "browser_xhr"},
		{URL: "https://api.test/v1/orders", Method: "PUT", Source: "browser_xhr"},
		{URL: "https://api.test/internal/export", Method: "POST", Source: "browser_xhr"},
	})
	counts := map[string]int{}
	for _, diff := range diffs {
		counts[diff.Kind]++
	}
	if counts[MethodDrift] != 1 || counts[UndocumentedRuntime] != 1 || counts[DocumentedUnseen] != 1 {
		t.Fatalf("unexpected shadow API differences: %+v", diffs)
	}
}

func TestAnalyzeIgnoresOrdinaryPassivePageLinks(t *testing.T) {
	diffs := Analyze([]Operation{
		{URL: "https://app.test/docs", Method: "GET", Source: "link"},
		{URL: "https://app.test/static/app.js", Method: "GET", Source: "script"},
	})
	if len(diffs) != 0 {
		t.Fatalf("ordinary passive links must not be classified as shadow APIs: %+v", diffs)
	}
}
