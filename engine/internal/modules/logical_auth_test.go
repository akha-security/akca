package modules

import "testing"

func TestExtractIDCandidatesNumeric(t *testing.T) {
	cands := extractIDCandidates("https://example.com/api/user?id=42&name=test", "id")
	if len(cands) == 0 || cands[0].Kind != "numeric" {
		t.Fatalf("expected numeric id candidate, got %+v", cands)
	}
}

func TestExtractIDCandidatesUUIDPath(t *testing.T) {
	uuid := "550e8400-e29b-41d4-a716-446655440000"
	cands := extractIDCandidates("https://example.com/users/"+uuid+"/profile", "")
	found := false
	for _, c := range cands {
		if c.Kind == "uuid" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected uuid path segment, got %+v", cands)
	}
}

func TestBuildStepSkipURLs(t *testing.T) {
	urls := buildStepSkipURLs("https://shop.example.com/checkout/payment")
	if len(urls) == 0 {
		t.Fatal("expected step skip URLs for checkout flow")
	}
	found := false
	for _, u := range urls {
		if containsAny(u, "receipt", "confirm", "complete") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected terminal step URL, got %v", urls)
	}
}

func TestClassifyIDValueEmail(t *testing.T) {
	if classifyIDValue("user@example.com") != "email" {
		t.Fatal("expected email classification")
	}
}

func TestIDSwapValuesNumeric(t *testing.T) {
	vals := idSwapValues("numeric", "5")
	if len(vals) < 3 {
		t.Fatalf("expected swap values, got %v", vals)
	}
}
