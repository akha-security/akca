package modules

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/testfixtures"
)

func TestStatusOnlyDifferentialRejects405(t *testing.T) {
	if !statusOnlyDifferential(405, 200) {
		t.Fatal("405 vs 200 should be status-only differential")
	}
	if differentialWithStatusGuard("Method Not Allowed", "ok page", `' OR 1=1`, 405, 200) {
		t.Fatal("405 body diff should not confirm")
	}
}

func TestDifferentialRejectsPayloadReflection(t *testing.T) {
	payload := `"><svg/onload=alert(1)>`
	base := "search results"
	body := `search results: "><svg/onload=alert(1)>`
	if differentialWithStatusGuard(body, base, payload, 200, 200) {
		t.Fatal("payload reflection alone should not confirm differential")
	}
}

func TestSecretExposureRequiresNovelSecret(t *testing.T) {
	token := testfixtures.GitHubToken()
	body := `key = "` + token + `"`
	base := body
	if secretExposureConfirmed(body, base, "github_token") {
		t.Fatal("secret already in baseline should not confirm")
	}
	if !secretExposureConfirmed(body, "", "github_token") {
		t.Fatal("novel secret should confirm when no baseline")
	}
}

func TestNoSQLRejectsStatusOnlyDiff(t *testing.T) {
	base := httpclient.ResponseRecord{Body: "ok", StatusCode: 200}
	probe := httpclient.ResponseRecord{Body: "not found", StatusCode: 404}
	if moduleSignalConfirmed("nosql", defaultPayload("nosql", "x", "{}", "nosql_diff"), "nosql_diff", base, probe, false, "") {
		t.Fatal("404 status-only diff should not confirm nosql")
	}
}

func TestXXEDefaultDiffRejected(t *testing.T) {
	base := httpclient.ResponseRecord{Body: "a", StatusCode: 200}
	probe := httpclient.ResponseRecord{Body: "ab", StatusCode: 200}
	if moduleSignalConfirmed("xxe", defaultPayload("xxe", "x", "x", "unknown"), "unknown", base, probe, false, "") {
		t.Fatal("xxe unknown signal with tiny diff should not confirm")
	}
}

func TestCORSDefaultRejected(t *testing.T) {
	h := map[string]string{"Access-Control-Allow-Origin": "https://other.example"}
	if corsSignalConfirmed(nil, h, "trusted_subdomain", "https://evil.example") {
		t.Fatal("cors default branch should not confirm unrelated origin")
	}
}
