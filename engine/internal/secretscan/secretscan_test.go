package secretscan

import (
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/testfixtures"
)

func kinds(ms []Match) map[string]bool {
	out := map[string]bool{}
	for _, m := range ms {
		out[m.Kind] = true
	}
	return out
}

func TestDetectProviderSecrets(t *testing.T) {
	// Assemble provider-shaped fixtures at runtime so repository secret
	// protection does not mistake intentionally fake scanner inputs for live
	// credentials.
	body := `
google = "` + testfixtures.GoogleAPIKey() + `";
ghp    = "` + testfixtures.GitHubToken() + `";
stripe = "` + testfixtures.StripeSecretKey() + `";
slack  = "` + testfixtures.SlackWebhook() + `";
db     = "postgres://app:s3cretValue99@db.internal:5432/app";
url    = "https://admin:s3cretValue99@db.internal.example.com";
openai = "` + testfixtures.OpenAIKey() + `";
ant    = "` + testfixtures.AnthropicKey() + `";
hf     = "` + testfixtures.HuggingFaceToken() + `";
slacktok = "` + testfixtures.SlackToken() + `";
`
	got := kinds(Detect(body))
	if got["aws_access_key_id"] {
		t.Fatal("AWS EXAMPLE keys should be filtered")
	}
	for _, want := range []string{
		"google_api_key", "github_token", "stripe_secret_key",
		"slack_webhook", "db_connection_string", "basic_auth_url", "openai_key",
		"anthropic_key", "huggingface_token", "slack_token",
	} {
		if !got[want] {
			t.Errorf("expected kind %q to be detected, got %v", want, got)
		}
	}
}

func TestExampleAWSKeyFiltered(t *testing.T) {
	if ms := Detect(`token = "` + testfixtures.AWSExampleAccessKey() + `";`); len(ms) != 0 {
		t.Fatalf("expected EXAMPLE AWS key to be filtered, got %+v", ms)
	}
}

func TestRedactionHidesValue(t *testing.T) {
	raw := testfixtures.GitHubToken()
	ms := Detect(`token = "` + raw + `";`)
	if len(ms) == 0 {
		t.Fatal("expected detection")
	}
	for _, m := range ms {
		if m.Value != raw {
			t.Fatalf("expected full value stored, got %q", m.Value)
		}
		if strings.Contains(m.Redacted, raw) {
			t.Fatalf("value not redacted: %s", m.Redacted)
		}
	}
}

func TestPlaceholderFiltering(t *testing.T) {
	body := `
const a = { api_key: "your_api_key_here_value" };
const b = { api_key: "process.env.SECRET_KEY" };
const c = { password: "changeme123" };
`
	if k := kinds(Detect(body)); k["api_key"] || k["password_assignment"] {
		t.Fatalf("placeholders should be filtered, got %v", k)
	}
}

func TestGenericRequiresEntropy(t *testing.T) {
	// Low-entropy repeated value should be rejected by the entropy gate.
	if k := kinds(Detect(`api_key = "aaaaaaaaaaaaaaaaaaaa"`)); k["api_key"] {
		t.Fatalf("low-entropy value should not be flagged, got %v", k)
	}
	// A realistic mixed-case + digit credential should pass.
	if k := kinds(Detect(`api_key = "Ab3Df8Gh1Jk5Lm9Np2Qr"`)); !k["api_key"] {
		t.Fatal("expected high-entropy generic api_key to be detected")
	}
}

func TestLineNumberReported(t *testing.T) {
	body := "line one\nline two\nkey = \"" + testfixtures.GitHubToken() + "\"\n"
	ms := Detect(body)
	if len(ms) == 0 || ms[0].Line != 3 {
		t.Fatalf("expected secret on line 3, got %+v", ms)
	}
}

func TestEvidenceJSONKeepsRawSecretForCompleteReporting(t *testing.T) {
	raw := testfixtures.GitHubToken()
	ev := EvidenceJSON("github_token", raw, "https://example.com/app.js", 7)
	if !strings.Contains(ev, raw) {
		t.Fatalf("evidence did not preserve raw secret: %s", ev)
	}
	if !strings.Contains(ev, "secret_sha256") || !strings.Contains(ev, "secret_preview") {
		t.Fatalf("evidence missing fingerprint or preview: %s", ev)
	}
}
