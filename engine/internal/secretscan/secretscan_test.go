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

func TestReportableFiltersPublicAndLowConfidenceIdentifiers(t *testing.T) {
	if !IsReportable(Match{Kind: "github_token", Confidence: 0.9}) {
		t.Fatal("provider credential should remain reportable")
	}
	for _, item := range []Match{
		{Kind: "stripe_publishable_key", Confidence: 0.9},
		{Kind: "firebase_database_url", Confidence: 0.9},
		{Kind: "bearer_token", Confidence: 0.55},
	} {
		if IsReportable(item) {
			t.Fatalf("%s must not become a passive secret finding", item.Kind)
		}
	}
}

func TestFalsePositiveRegressionFromClientJS(t *testing.T) {
	jsSamples := []string{
		`var a = s.DIRECTORY_SEARCH_ENABLED;`,
		`var b = s.CHOOSE_ALTERNATIVE_FACTOR;`,
		`var c = s.CONCURRENT_ALLOWED_DEVICES_COUNT;`,
		`var d = s.IS_SERVICE_ACCOUNT_CONFIGURED;`,
		`var e = s.SERVICE_ACCOUNT_PASSWORD;`,
		`var f = s.IS_CACHED_CREDENTIAL_UPDATE_WITHOUT_VPN_ENABLED;`,
		`s.setNamespaceSearchDisabled();`,
		`s.buildFakeRegistryWithDeprecations();`,
		`s.generateControllerFactory();`,
		`s.normalizeControllerQueryParams();`,
		`s.instrumentationSubscribe();`,
		`s.addCanonicalInternalModel();`,
		`url = "login?password=" + form.j_password.value + "&next=";`,
		`params = "pwd=" + encodeURIComponent(t.RADIUS_PASSWORD) + "";`,
	}
	for _, js := range jsSamples {
		matches := Detect(js)
		if len(matches) > 0 {
			t.Fatalf("false positive detected in JS sample %q: %+v", js, matches)
		}
	}
}

func TestOpenAIAndOktaFalsePositiveRegressions(t *testing.T) {
	fpSamples := []string{
		`sk-8030-kablosuz-cam-govde-su-isitici-sk-7338-p-367682`,
		`000-adet-nostalji-oyun-3-5inc-ipsekran-mp3`,
		`000000000000000000000000000000000000000000`,
		`sk-something-short`,
	}
	for _, sample := range fpSamples {
		matches := Detect(sample)
		for _, m := range matches {
			if m.Kind == "openai_key" || m.Kind == "okta_api_token" {
				t.Fatalf("false positive detected for %q: kind=%s value=%s", sample, m.Kind, m.Value)
			}
		}
	}

	// Valid Okta token: 00 + 40 mixed-case base62 high-entropy chars
	validOkta := "00aB3dE5gH7jK9mN1pQ3rS5tU7vW9xY1zA2bC4dE6f"
	matches := Detect("auth = \"" + validOkta + "\"")
	foundOkta := false
	for _, m := range matches {
		if m.Kind == "okta_api_token" {
			foundOkta = true
			break
		}
	}
	if !foundOkta {
		t.Fatalf("expected genuine okta_api_token to be detected in %q, got %+v", validOkta, matches)
	}
}

