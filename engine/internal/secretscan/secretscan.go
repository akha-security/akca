// Package secretscan provides a reusable, high-coverage secret/credential
// detector. It is shared by the JavaScript analyzer (for downloaded JS) and the
// crawler (for every fetched response body: HTML, JSON, inline scripts, etc.).
//
// Detection combines fixed-format provider signatures (AWS, Google, Stripe,
// GitHub, …) with generic credential-assignment heuristics that are gated by
// placeholder filtering and Shannon-entropy checks to keep false positives low.
package secretscan

import (
	"math"
	"regexp"
	"strings"
)

// Match is a single secret finding. Value holds the full detected secret for
// local reporting; Redacted is a masked preview for logs/events only.
type Match struct {
	Kind       string  `json:"kind"`
	Value      string  `json:"value"`
	Redacted   string  `json:"redacted"`
	Confidence float64 `json:"confidence"`
	Line       int     `json:"line,omitempty"`
}

// pattern describes a single detector. valueGroup is the capture group holding
// the sensitive value to redact (0 = whole match). When generic is true the
// captured value is additionally run through placeholder and entropy filters.
type pattern struct {
	kind       string
	re         *regexp.Regexp
	confidence float64
	valueGroup int
	generic    bool
}

var patterns = []pattern{
	// --- Cloud: AWS ---
	{kind: "aws_access_key_id", re: regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b`), confidence: 0.9},
	{kind: "aws_secret_access_key", re: regexp.MustCompile(`(?i)aws[_\- ]?(?:secret|sk)[_\- ]?(?:access)?[_\- ]?key\s*[:=]\s*["']([A-Za-z0-9/+]{40})["']`), confidence: 0.9, valueGroup: 1},
	{kind: "aws_session_token", re: regexp.MustCompile(`(?i)aws[_\- ]?session[_\- ]?token\s*[:=]\s*["']([A-Za-z0-9/+=]{100,})["']`), confidence: 0.8, valueGroup: 1},
	{kind: "aws_mws_token", re: regexp.MustCompile(`\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`), confidence: 0.85},

	// --- Cloud: Google / GCP / Firebase ---
	{kind: "google_api_key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), confidence: 0.9},
	{kind: "google_oauth_token", re: regexp.MustCompile(`\bya29\.[0-9A-Za-z_\-]{20,}`), confidence: 0.8},
	{kind: "google_oauth_client_id", re: regexp.MustCompile(`\b[0-9]{10,}-[0-9a-z]{32}\.apps\.googleusercontent\.com\b`), confidence: 0.6},
	{kind: "gcp_service_account", re: regexp.MustCompile(`"type"\s*:\s*"service_account"`), confidence: 0.7},
	{kind: "firebase_cloud_messaging_key", re: regexp.MustCompile(`\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}\b`), confidence: 0.85},
	{kind: "firebase_database_url", re: regexp.MustCompile(`\bhttps://[a-z0-9.\-]+\.firebaseio\.com\b`), confidence: 0.5},

	// --- Cloud: Azure / DigitalOcean / Heroku ---
	{kind: "azure_storage_key", re: regexp.MustCompile(`(?i)AccountKey\s*=\s*[A-Za-z0-9/+]{86}==`), confidence: 0.85},
	{kind: "azure_ad_client_secret", re: regexp.MustCompile(`(?i)client[_\- ]?secret\s*[:=]\s*["']([A-Za-z0-9~._\-]{34,40})["']`), confidence: 0.6, valueGroup: 1, generic: true},
	{kind: "digitalocean_token", re: regexp.MustCompile(`\bdo[oprv]_v1_[0-9a-f]{64}\b`), confidence: 0.9},
	{kind: "heroku_api_key", re: regexp.MustCompile(`(?i)heroku[a-z0-9_ \-]*\s*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?`), confidence: 0.7, valueGroup: 1},

	// --- Source control / CI / registries ---
	{kind: "github_token", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`), confidence: 0.9},
	{kind: "github_fine_grained_pat", re: regexp.MustCompile(`\bgithub_pat_[0-9a-zA-Z_]{22,}\b`), confidence: 0.9},
	{kind: "gitlab_pat", re: regexp.MustCompile(`\bglpat-[0-9A-Za-z\-_]{20,}\b`), confidence: 0.9},
	{kind: "npm_token", re: regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), confidence: 0.9},
	{kind: "pypi_token", re: regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b`), confidence: 0.9},
	{kind: "rubygems_key", re: regexp.MustCompile(`\brubygems_[0-9a-f]{48}\b`), confidence: 0.85},
	{kind: "dockerhub_pat", re: regexp.MustCompile(`\bdckr_pat_[A-Za-z0-9_\-]{20,}\b`), confidence: 0.85},

	// --- Payments ---
	{kind: "stripe_secret_key", re: regexp.MustCompile(`\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b`), confidence: 0.95},
	{kind: "stripe_test_key", re: regexp.MustCompile(`\b(?:sk|rk)_test_[0-9a-zA-Z]{20,}\b`), confidence: 0.6},
	{kind: "stripe_publishable_key", re: regexp.MustCompile(`\bpk_live_[0-9a-zA-Z]{20,}\b`), confidence: 0.5},
	{kind: "square_token", re: regexp.MustCompile(`\bsq0[a-z]{3}-[0-9A-Za-z\-_]{22,}\b`), confidence: 0.8},
	{kind: "square_oauth_secret", re: regexp.MustCompile(`\bsq0csp-[0-9A-Za-z\-_]{43}\b`), confidence: 0.85},
	{kind: "paypal_braintree_token", re: regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`), confidence: 0.9},

	// --- Messaging / Email / SaaS APIs ---
	{kind: "slack_token", re: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`), confidence: 0.9},
	{kind: "slack_webhook", re: regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]+`), confidence: 0.9},
	{kind: "discord_bot_token", re: regexp.MustCompile(`\b[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b`), confidence: 0.8},
	{kind: "discord_webhook", re: regexp.MustCompile(`https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,}/[A-Za-z0-9_\-]{60,}`), confidence: 0.9},
	{kind: "telegram_bot_token", re: regexp.MustCompile(`\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}\b`), confidence: 0.85},
	{kind: "sendgrid_key", re: regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`), confidence: 0.9},
	{kind: "mailgun_key", re: regexp.MustCompile(`\bkey-[0-9a-zA-Z]{32}\b`), confidence: 0.75},
	{kind: "mailchimp_key", re: regexp.MustCompile(`\b[0-9a-f]{32}-us[0-9]{1,2}\b`), confidence: 0.8},
	{kind: "postmark_token", re: regexp.MustCompile(`(?i)postmark[a-z_ \-]*\s*[:=]\s*["']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']`), confidence: 0.7, valueGroup: 1},
	{kind: "twilio_account_sid", re: regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`), confidence: 0.7},
	{kind: "twilio_api_key", re: regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`), confidence: 0.7},
	{kind: "openai_key", re: regexp.MustCompile(`\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}\b`), confidence: 0.8},
	{kind: "anthropic_key", re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`), confidence: 0.85},
	{kind: "huggingface_token", re: regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}\b`), confidence: 0.8},
	{kind: "mapbox_token", re: regexp.MustCompile(`\b(?:pk|sk)\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}`), confidence: 0.7},
	{kind: "algolia_admin_key", re: regexp.MustCompile(`(?i)algolia[a-z_ \-]*(?:admin|api)[a-z_ \-]*key\s*[:=]\s*["']([0-9a-f]{32})["']`), confidence: 0.7, valueGroup: 1},
	{kind: "datadog_api_key", re: regexp.MustCompile(`(?i)(?:dd|datadog)[a-z_ \-]*api[a-z_ \-]*key\s*[:=]\s*["']([0-9a-f]{32})["']`), confidence: 0.7, valueGroup: 1},
	{kind: "newrelic_key", re: regexp.MustCompile(`\bNRAK-[A-Z0-9]{27}\b`), confidence: 0.85},
	{kind: "cloudflare_api_token", re: regexp.MustCompile(`(?i)cloudflare[a-z_ \-]*(?:api[a-z_ \-]*)?token\s*[:=]\s*["']([A-Za-z0-9_\-]{40})["']`), confidence: 0.7, valueGroup: 1},
	{kind: "shopify_token", re: regexp.MustCompile(`\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b`), confidence: 0.9},
	{kind: "dropbox_token", re: regexp.MustCompile(`\bsl\.[A-Za-z0-9_\-]{130,}\b`), confidence: 0.8},
	{kind: "facebook_access_token", re: regexp.MustCompile(`\bEAACEdEose0cBA[0-9A-Za-z]{20,}\b`), confidence: 0.7},
	{kind: "linkedin_secret", re: regexp.MustCompile(`(?i)linkedin[a-z_ \-]*secret\s*[:=]\s*["']([A-Za-z0-9]{16})["']`), confidence: 0.6, valueGroup: 1},

	// --- Additional Cloud Storage & SaaS APIs ---
	{kind: "openai_org_id", re: regexp.MustCompile(`\borg-[A-Za-z0-9]{24}\b`), confidence: 0.85},
	{kind: "deepseek_key", re: regexp.MustCompile(`\bsk-[a-f0-9]{32}\b`), confidence: 0.85},
	{kind: "groq_api_key", re: regexp.MustCompile(`\bgsk_[a-zA-Z0-9]{52}\b`), confidence: 0.9},
	{kind: "perplexity_api_key", re: regexp.MustCompile(`\bpplx-[a-f0-9]{48}\b`), confidence: 0.9},
	{kind: "replicate_api_token", re: regexp.MustCompile(`\br8_[A-Za-z0-9]{37}\b`), confidence: 0.9},
	{kind: "okta_api_token", re: regexp.MustCompile(`\b00[A-Za-z0-9_\-]{40}\b`), confidence: 0.85},
	{kind: "doppler_token", re: regexp.MustCompile(`\bdp\.st\.[a-z0-9_\-]{40,}\b`), confidence: 0.9},
	{kind: "postman_api_key", re: regexp.MustCompile(`\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b`), confidence: 0.9},
	{kind: "tailscale_auth_key", re: regexp.MustCompile(`\btskey-auth-[A-Za-z0-9_\-]{30,}\b`), confidence: 0.9},
	{kind: "razorpay_key_id", re: regexp.MustCompile(`\brzp_(?:test|live)_[0-9a-zA-Z]{14}\b`), confidence: 0.9},
	{kind: "square_access_token", re: regexp.MustCompile(`\bEAAA[a-zA-Z0-9_\-]{60}\b`), confidence: 0.9},
	{kind: "plaid_secret", re: regexp.MustCompile(`(?i)plaid[a-z_ \-]*(?:secret|key)\s*[:=]\s*["']([0-9a-f]{30})["']`), confidence: 0.8, valueGroup: 1},
	{kind: "s3_bucket_url", re: regexp.MustCompile(`\bhttps?://[a-z0-9.\-]+\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com\b`), confidence: 0.75},
	{kind: "azure_blob_url", re: regexp.MustCompile(`\bhttps?://[a-z0-9.\-]+\.blob\.core\.windows\.net\b`), confidence: 0.75},
	{kind: "gcp_storage_url", re: regexp.MustCompile(`\bhttps?://storage\.googleapis\.com/[a-z0-9.\-_]+\b`), confidence: 0.7},
	{kind: "kubernetes_sa_token", re: regexp.MustCompile(`\beyJhbGciOiJSUzI1NiIsImtpZCI6[A-Za-z0-9_\-.]+\b`), confidence: 0.9},
	{kind: "gitlab_ci_registration_token", re: regexp.MustCompile(`\bglrt-[0-9A-Za-z\-_]{20,}\b`), confidence: 0.9},
	{kind: "gitlab_pipeline_token", re: regexp.MustCompile(`\bglpt-[0-9a-f]{32}\b`), confidence: 0.9},
	{kind: "github_app_secret", re: regexp.MustCompile(`\bghs_[A-Za-z0-9]{36}\b`), confidence: 0.9},
	{kind: "github_refresh_token", re: regexp.MustCompile(`\bghr_[A-Za-z0-9]{36}\b`), confidence: 0.9},
	{kind: "vercel_token", re: regexp.MustCompile(`\bvc_[A-Za-z0-9]{24,}\b`), confidence: 0.85},
	{kind: "resend_api_key", re: regexp.MustCompile(`\bre_[A-Za-z0-9]{24,}\b`), confidence: 0.85},
	{kind: "supabase_api_key", re: regexp.MustCompile(`(?i)(?:supabase[a-z_ \-]*(?:key|token|anon|service))\s*[:=]\s*["'](ey[A-Za-z0-9_\-.]+)["']`), confidence: 0.8, valueGroup: 1},
	{kind: "sentry_token", re: regexp.MustCompile(`\bsntrys_[A-Za-z0-9_\-]{64}\b`), confidence: 0.9},
	{kind: "planetscale_token", re: regexp.MustCompile(`\bpscale_tkn_[A-Za-z0-9_\-]{43}\b`), confidence: 0.9},
	{kind: "linear_api_key", re: regexp.MustCompile(`\blin_api_[A-Za-z0-9]{40}\b`), confidence: 0.9},
	{kind: "hashicorp_vault_token", re: regexp.MustCompile(`\b(?:hvs|hvb)\.[A-Za-z0-9]{24,}\b|\bs\.[A-Za-z0-9]{24}\b`), confidence: 0.9},
	{kind: "confluent_cloud_secret", re: regexp.MustCompile(`(?i)confluent[a-z_ \-]*(?:secret|key)\s*[:=]\s*["']([A-Za-z0-9/+=]{64})["']`), confidence: 0.85, valueGroup: 1},
	{kind: "snowflake_connection_string", re: regexp.MustCompile(`(?i)\b(?:snowflake|redshift)://[A-Za-z0-9._%+\-]+:[^@\s/"'<>]+@[A-Za-z0-9.\-]+`), confidence: 0.85},
	{kind: "databricks_token", re: regexp.MustCompile(`\bdapi[a-f0-9]{32}\b`), confidence: 0.85},
	{kind: "grafana_api_key", re: regexp.MustCompile(`\beyJrIjoi[A-Za-z0-9_\-]{50,}\b`), confidence: 0.85},
	{kind: "ssh_public_key", re: regexp.MustCompile(`\b(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256)\s+AAAA[0-9A-Za-z+/]+[=]*`), confidence: 0.75},

	// --- Generic auth material ---
	{kind: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), confidence: 0.65},
	{kind: "bearer_token", re: regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}`), confidence: 0.55},
	{kind: "basic_auth_header", re: regexp.MustCompile(`(?i)authorization\s*[:=]\s*["']?basic\s+([A-Za-z0-9+/=]{16,})`), confidence: 0.7, valueGroup: 1},
	{kind: "basic_auth_url", re: regexp.MustCompile(`\bhttps?://[A-Za-z0-9._%+\-]+:[^@\s/"'<>]+@[A-Za-z0-9.\-]+`), confidence: 0.8},

	// --- Database credentials & connection assignments ---
	{kind: "db_connection_string", re: regexp.MustCompile(`(?i)\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[A-Za-z0-9._%+\-]+:[^@\s/"'<>]+@[A-Za-z0-9.\-]+`), confidence: 0.85},
	{kind: "db_password_assignment", re: regexp.MustCompile(`(?i)(?:db[_-]?pass(?:word)?|database[_-]?(?:password|pass|url)|sql[_-]?(?:pass|password)|mongo[_-]?password)\s*[:=]\s*["']?([^"'\s<>&;]{6,})["']?`), confidence: 0.75, valueGroup: 1, generic: true},

	// --- Private keys ---
	{kind: "private_key", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`), confidence: 0.95},

	// --- HTML hidden input / comment secret assignments ---
	{kind: "html_hidden_secret", re: regexp.MustCompile(`(?i)<input[^>]+(?:name|id)=["'](?:api[_-]?key|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)["'][^>]+value=["']([^"']{12,})["']`), confidence: 0.75, valueGroup: 1, generic: true},

	// --- Generic credential assignments (entropy + placeholder gated) ---
	{kind: "api_key", re: regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|secret|access[_-]?token|client[_-]?secret|auth[_-]?token|x[_-]?api[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']`), confidence: 0.7, valueGroup: 1, generic: true},
	{kind: "password_assignment", re: regexp.MustCompile(`(?i)(?:password|passwd|pwd|client_secret|private_key)\s*[:=]\s*["']([^"'\s]{8,})["']`), confidence: 0.6, valueGroup: 1, generic: true},
}

// commonPlaceholders filters out obvious sample/doc values.
var commonPlaceholders = []string{
	"your_api_key", "yourapikey", "your-api-key", "your_token", "your_secret",
	"example", "changeme", "change_me", "placeholder", "xxxxxxxx", "000000",
	"<your", "{{", "}}", "dummy", "test_key", "sample", "replace_me", "redacted",
	"************", "null", "undefined", "todo", "lorem", "foobar", "abcdef123456",
	"process.env", "import.meta", "${",
}

// Detect returns all redacted secret matches found in content.
func Detect(content string) []Match {
	var out []Match
	seen := map[string]struct{}{}
	for _, p := range patterns {
		for _, loc := range p.re.FindAllStringSubmatchIndex(content, -1) {
			vs, ve := loc[0], loc[1]
			if p.valueGroup > 0 && len(loc) >= 2*(p.valueGroup+1) && loc[2*p.valueGroup] >= 0 {
				vs, ve = loc[2*p.valueGroup], loc[2*p.valueGroup+1]
			}
			raw := content[vs:ve]
			if isKnownExampleSecret(p.kind, raw) {
				continue
			}
			if p.kind == "hashicorp_vault_token" {
				if strings.HasPrefix(raw, "s.") {
					tokenBody := raw[2:]
					if strings.Contains(tokenBody, "_") || !hasDigits(tokenBody) || !hasLowerAndUpper(tokenBody) || shannonEntropy(tokenBody) < 3.3 {
						continue
					}
				}
			}
			if p.generic {
				if isPlaceholder(raw) || !looksSecretish(raw) {
					continue
				}
			}
			red := Redact(raw)
			key := p.kind + "|" + red
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, Match{
				Kind: p.kind, Value: raw, Redacted: red, Confidence: p.confidence, Line: lineAt(content, vs),
			})
		}
	}
	return out
}

func isPlaceholder(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if lower == "" {
		return true
	}
	for _, p := range commonPlaceholders {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func isKnownExampleSecret(kind, raw string) bool {
	upper := strings.ToUpper(strings.TrimSpace(raw))
	if upper == "" {
		return false
	}
	if kind == "aws_access_key_id" && strings.Contains(upper, "EXAMPLE") {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "super_secret_password", "your_secret_key", "your-secret-key":
		return true
	}
	return false
}

// looksSecretish requires generic assignment values to have enough randomness
// (or mixed character classes) to plausibly be a real credential.
func looksSecretish(raw string) bool {
	raw = strings.TrimSpace(raw)
	if len(raw) < 8 {
		return false
	}
	if isCodeOrDOMReference(raw) {
		return false
	}
	if shannonEntropy(raw) >= 3.2 {
		return true
	}
	var hasUpper, hasLower, hasDigit bool
	for _, r := range raw {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	return hasUpper && hasLower && hasDigit
}

func isCodeOrDOMReference(raw string) bool {
	lower := strings.ToLower(raw)
	if strings.HasPrefix(raw, "+") || strings.HasSuffix(raw, "+") ||
		strings.HasPrefix(raw, ".") || strings.HasSuffix(raw, ".") ||
		strings.ContainsAny(raw, "+();[]{}\"'$#`\\") {
		return true
	}
	if strings.Contains(lower, "form.") || strings.Contains(lower, ".value") ||
		strings.Contains(lower, "encodeuri") || strings.Contains(lower, "decodeuri") ||
		strings.Contains(lower, "document.") || strings.Contains(lower, "window.") ||
		strings.Contains(lower, "this.") || strings.Contains(lower, "props.") ||
		strings.Contains(lower, "state.") || strings.Contains(lower, "event.") ||
		strings.Contains(lower, "req.") || strings.Contains(lower, "res.") ||
		strings.Contains(lower, "json.") || strings.Contains(lower, "t.") {
		return true
	}
	return false
}

func hasDigits(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func hasLowerAndUpper(s string) bool {
	var hasLower, hasUpper bool
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			hasLower = true
		}
		if r >= 'A' && r <= 'Z' {
			hasUpper = true
		}
	}
	return hasLower && hasUpper
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	var entropy float64
	n := float64(len(s))
	for _, c := range freq {
		p := c / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func lineAt(content string, offset int) int {
	if offset > len(content) {
		offset = len(content)
	}
	return strings.Count(content[:offset], "\n") + 1
}

// Redact masks a secret value, keeping a short prefix/suffix for identification.
func Redact(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) <= 6 {
		return "[REDACTED]"
	}
	keep := len(raw) - 6
	if keep > 12 {
		keep = 12
	}
	return raw[:3] + strings.Repeat("*", keep) + raw[len(raw)-3:]
}

// Severity maps a detector confidence to a finding severity bucket.
func Severity(confidence float64) string {
	switch {
	case confidence >= 0.85:
		return "high"
	case confidence >= 0.65:
		return "medium"
	default:
		return "low"
	}
}

// IsReportable distinguishes high-confidence credential material from public
// identifiers and weak heuristics. Callers may still use Detect for inventory,
// but passive scanners must not create vulnerability findings from values that
// are normally public or too ambiguous to action safely.
func IsReportable(match Match) bool {
	if match.Confidence < 0.70 {
		return false
	}
	switch match.Kind {
	case "firebase_database_url", "google_oauth_client_id", "stripe_test_key",
		"stripe_publishable_key", "openai_org_id", "s3_bucket_url", "azure_blob_url",
		"gcp_storage_url", "ssh_public_key":
		return false
	default:
		return true
	}
}
