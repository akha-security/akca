package modules

import (
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
)

func TestBodyDiffRatioAlignsSingleInsertion(t *testing.T) {
	base := strings.Repeat("stable response body ", 100)
	probe := "X" + base
	if ratio := bodyDiffRatio(base, probe); ratio >= 0.01 {
		t.Fatalf("single insertion must remain a small aligned diff, got %.4f", ratio)
	}
}

func TestBodyDiffRatioDetectsDifferentBodies(t *testing.T) {
	if ratio := bodyDiffRatio(strings.Repeat("a", 100), strings.Repeat("b", 100)); ratio < 0.99 {
		t.Fatalf("unrelated bodies must have a high diff ratio, got %.4f", ratio)
	}
}

func TestSSRFSignalRequiresBaselineDelta(t *testing.T) {
	p := payloadgen.Payload{Value: "http://169.254.169.254/latest/meta-data/", ExpectedSignal: "aws_metadata"}
	body := "ami-id and instance-id"
	base := "ami-id and instance-id"
	if ssrfSignalConfirmed(p, httpclient.ResponseRecord{Body: base}, httpclient.ResponseRecord{Body: body}, "aws_metadata") {
		t.Fatal("expected SSRF marker already in baseline to be rejected")
	}
	if !ssrfSignalConfirmed(p, httpclient.ResponseRecord{Body: "ok"},
		httpclient.ResponseRecord{Body: body}, "aws_metadata") {
		t.Fatal("expected two new AWS metadata markers to be accepted")
	}
}

func TestSSRFRejectsBlockedPayloadEcho(t *testing.T) {
	p := payloadgen.Payload{Value: "http://169.254.169.254/latest/meta-data/", ExpectedSignal: "aws_metadata"}
	for _, body := range []string{
		"Input URL http://169.254.169.254/latest/meta-data/ is blocked by policy; ami-id instance-id",
		"Input URL http://169.254.169.254/latest/meta-data/ is blocked; ami-id instance-id",
	} {
		if ssrfSignalConfirmed(p, httpclient.ResponseRecord{Body: "ok"},
			httpclient.ResponseRecord{Body: body}, "aws_metadata") {
			t.Fatalf("payload reflection must not prove SSRF: %q", body)
		}
	}
}

func TestSSRFSignalsAreProviderSpecific(t *testing.T) {
	internal := payloadgen.Payload{Value: "http://127.0.0.1/", ExpectedSignal: "internal_ip"}
	if ssrfSignalConfirmed(internal, httpclient.ResponseRecord{Body: "ok"},
		httpclient.ResponseRecord{Body: "unrelated instance-id ami-id"}, "internal_ip") {
		t.Fatal("internal_ip payload cannot borrow unrelated AWS markers")
	}
	gcp := payloadgen.Payload{Value: "http://metadata.google.internal/", ExpectedSignal: "gcp_metadata"}
	body := "project/project-id"
	if ssrfSignalConfirmed(gcp, httpclient.ResponseRecord{Body: "ok"},
		httpclient.ResponseRecord{Body: body}, "gcp_metadata") {
		t.Fatal("GCP metadata proof requires Metadata-Flavor response header")
	}
	if !ssrfSignalConfirmed(gcp, httpclient.ResponseRecord{Body: "ok"},
		httpclient.ResponseRecord{Body: body, Headers: map[string]string{"Metadata-Flavor": "Google"}}, "gcp_metadata") {
		t.Fatal("expected provider-specific GCP proof")
	}
}

func TestSSTIGenericSignalsAreNotExecutionProof(t *testing.T) {
	p := payloadgen.Payload{Value: "{{bad", ExpectedSignal: "error_trace"}
	if sstiSignalConfirmed(p, "jinja2.exceptions.TemplateSyntaxError", "ok", "error_trace") {
		t.Fatal("template editor syntax errors must not prove SSTI exploitation")
	}
	if sstiSignalConfirmed(p, "search result root: /bin/bash uid=1000", "ok", "command_output") {
		t.Fatal("generic OS text must not prove SSTI command execution")
	}
	multiply := payloadgen.Payload{Value: "{{7*'7'}}", ExpectedSignal: "string_multiply_eval"}
	if sstiSignalConfirmed(multiply, "7777777", "ok", "string_multiply_eval") ||
		sstiSignalConfirmed(multiply, "777777777777777", "ok", "string_multiply_eval") {
		t.Fatal("fixed digit counts must not prove string-multiply SSTI")
	}
}

func TestCORSRequiresHeaderChange(t *testing.T) {
	base := map[string]string{"Access-Control-Allow-Origin": "https://evil.example"}
	probe := map[string]string{"Access-Control-Allow-Origin": "https://evil.example"}
	if corsSignalConfirmed(base, probe, "origin_reflection", "https://evil.example") {
		t.Fatal("unchanged ACAO should not confirm CORS")
	}
}

func TestCORSReflectionDoesNotRequireCredentials(t *testing.T) {
	origin := "https://evil.example"
	probe := map[string]string{"Access-Control-Allow-Origin": origin}
	if !corsSignalConfirmed(nil, probe, "origin_reflection", origin) {
		t.Fatal("arbitrary origin reflection should be confirmed without credentials")
	}
}

func TestCORSDomainBypassSignalsUseExactReflectedOrigin(t *testing.T) {
	origin := "https://example.com.evil.example"
	probe := map[string]string{"Access-Control-Allow-Origin": origin}
	if !corsSignalConfirmed(nil, probe, "partial_origin_match", origin) {
		t.Fatal("target-shaped reflected origin should confirm whitelist bypass")
	}
	probe["Access-Control-Allow-Origin"] = "https://unrelated.example"
	if corsSignalConfirmed(nil, probe, "partial_origin_match", origin) {
		t.Fatal("unrelated ACAO must not confirm whitelist bypass")
	}
}

func TestModuleSignalConfirmedSQLi(t *testing.T) {
	p := defaultPayload("sqli", "x", `'`, "error_based")
	base := httpclient.ResponseRecord{Body: "ok", StatusCode: 200}
	probe := httpclient.ResponseRecord{Body: "mysql syntax error near foo", StatusCode: 200}
	if !moduleSignalConfirmed("sqli", p, "error_based", base, probe, false, "") {
		t.Fatal("expected SQLi error confirmation")
	}
}

func TestBooleanSQLiRejects405(t *testing.T) {
	p := defaultPayload("sqli", "boolean_true", `' OR '1'='1`, "boolean_differential")
	base := httpclient.ResponseRecord{Body: "form page", StatusCode: 200}
	probe := httpclient.ResponseRecord{Body: "Method Not Allowed", StatusCode: 405}
	if moduleSignalConfirmed("sqli", p, "boolean_differential", base, probe, false, "") {
		t.Fatal("405 differential should not confirm boolean SQLi")
	}
}

func TestXSSRejectsSQLiErrorReflection(t *testing.T) {
	p := defaultPayload("xss", "html_svg_onload", `"><svg/onload=alert(1)>`, "reflected_partial")
	base := httpclient.ResponseRecord{Body: "search results", StatusCode: 200}
	probe := httpclient.ResponseRecord{
		Body:       `you have an error in your sql syntax near '"><svg/onload=alert(1)>'`,
		StatusCode: 500,
	}
	if moduleSignalConfirmed("xss", p, "reflected_partial", base, probe, false, "") {
		t.Fatal("SQL error page payload echo should not confirm XSS")
	}
}

func TestContentModulesRequireClassSpecificFingerprints(t *testing.T) {
	base := httpclient.ResponseRecord{Body: "not found", StatusCode: 404}
	generic := httpclient.ResponseRecord{Body: "generic body", StatusCode: 200}
	for _, test := range []struct {
		module string
		signal string
	}{
		{"framework_debug", "werkzeug_debugger"},
		{"actuator", "actuator_env"},
		{"spring_cloud_jolokia", "spring_jolokia_agent"},
		{"saas_exposure", "servicenow_table_exposure"},
		{"pdf_injection", "pdf_metadata_ssrf"},
		{"swagger_exposure", "openapi_v3_json"},
		{"cloud_native_exposure", "docker_version_exposed"},
		{"grpc_scan", "grpc_reflection_exposed"},
		{"backup_archives", "compressed_backup_disclosure_zip"},
		{"cloud_takeover", "subdomain_takeover_aws_s3_bucket"},
		{"devops_exposure", "devops_exposure_terraform.tfstate"},
		{"http_smuggling", "http_desync_cl_te"},
		{"file_upload", "retrieved_hash_confirmed"},
		{"nextjs_bypass", "middleware_bypass"},
		{"iis_discovery", "iis_source_disclosure"},
		{"graphql", "type_inversion_error_disclosure"},
	} {
		if moduleSignalConfirmed(test.module, defaultPayload(test.module, test.signal, "x", test.signal),
			test.signal, base, generic, false, "") {
			t.Fatalf("%s generic 200 body must not confirm %s", test.module, test.signal)
		}
	}
}

func TestCentralContentHelpersPreserveSpecificProof(t *testing.T) {
	base := httpclient.ResponseRecord{Body: "not found", StatusCode: 404}

	if !moduleSignalConfirmed("backup_archives",
		defaultPayload("backup_archives", "zip", "/backup.zip", "compressed_backup_disclosure_zip"),
		"compressed_backup_disclosure_zip",
		base,
		httpclient.ResponseRecord{Body: "PK\x03\x04archive", StatusCode: 200},
		false,
		"",
	) {
		t.Fatal("archive magic bytes must still confirm backup archive exposure")
	}

	if !moduleSignalConfirmed("devops_exposure",
		defaultPayload("devops_exposure", "tfstate", "/terraform.tfstate", "devops_exposure_terraform.tfstate"),
		"devops_exposure_terraform.tfstate",
		base,
		httpclient.ResponseRecord{Body: `{"version":4,"resources":[],"provider":"registry.terraform.io/hashicorp/aws"}`, StatusCode: 200},
		false,
		"",
	) {
		t.Fatal("strict Terraform state fingerprint must still confirm devops exposure")
	}

	if !moduleSignalConfirmed("http_smuggling",
		defaultPayload("http_smuggling", "cl_te", "akca-smuggle-canary", "http_desync_cl_te"),
		"http_desync_cl_te",
		base,
		httpclient.ResponseRecord{Body: "HTTP/1.1 404 Not Found\r\n\r\n/akca-smuggle-canary", StatusCode: 404},
		false,
		"",
	) {
		t.Fatal("smuggling canary must still confirm HTTP desync")
	}

	if !moduleSignalConfirmed("file_upload",
		defaultPayload("file_upload", "marker", "AKCA_UPLOAD_canary", "retrieved_hash_confirmed"),
		"retrieved_hash_confirmed",
		base,
		httpclient.ResponseRecord{Body: "prefix AKCA_UPLOAD_canary", StatusCode: 200},
		false,
		"",
	) {
		t.Fatal("retrieved upload marker must still confirm file upload proof")
	}

	if !moduleSignalConfirmed("nextjs_bypass",
		defaultPayload("nextjs_bypass", "middleware", "x-middleware-subrequest", "middleware_bypass"),
		"middleware_bypass",
		httpclient.ResponseRecord{Body: "forbidden", StatusCode: 403},
		httpclient.ResponseRecord{Body: strings.Repeat("protected dashboard ", 3), StatusCode: 200},
		false,
		"",
	) {
		t.Fatal("protected-route middleware bypass must still confirm Next.js bypass")
	}
}

func TestSSRFRejects404AndClientErrors(t *testing.T) {
	p := payloadgen.Payload{Value: "http://127.0.0.1/", ExpectedSignal: "internal_ip"}
	base := httpclient.ResponseRecord{Body: "<html><body>Welcome to content page</body></html>", StatusCode: 200}
	
	// Server responds 404 Not Found to /content/http://127.0.0.1/
	probe404 := httpclient.ResponseRecord{
		Body:       "<html><body>404 Not Found: /content/http://127.0.0.1/ does not exist</body></html>",
		StatusCode: 404,
	}
	if ssrfSignalConfirmed(p, base, probe404, "internal_ip") {
		t.Fatal("404 Not Found must never be confirmed as SSRF")
	}

	// Server responds 400 Bad Request
	probe400 := httpclient.ResponseRecord{
		Body:       "Bad Request: Invalid URL format http://127.0.0.1/",
		StatusCode: 400,
	}
	if ssrfSignalConfirmed(p, base, probe400, "internal_ip") {
		t.Fatal("400 Bad Request must never be confirmed as SSRF")
	}
}

func TestCRLFRejectsJSONStateReflection(t *testing.T) {
	payload := "\r\n\r\nAKCA_CRLF_BODY_akca-crlf-__state__"
	base := `{"state":"clean","params":{},"fullPath":"/bignews"}`
	probeJSON := `{"state":"AKCA_CRLF_BODY_akca-crlf-__state__"},"params":{},"fullPath":"\u002Fbignews?__state__=%0D%0A%0D%0AAKCA_CRLF_BODY_akca-crlf-__state__"}`

	if crlfBodyConfirmed(base, probeJSON, payload) {
		t.Fatal("query parameter reflected into JSON state and URL-encoded fullPath must NOT confirm CRLF body injection")
	}

	// Real CRLF response splitting: body starts with raw injected body marker
	probeRealSplit := "AKCA_CRLF_BODY_akca-crlf-__state__\r\n<html>injected body</html>"
	if !crlfBodyConfirmed(base, probeRealSplit, payload) {
		t.Fatal("genuine HTTP response splitting with raw body breakout must be confirmed")
	}
}

