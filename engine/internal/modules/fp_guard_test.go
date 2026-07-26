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
