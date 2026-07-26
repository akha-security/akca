package modules

import (
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/timingblind"
)

func TestSQLiSignalConfirmedRejectsReflection(t *testing.T) {
	p := payloadgen.Payload{Value: `' OR '1'='1`, VulnClass: "sqli"}
	body := "result ' OR '1'='1 ok"
	if sqliSignalConfirmed(p, body, "result ok", "boolean_differential") {
		t.Fatal("expected reflection-only boolean diff to be rejected")
	}
}

func TestXSSSignalConfirmedRejectsEncodedReflection(t *testing.T) {
	p := payloadgen.Payload{Value: `<img src=x onerror=alert(1)>`}
	body := `&lt;img src=x onerror=alert(1)&gt;`
	if xssSignalConfirmed(p, body, "", "reflected_encoded") {
		t.Fatal("encoded reflection should not confirm XSS")
	}
}

func TestXSSSignalConfirmedRejectsPayloadInsideTextarea(t *testing.T) {
	p := payloadgen.Payload{Value: `<img src=x onerror=alert(1)>`}
	body := `<html><textarea><img src=x onerror=alert(1)></textarea></html>`
	if xssSignalConfirmed(p, body, "", "reflected") {
		t.Fatal("payload inside textarea is text, not executable DOM")
	}
}

func TestXSSSignalConfirmedAcceptsExecutableEventHandler(t *testing.T) {
	p := payloadgen.Payload{Value: `<img src=x onerror=alert(1)>`}
	body := `<html><body><img src=x onerror=alert(1)></body></html>`
	if !xssSignalConfirmed(p, body, "", "reflected") {
		t.Fatal("expected parsed event handler to confirm XSS")
	}
}

func TestCmdInjRequiresMultipleMarkers(t *testing.T) {
	p := payloadgen.Payload{Value: `|id`}
	if cmdInjSignalConfirmed(p, "uid=1000 only", "", "separator_output") {
		t.Fatal("single uid marker should not confirm command injection")
	}
	if !cmdInjSignalConfirmed(p, "uid=1000 gid=1000 groups=1000", "", "separator_output") {
		t.Fatal("uid+gid should confirm command injection")
	}
}

func TestCmdInjCanaryRequiresExecutedOutput(t *testing.T) {
	seed, _ := commandCanarySeeds("scan-test", ScanTarget{EndpointURL: "http://example.com/run", Parameter: "cmd", Location: "query"})
	p := commandCanaryProbe(payloadgen.Payload{}, false, seed, "test")
	expected := commandExpectedMarker(p)
	if expected == "" || strings.Contains(p.Value, expected) {
		t.Fatalf("computed marker must be derivable but absent from request: payload=%q expected=%q", p.Value, expected)
	}
	if cmdInjSignalConfirmed(p, `echo `+p.Value, "", "canary_output") {
		t.Fatal("full payload reflection must not confirm command execution")
	}
	if !cmdInjSignalConfirmed(p, `result: `+expected, "", "canary_output") {
		t.Fatal("expected isolated command canary output to confirm execution")
	}
}

func TestCmdInjRejectsLargeDynamicHTMLAndReflectedLegacyMarker(t *testing.T) {
	p := payloadgen.Payload{Value: `;printf AKCA_CMD_8427`, ExpectedSignal: "canary_output"}
	body := `<!DOCTYPE html><html lang="tr-TR" dir="ltr"><head><meta charset="utf-8">` +
		`<div data-fluid="uid=674b8d5747-78dds"></div><script>const tracking="gid=61";</script>` +
		`<link rel="canonical" href="?merchantId=%3Bprintf+AKCA_CMD_8427&boutiqueId=61">` +
		`<img src="https://cdn.dsmcdn.com/sfweb-browsing/images/footer-etbis.png"></html>`
	if signal := detectCommandSignal(p, body, "ordinary baseline", 30, timingblind.Baseline{}, 5); signal != "" {
		t.Fatalf("dynamic commerce HTML and reflected legacy marker must not produce command signal, got %q", signal)
	}
	if cmdInjSignalConfirmed(p, body, "ordinary baseline", "canary_output") {
		t.Fatal("legacy marker present in both request and page URL is reflection, not execution")
	}
}

func TestCommandOASTPayloadContainsCallbackHost(t *testing.T) {
	unix := commandOASTPayload("http://abc123.oast.test/", false)
	windows := commandOASTPayload("http://abc123.oast.test/", true)
	if unix != ";nslookup abc123.oast.test" || windows != "&nslookup abc123.oast.test" {
		t.Fatalf("unexpected command OAST payloads: %q %q", unix, windows)
	}
}
