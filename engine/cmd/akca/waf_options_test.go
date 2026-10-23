package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/events"
)

func TestWAFPayloadCLIChoices(t *testing.T) {
	for _, tc := range []struct {
		name                                       string
		enabled, disabled, enabledSet, disabledSet bool
		want                                       config.WAFPayloadMode
	}{
		{"default", false, false, false, false, config.WAFPayloadAuto},
		{"on", true, false, true, false, config.WAFPayloadOn},
		{"explicit false", false, false, true, false, config.WAFPayloadOff},
		{"off", false, true, false, true, config.WAFPayloadOff},
		{"disable false", false, false, false, true, config.WAFPayloadAuto},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := wafPayloadModeForFlags(tc.enabled, tc.disabled, tc.enabledSet, tc.disabledSet); got != tc.want {
				t.Fatalf("mode=%s want=%s", got, tc.want)
			}
		})
	}
}

func TestWAFStatusShowsAutomaticDecision(t *testing.T) {
	var output bytes.Buffer
	cw := NewConsoleWriter()
	cw.out = &output
	cw.interactive = false
	if err := cw.WriteEvent(events.Event{Type: "waf_detected", Message: "Cloudflare", Payload: map[string]interface{}{"waf_payload_mode": "auto", "payload_adaptation_active": true}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Cloudflare | Payload adaptation: AUTO (profile)") {
		t.Fatal(output.String())
	}
	for _, mode := range []string{"auto", "on", "off"} {
		payload := map[string]interface{}{"waf_payload_mode": mode}
		if !strings.Contains(scanSessionLine(payload), "waf_payload_mode="+mode) {
			t.Fatal("plain status omitted WAF mode")
		}
		if !strings.Contains(scanSessionPanel(payload), strings.ToUpper(mode)) {
			t.Fatal("session card omitted WAF mode")
		}
	}
}
