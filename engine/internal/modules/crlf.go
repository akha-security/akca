package modules

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/payloadgen"
)

func (r *Runner) runCRLF(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("crlf", target); !ok {
		r.emitSkip("crlf", target, reason)
		return nil
	}
	if ok, reason := hasParameter(target); !ok {
		r.emitSkip("crlf", target, reason)
		return nil
	}
	baseline, ok := r.stableNativeBaseline(ctx, target)
	if !ok {
		return nil
	}
	tokenSeed := strings.NewReplacer(":", "-", "/", "-", "?", "-", "&", "-").Replace(target.Parameter)
	if tokenSeed == "" {
		tokenSeed = "param"
	}
	token := "akca-crlf-" + tokenSeed
	probes := []payloadgen.Payload{
		defaultPayload("crlf", "raw_header_split", "\r\nX-Akca-CRLF: "+token, "crlf_header_injection"),
		defaultPayload("crlf", "encoded_header_split", "%0d%0aX-Akca-CRLF:%20"+token, "crlf_header_injection"),
	}
	var out []ModuleFinding
	for _, p := range probes {
		if ctx.Err() != nil {
			break
		}
		rr, err := r.probe(ctx, target, p.Value)
		if err != nil {
			continue
		}
		if !crlfHeaderConfirmed(baseline.Response.Headers, rr.Response.Headers, p.Value) {
			continue
		}
		f := r.verifyAndBuild(ctx, "crlf", target, p, baseline, rr, p.ExpectedSignal, false, false, "", "")
		if f != nil {
			f.Title = "CRLF Injection"
			f.Description += fmt.Sprintf(" Confirmed injected response header X-Akca-CRLF with token %q.", crlfToken(p.Value))
		}
		r.recordFinding(&out, f, "crlf", p.ExpectedSignal)
	}
	return out
}

func crlfHeaderConfirmed(baseHeaders, probeHeaders map[string]string, payload string) bool {
	token := strings.ToLower(crlfToken(payload))
	if token == "" {
		return false
	}
	base := strings.ToLower(headerValue(baseHeaders, "X-Akca-CRLF"))
	probe := strings.ToLower(headerValue(probeHeaders, "X-Akca-CRLF"))
	return probe != "" && strings.Contains(probe, token) && !strings.Contains(base, token)
}

func crlfToken(payload string) string {
	if decoded, err := url.QueryUnescape(payload); err == nil && decoded != payload {
		if token := crlfToken(decoded); token != "" {
			return token
		}
	}
	lower := strings.ToLower(payload)
	idx := strings.Index(lower, "akca-crlf-")
	if idx < 0 {
		return ""
	}
	token := payload[idx:]
	token = strings.TrimSpace(token)
	token = strings.Trim(token, "\r\n\t ;")
	return token
}
