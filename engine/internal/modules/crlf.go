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
	baseline, ok, baselineReason := r.stableNativeBaselineForModule(ctx, "crlf", target)
	if !ok {
		r.emitSkip("crlf", target, baselineReason)
		return nil
	}
	tokenSeed := strings.NewReplacer(":", "-", "/", "-", "?", "-", "&", "-").Replace(target.Parameter)
	if tokenSeed == "" {
		tokenSeed = "param"
	}
	token := "akca-crlf-" + tokenSeed
	probes := []payloadgen.Payload{
		defaultPayload("crlf", "raw_header_split", "\r\nX-Akca-CRLF: "+token, "crlf_header_injection"),
		defaultPayload("crlf", "raw_set_cookie_split", "\r\nSet-Cookie: akca_crlf="+token+"; Path=/", "crlf_header_injection"),
		defaultPayload("crlf", "response_splitting_body", "\r\n\r\nAKCA_CRLF_BODY_"+token, "crlf_body_injection"),
		defaultPayload("crlf", "double_decoded_header_split", "%0d%0aX-Akca-CRLF:%20"+token, "crlf_header_injection"),
	}
	var out []ModuleFinding
	for _, p := range probes {
		if ctx.Err() != nil {
			break
		}
		rr, err := r.probeForModule(ctx, "crlf", target, p.Value)
		if err != nil {
			continue
		}
		confirmed := crlfHeaderConfirmed(baseline.Response.Headers, rr.Response.Headers, p.Value)
		if !confirmed && p.ExpectedSignal == "crlf_body_injection" {
			confirmed = crlfBodyConfirmed(baseline.Response.Body, rr.Response.Body, p.Value)
		}
		if !confirmed {
			continue
		}
		f := r.verifyAndBuild(ctx, "crlf", target, p, baseline, rr, p.ExpectedSignal, false, false, "", "")
		if f != nil {
			f.Title = "CRLF Injection / HTTP Response Splitting"
			f.Description += fmt.Sprintf(" Confirmed injected response header or body token %q.", crlfToken(p.Value))
		}
		r.recordFinding(ctx, &out, f, "crlf", p.ExpectedSignal)
	}
	return out
}

func crlfHeaderConfirmed(baseHeaders, probeHeaders map[string]string, payload string) bool {
	token := strings.ToLower(crlfToken(payload))
	if token == "" {
		return false
	}
	base := strings.ToLower(headerValue(baseHeaders, "X-Akca-CRLF") + " " + headerValue(baseHeaders, "Set-Cookie"))
	probe := strings.ToLower(headerValue(probeHeaders, "X-Akca-CRLF") + " " + headerValue(probeHeaders, "Set-Cookie"))
	return (strings.Contains(probe, token) || strings.Contains(probe, "akca_crlf="+token)) && !strings.Contains(base, token)
}

func crlfBodyConfirmed(baseBody, probeBody, payload string) bool {
	token := strings.ToLower(crlfToken(payload))
	if token == "" {
		return false
	}
	marker := "akca_crlf_body_" + token
	probeLower := strings.ToLower(probeBody)
	baseLower := strings.ToLower(baseBody)
	if !strings.Contains(probeLower, marker) || strings.Contains(baseLower, marker) {
		return false
	}

	// 1. If the marker is URL-encoded or appears in a URL query echo, it means
	// the web application/server treated it as regular parameter text rather than HTTP control characters.
	if strings.Contains(probeLower, "%0d%0a"+marker) ||
		strings.Contains(probeLower, "%0a"+marker) ||
		strings.Contains(probeLower, "%0d"+marker) ||
		strings.Contains(probeLower, "fullpath") ||
		strings.Contains(probeLower, `\u002f`) ||
		strings.Contains(probeLower, `\u002F`) {
		return false
	}

	// 2. Reject if the marker appears inside a URL query string, path echo, or router state
	for _, echoMarker := range []string{
		"fullpath", "params\":", "query\":", `\u002f`, `\u002F`,
	} {
		if strings.Contains(probeLower, echoMarker) {
			return false
		}
	}

	// 3. In HTTP response splitting / body injection, the injected \r\n\r\n must break out
	// into the HTTP body with raw unescaped newlines (\r\n\r\n or \n\n), or the body must start
	// directly with the injected body token.
	hasRawCRLFBreakout := strings.Contains(probeLower, "\r\n\r\n"+marker) ||
		strings.Contains(probeLower, "\n\n"+marker) ||
		strings.Contains(probeLower, "\r\r"+marker) ||
		strings.HasPrefix(strings.TrimSpace(probeLower), marker)

	if !hasRawCRLFBreakout {
		return false
	}

	// 4. Reject if the body is a JSON document where the marker is simply embedded in a JSON string
	trimmed := strings.TrimSpace(probeBody)
	if (strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) ||
		(strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")) {
		return false
	}

	return true
}

func crlfSignalConfirmed(baseHeaders, probeHeaders map[string]string, baseBody, probeBody, payload, signal string) bool {
	if crlfHeaderConfirmed(baseHeaders, probeHeaders, payload) {
		return true
	}
	if signal == "crlf_body_injection" {
		return crlfBodyConfirmed(baseBody, probeBody, payload)
	}
	return false
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
