package modules

import (
	"context"
	"strings"
)

func (r *Runner) runXXE(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("xxe", target); !ok {
		r.emitSkip("xxe", target, reason)
		return nil
	}
	var out []ModuleFinding
	oast := ""
	if r.cfg.EnableOAST && r.oast != nil {
		oast = strings.TrimSpace(r.oastURL(ctx, "xxe-"+target.Parameter, target, "xxe"))
	}
	payloads := r.modulePayloads(target, "xxe", oast)
	if len(payloads) == 0 {
		return nil
	}
	for _, carrier := range xxeCarriers(target) {
		baselineBody, baselineType, err := buildXXECarrierRequest(carrier, target, payloads[0], true, oast)
		if err != nil || len(baselineBody) == 0 {
			continue
		}
		baseline, err := r.probeWithRawBodyForModule(ctx, "xxe", target, baselineBody, baselineType, nil)
		if err != nil {
			continue
		}
		for _, original := range payloads {
			p := original
			body, contentType, err := buildXXECarrierRequest(carrier, target, p, false, oast)
			if err != nil || len(body) == 0 {
				continue
			}
			if carrier.name != "xml" {
				p.Variant += "_" + carrier.name
				p.Encoding = carrier.encoding()
			}
			rr, err := r.probeWithRawBodyForModule(ctx, "xxe", target, body, contentType, nil)
			if err != nil {
				continue
			}
			if p.ExpectedSignal == "blind_oast" {
				if oast != "" {
					r.recordOASTProbeDelivery(target, original.Value, rr)
				}
				continue
			}
			if runtimeFinding, handled := r.runtimeSinkProof(ctx, "xxe", target, p, baseline, rr); handled {
				if runtimeFinding != nil {
					r.recordFinding(ctx, &out, runtimeFinding, "xxe", runtimeFinding.Evidence.Signal)
					return out
				}
				continue
			}
			if !xxeSignalConfirmed(rr.Response.Body, baseline.Response.Body, p.ExpectedSignal) {
				continue
			}
			f := r.verifyAndBuild(ctx, "xxe", target, p, baseline, rr, p.ExpectedSignal, false, false, "", "")
			if f != nil && (p.ExpectedSignal == "classic_entity" || p.ExpectedSignal == "soap_xxe") {
				f.Title = "XML Internal Entity Expansion Enabled"
				f.Severity = "medium"
				f.Description = "The XML parser expanded a controlled internal entity. This proves entity expansion, but does not by itself prove local-file disclosure or external network access; those impacts require file-specific, runtime, or correlated OAST evidence."
			}
			r.recordFinding(ctx, &out, f, "xxe", p.ExpectedSignal)
		}
	}
	return out
}
