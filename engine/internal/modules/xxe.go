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
	baseline, err := r.probeWithBody(ctx, target, `<root>baseline</root>`, "application/xml", nil)
	if err != nil {
		return nil
	}
	oast := ""
	if r.cfg.EnableOAST && r.oast != nil {
		oast = strings.TrimSpace(r.oastURL(ctx, "xxe-"+target.Parameter, target, "xxe"))
	}
	for _, p := range r.modulePayloads(target, "xxe", oast) {
		if p.ExpectedSignal == "blind_oast" {
			if oast == "" {
				continue
			}
			_, _ = r.probeWithBody(ctx, target, p.Value, "application/xml", nil)
			continue
		}
		ct := "application/xml"
		if p.ExpectedSignal == "soap_xxe" {
			ct = "text/xml"
		}
		rr, err := r.probeWithBody(ctx, target, p.Value, ct, nil)
		if err != nil {
			continue
		}
		if runtimeFinding, handled := r.runtimeSinkProof(ctx, "xxe", target, p, baseline, rr); handled {
			if runtimeFinding != nil {
				r.recordFinding(&out, runtimeFinding, "xxe", runtimeFinding.Evidence.Signal)
				return out
			}
			continue
		}
		if p.ExpectedSignal == "classic_entity" && !xxeSignalConfirmed(rr.Response.Body, baseline.Response.Body, p.ExpectedSignal) {
			continue
		}
		if p.ExpectedSignal == "soap_xxe" && !xxeSignalConfirmed(rr.Response.Body, baseline.Response.Body, p.ExpectedSignal) {
			continue
		}
		signal := strings.TrimSpace(p.ExpectedSignal)
		if signal == "" {
			switch {
			case xxeSignalConfirmed(rr.Response.Body, baseline.Response.Body, "classic_entity"):
				signal = "classic_entity"
			case xxeSignalConfirmed(rr.Response.Body, baseline.Response.Body, "soap_xxe"):
				signal = "soap_xxe"
			default:
				continue
			}
		}
		f := r.verifyAndBuild(ctx, "xxe", target, p, baseline, rr, signal, false, false, "", "")
		r.recordFinding(&out, f, "xxe", p.ExpectedSignal)
	}
	return out
}
