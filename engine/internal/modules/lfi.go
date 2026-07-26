package modules

import (
	"context"
	"strings"

	"github.com/akha-security/akca/engine/internal/deeptraversal"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/verification"
)

func deepTraversalPayloads() []payloadgen.Payload {
	out := make([]payloadgen.Payload, 0, len(deeptraversal.Payloads()))
	for i, p := range deeptraversal.Payloads() {
		priority := 82 - i
		if priority < 60 {
			priority = 60
		}
		out = append(out, payloadgen.Payload{
			Value: p.Value, VulnClass: "lfi", Variant: p.Variant, Family: "lfi",
			ExpectedSignal: p.Signal, Priority: priority, BudgetCost: 2,
			VerificationStrategy: "differential_compare", NoiseLevel: "medium",
		})
	}
	return out
}

func (r *Runner) runLFI(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("lfi", target); !ok {
		r.emitSkip("lfi", target, reason)
		return nil
	}
	var out []ModuleFinding
	baseline, err := r.probe(ctx, target, "index.html")
	if err != nil {
		return nil
	}
	oast := ""
	if r.cfg.EnableOAST && r.oast != nil {
		oast = strings.TrimSpace(r.oastURL(ctx, "lfi-"+target.Parameter, target, "lfi"))
	}
	probes := mergeLFIProbes(deepTraversalPayloads(), r.modulePayloads(target, "lfi", oast))
	type directProof struct {
		payload payloadgen.Payload
		rr      httpclient.RequestResponse
	}
	proofs := make(map[string][]directProof)
	for _, p := range probes {
		if p.ExpectedSignal == "rfi_oast" {
			if oast == "" {
				continue
			}
			r.sendOASTProbe(ctx, target, strings.TrimSpace(p.Value))
			continue
		}
		if strings.TrimSpace(p.Value) == "" {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		rr, err := r.probe(ctx, target, p.Value)
		if err != nil {
			continue
		}
		if runtimeFinding, handled := r.runtimeSinkProof(ctx, "lfi", target, p, baseline, rr); handled {
			if runtimeFinding != nil {
				r.recordFinding(&out, runtimeFinding, "lfi", runtimeFinding.Evidence.Signal)
				return out
			}
			continue
		}
		if !deeptraversal.DetectSignal(rr.Response.Body, baseline.Response.Body, p.ExpectedSignal) &&
			!lfiSignal(rr.Response.Body, baseline.Response.Body, p.ExpectedSignal) {
			continue
		}
		family := lfiSignalFamily(p.ExpectedSignal)
		proofs[family] = append(proofs[family], directProof{payload: p, rr: rr})
	}
	for family, familyProofs := range proofs {
		if len(familyProofs) < 2 {
			continue
		}
		first, independent := familyProofs[0], familyProofs[1]
		f := r.verifyAndBuildWithCandidate(ctx, "lfi", target, first.payload, baseline, first.rr,
			first.payload.ExpectedSignal, false, false, "", "", func(candidate *verification.Candidate) {
				candidate.RequestedProofType = verification.ProofDifferentialReplay
				independentObservation := r.observation(
					"lfi", target, verification.RolePositiveReplay, 4, independent.rr,
				)
				if independentObservation.Valid() {
					candidate.Observations = append(candidate.Observations, independentObservation)
				}
			})
		if f != nil {
			f.Description += " Two distinct traversal encodings retrieved the same operating-system file family, followed by replay and a clean negative control."
			f.Evidence.Verification.UpgradeReasons = append(
				f.Evidence.Verification.UpgradeReasons, "independent_traversal_variants",
			)
		}
		r.recordFinding(&out, f, "lfi", family)
	}
	return out
}

func lfiSignalFamily(signal string) string {
	switch {
	case strings.HasPrefix(signal, "linux"):
		return "linux_file"
	case strings.HasPrefix(signal, "windows"):
		return "windows_file"
	default:
		return "traversal_file"
	}
}

func mergeLFIProbes(parts ...[]payloadgen.Payload) []payloadgen.Payload {
	seen := map[string]struct{}{}
	var out []payloadgen.Payload
	for _, list := range parts {
		for _, p := range list {
			if p.Value == "" {
				continue
			}
			if _, ok := seen[p.Value]; ok {
				continue
			}
			seen[p.Value] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func lfiSignal(body, baseline, signal string) bool {
	if signal == "rfi_oast" {
		return false
	}
	return deeptraversal.DetectSignal(body, baseline, signal)
}
