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
	if strings.TrimSpace(target.Parameter) == "" {
		return nil
	}
	if !isLikelyLFIParam(target.Parameter) {
		r.emitSkip("lfi", target, "parameter is not a file/path candidate")
		return nil
	}
	if ok, reason := r.shouldRunModule("lfi", target); !ok {
		r.emitSkip("lfi", target, reason)
		return nil
	}
	var out []ModuleFinding
	var err error
	baseline, ok, baselineReason := r.stableNativeBaselineForModule(ctx, "lfi", target)
	if !ok {
		baseline, err = r.cachedEmptyProbe(ctx, target)
		if err != nil {
			r.emitSkip("lfi", target, "baseline failed: "+baselineReason)
			return nil
		}
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
	coreTested := 0
	coreHadSignal := false
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
		// Fast-fail: if the first 6 core payloads fail to produce any signal or change, terminate.
		if coreTested >= 6 && !coreHadSignal && len(proofs) == 0 {
			break
		}
		coreTested++
		rr, err := r.probeForModule(ctx, "lfi", target, p.Value)
		if err != nil {
			continue
		}
		if runtimeFinding, handled := r.runtimeSinkProof(ctx, "lfi", target, p, baseline, rr); handled {
			if runtimeFinding != nil {
				r.recordFinding(ctx, &out, runtimeFinding, "lfi", runtimeFinding.Evidence.Signal)
				return out
			}
			continue
		}
		if !deeptraversal.DetectSignal(rr.Response.Body, baseline.Response.Body, p.ExpectedSignal) &&
			!lfiSignal(rr.Response.Body, baseline.Response.Body, p.ExpectedSignal) {
			continue
		}
		coreHadSignal = true
		family := lfiSignalFamily(p.ExpectedSignal)
		proofs[family] = append(proofs[family], directProof{payload: p, rr: rr})
	}
	for family, familyProofs := range proofs {
		if len(familyProofs) >= 2 {
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
			r.recordFinding(ctx, &out, f, "lfi", family)
		} else if len(familyProofs) == 1 {
			first := familyProofs[0]
			reprobe, repErr := r.probeForModule(ctx, "lfi", target, first.payload.Value)
			if repErr == nil && (deeptraversal.DetectSignal(reprobe.Response.Body, baseline.Response.Body, first.payload.ExpectedSignal) || lfiSignal(reprobe.Response.Body, baseline.Response.Body, first.payload.ExpectedSignal)) {
				f := r.verifyAndBuild(ctx, "lfi", target, first.payload, baseline, reprobe, first.payload.ExpectedSignal, false, false, "", "")
				if f != nil {
					f.Title = "Local File Inclusion (" + family + ")"
					r.recordFinding(ctx, &out, f, "lfi", first.payload.ExpectedSignal)
				}
			}
		}
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

func isLikelyLFIParam(param string) bool {
	p := strings.ToLower(strings.TrimSpace(param))
	if p == "" {
		return false
	}
	switch p {
	case "_", "t", "ts", "timestamp", "cb", "cache", "nocache", "v", "ver", "version",
		"format", "lang", "locale", "theme", "sort", "order", "dir", "asc", "desc",
		"limit", "offset", "page_size", "per_page", "count", "qty", "quantity",
		"price", "amount", "total", "id", "user_id", "product_id", "item_id", "category_id",
		"account_id", "org_id", "role_id", "status", "state", "is_active", "enabled",
		"disabled", "color", "size", "width", "height", "lat", "lon", "lng", "zoom",
		"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "ref", "fbclid", "gclid":
		return false
	}
	for _, kw := range []string{
		"file", "path", "page", "doc", "document", "folder", "root", "template", "view",
		"layout", "include", "inc", "load", "read", "url", "uri", "module", "content",
		"dir", "filename", "image", "img", "pdf", "download", "cat", "source", "src",
		"conf", "config", "action", "item", "name", "report", "target", "dest",
		"resource", "data", "logfile", "log", "feed", "style", "sheet", "nav",
	} {
		if strings.Contains(p, kw) {
			return true
		}
	}
	return false
}
