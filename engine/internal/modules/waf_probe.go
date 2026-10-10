package modules

import (
	"encoding/json"
	"strings"

	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/wafintel"
)

func (r *Runner) wafHeadersForModule(module, endpointURL string) map[string]string {
	if !moduleAllowsHeaderPayloads(module) {
		return nil
	}
	if r.db == nil || !r.cfg.EnableWAFBypassHeaders {
		return nil
	}
	host := wafintel.HostFromTarget(endpointURL)
	if host == "" {
		return nil
	}
	waf, err := r.db.GetWAFProfile(r.scanID, host)
	if err != nil || waf.Vendor == "" {
		return nil
	}
	raw, err := r.db.LoadWAFLearningProfile(host)
	learn := wafintel.NewLearningProfile(host)
	if err == nil {
		_ = json.Unmarshal([]byte(raw), &learn)
	}
	strategy := wafintel.SelectStrategy(waf.Vendor, learn)
	_, headers := wafintel.ApplyStrategy("", strategy)
	return headers
}

func (r *Runner) wafHeaders(endpointURL string) map[string]string {
	return r.wafHeadersForModule("", endpointURL)
}

func moduleAllowsHeaderPayloads(module string) bool {
	module = strings.ToLower(strings.TrimSpace(module))
	if module == "" {
		return false
	}
	return severityRank[moduleMaxSeverity(module)] >= severityRank["high"]
}

func mergeHeaders(base, extra map[string]string) map[string]string {
	if len(extra) == 0 {
		return base
	}
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func (r *Runner) modulePayloads(target ScanTarget, vulnClass, oastURL string) []payloadgen.Payload {
	if existing := payloadsForClass(target.Payloads.Payloads, vulnClass); len(existing) > 0 {
		if isValidOASTURL(oastURL) {
			generated := r.generatedModulePayloads(target, vulnClass, oastURL)
			for _, candidate := range generated {
				if strings.Contains(strings.ToLower(candidate.ExpectedSignal), "oast") {
					existing = append(existing, candidate)
				}
			}
		}
		return dedupePayloads(existing)
	}
	return r.generatedModulePayloads(target, vulnClass, oastURL)
}

// generatedModulePayloads deliberately excludes discovered/static payloads.
// OAST callers use it to regenerate the same WAF variant with a fresh
// callback URL, preserving a one-to-one callback-to-probe binding.
func (r *Runner) generatedModulePayloads(target ScanTarget, vulnClass, oastURL string) []payloadgen.Payload {
	hints := r.wafHintsForTarget(target)
	hints.AllowEvasion = hints.AllowEvasion && moduleAllowsHeaderPayloads(vulnClass)
	return dedupePayloads(payloadgen.GenerateGroupB(vulnClass, oastURL, hints))
}

func (r *Runner) wafHintsForTarget(target ScanTarget) payloadgen.WAFHints {
	hints := payloadgen.WAFHints{AllowEvasion: r.cfg.EnableWAFBypassHeaders}
	if r.db != nil {
		host := wafintel.HostFromTarget(target.EndpointURL)
		if waf, err := r.db.GetWAFProfile(r.scanID, host); err == nil {
			hints.Vendor = waf.Vendor
			hints.CautiousModeRecommended = waf.CautiousModeRecommended
		}
		if raw, err := r.db.LoadWAFLearningProfile(host); err == nil {
			learn := wafintel.NewLearningProfile(host)
			if json.Unmarshal([]byte(raw), &learn) == nil {
				hints.PreferredTechniques = wafintel.PreferredTechniques(learn)
				hints.BlockedChars = learn.BlockedChars
				hints.AllowedChars = learn.AllowedChars
				hints.QueryURLDecodeDepth = learn.Decoder.QueryURLDecodeDepth
				hints.QueryURLDecodeObserved = learn.Decoder.QueryURLDecodeObserved
				hints.QueryURLDecodeConflict = learn.Decoder.QueryURLDecodeConflict
				hints.QueryPlusAsSpace = learn.Decoder.QueryPlusAsSpace
				hints.QueryPlusObserved = learn.Decoder.QueryPlusObserved
				hints.QueryPlusConflict = learn.Decoder.QueryPlusConflict
			}
		}
	}
	return hints
}

func (r *Runner) runtimeSQLiWAFVariantSets(target ScanTarget, values []string) []payloadgen.WAFVariantSet {
	hints := r.wafHintsForTarget(target)
	return r.runtimeSQLiWAFVariantSetsWithHints(target, values, hints)
}

func (r *Runner) runtimeSQLiWAFVariantSetsWithHints(target ScanTarget, values []string, hints payloadgen.WAFHints) []payloadgen.WAFVariantSet {
	hints.AllowEvasion = hints.AllowEvasion && moduleAllowsHeaderPayloads("sqli")
	location := target.Location
	if strings.TrimSpace(location) == "" {
		location = target.Profile.ParameterLocation
	}
	return payloadgen.RuntimeWAFVariantSets(values, "sqli", target.Profile.Context, location, hints, 3)
}

func dedupePayloads(payloads []payloadgen.Payload) []payloadgen.Payload {
	seen := map[string]struct{}{}
	out := make([]payloadgen.Payload, 0, len(payloads))
	for _, p := range payloads {
		key := strings.ToLower(strings.Join([]string{
			p.Family, p.VulnClass, p.Value, p.Encoding, p.WAFVendor,
		}, "|"))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	return out
}
