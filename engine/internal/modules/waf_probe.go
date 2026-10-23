package modules

import (
	"encoding/json"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/models"

	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/wafintel"
)

func (r *Runner) wafHeadersForModule(module, endpointURL string) map[string]string {
	if !moduleAllowsHeaderPayloads(module) {
		return nil
	}
	if r.db == nil || r.cfg.PassiveMode || !r.cfg.EnableWAFBypassHeaders {
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
	return httpclient.MergeHeaders(base, extra)
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
	profile := target.Profile
	if target.Location != "" {
		profile.ParameterLocation = target.Location
	}
	return dedupePayloads(payloadgen.GenerateGroupBForProfile(vulnClass, oastURL, hints, profile))
}

func (r *Runner) wafHintsForTarget(target ScanTarget) payloadgen.WAFHints {
	var profile models.WAFProfile
	learn := wafintel.NewLearningProfile(wafintel.HostFromTarget(target.EndpointURL))
	if r.db != nil {
		host := wafintel.HostFromTarget(target.EndpointURL)
		if waf, err := r.db.GetWAFProfile(r.scanID, host); err == nil {
			profile = waf
		}
		if raw, err := r.db.LoadWAFLearningProfile(host); err == nil {
			if json.Unmarshal([]byte(raw), &learn) != nil {
				learn = wafintel.NewLearningProfile(host)
			}
		}
	}
	return payloadgen.WAFHintsForProfile(r.cfg, profile, learn)
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
