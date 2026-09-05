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
			generated := payloadgen.GenerateGroupB(vulnClass, oastURL, payloadgen.WAFHints{})
			for _, candidate := range generated {
				if strings.Contains(strings.ToLower(candidate.ExpectedSignal), "oast") {
					existing = append(existing, candidate)
				}
			}
		}
		return dedupePayloads(existing)
	}
	vendor := ""
	var preferred []string
	var blockedChars, allowedChars []string
	if r.db != nil {
		host := wafintel.HostFromTarget(target.EndpointURL)
		if waf, err := r.db.GetWAFProfile(r.scanID, host); err == nil {
			vendor = waf.Vendor
		}
		if raw, err := r.db.LoadWAFLearningProfile(host); err == nil {
			learn := wafintel.NewLearningProfile(host)
			if json.Unmarshal([]byte(raw), &learn) == nil {
				preferred = wafintel.PreferredTechniques(learn)
				blockedChars = learn.BlockedChars
				allowedChars = learn.AllowedChars
			}
		}
	}
	return dedupePayloads(payloadgen.GenerateGroupB(vulnClass, oastURL, payloadgen.WAFHints{
		Vendor: vendor, AllowEvasion: r.cfg.EnableWAFBypassHeaders && moduleAllowsHeaderPayloads(vulnClass),
		PreferredTechniques: preferred, BlockedChars: blockedChars, AllowedChars: allowedChars,
	}))
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
