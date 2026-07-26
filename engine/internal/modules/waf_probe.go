package modules

import (
	"encoding/json"
	"strings"

	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/wafintel"
)

func (r *Runner) wafHeaders(endpointURL string) map[string]string {
	if r.db == nil {
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
		return existing
	}
	vendor := ""
	if r.db != nil {
		host := wafintel.HostFromTarget(target.EndpointURL)
		if waf, err := r.db.GetWAFProfile(r.scanID, host); err == nil {
			vendor = waf.Vendor
		}
	}
	return payloadgen.GenerateGroupB(vulnClass, oastURL, payloadgen.WAFHints{
		Vendor: vendor, AllowEvasion: r.cfg.EnableWAFBypassHeaders,
	})
}
