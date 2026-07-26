package modules

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/akha-security/akca/engine/internal/httpclient"
	modcve "github.com/akha-security/akca/engine/internal/modules/cve"
)

var componentPatterns = []struct {
	vendor, product, source string
	pattern                 *regexp.Regexp
}{
	{"apache", "apache", "header", regexp.MustCompile(`(?i)apache[/ ]([0-9][\w.\-]+)`)},
	{"nginx", "nginx", "header", regexp.MustCompile(`(?i)nginx[/ ]([0-9][\w.\-]+)`)},
	{"php", "php", "header", regexp.MustCompile(`(?i)php[/ ]([0-9][\w.\-]+)`)},
	{"php", "php-fpm", "header_or_body", regexp.MustCompile(`(?i)php-fpm[/ ]([0-9][\w.\-]+)`)},
	{"apache", "log4j", "header_or_body", regexp.MustCompile(`(?i)log4j(?:-core)?[ /-]([0-9][\w.\-]+)`)},
	{"apache", "struts2", "header_or_body", regexp.MustCompile(`(?i)(?:struts2|apache struts)[ /-]([0-9][\w.\-]+)`)},
	{"openssl", "openssl", "header_or_body", regexp.MustCompile(`(?i)openssl[/ ]([0-9][\w.\-]+)`)},
	{"nghttp2", "nghttp2", "header_or_body", regexp.MustCompile(`(?i)nghttp2[/ ]([0-9][\w.\-]+)`)},
}

type detectedComponent struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Version string `json:"version"`
	Source  string `json:"source"`
}

func (r *Runner) runVulnerableComponents(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("vulnerable_components", target); !ok {
		r.emitSkip("vulnerable_components", target, reason)
		return nil
	}
	rr, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		return nil
	}
	components := detectComponents(rr.Response.Headers, rr.Response.Body)
	for _, component := range components {
		r.persistComponentInventory(component)
	}
	// Component discovery is inventory, not vulnerability proof. CVE-backed
	// findings are emitted once by known_cve to avoid duplicate reports.
	return nil
}

func (r *Runner) runKnownCVE(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("known_cve", target); !ok {
		r.emitSkip("known_cve", target, reason)
		return nil
	}
	rr, err := r.cachedEmptyProbe(ctx, target)
	if err != nil {
		return nil
	}
	components := detectComponents(rr.Response.Headers, rr.Response.Body)
	return r.componentFindings(ctx, target, rr, components, "known_cve")
}

func (r *Runner) componentFindings(ctx context.Context, target ScanTarget, rr httpclient.RequestResponse, components []detectedComponent, module string) []ModuleFinding {
	var out []ModuleFinding
	baseline := httpclient.RequestResponse{
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: "{}", Headers: map[string]string{"Content-Type": "application/json"}},
	}
	seen := make(map[string]struct{})
	for _, c := range components {
		matches := modcve.MatchComponent(c.Vendor, c.Product, c.Version)
		for _, m := range matches {
			key := strings.ToLower(m.CVEID + "|" + c.Product + "|" + c.Version + "|" + target.EndpointURL)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			p := defaultPayload(module, m.CVEID, c.Product+":"+c.Version, "cve_match")
			f := r.verifyAndBuild(ctx, module, target, p, baseline, rr, m.CVEID, false, false, "", "")
			if f != nil {
				f.Description = m.CVEID + " affects " + c.Product + " " + c.Version
				f.Severity = strings.ToLower(m.Severity)
				r.recordFinding(&out, f, module, m.CVEID)
				r.persistComponentMatch(c, m)
			}
		}
	}
	return out
}

func detectComponents(headers map[string]string, body string) []detectedComponent {
	var out []detectedComponent
	server := headerValue(headers, "Server")
	xPowered := headerValue(headers, "X-Powered-By")
	combined := server + " " + xPowered + " " + body
	seen := make(map[string]struct{})
	for _, fingerprint := range componentPatterns {
		if m := fingerprint.pattern.FindStringSubmatch(combined); len(m) == 2 {
			component := detectedComponent{Vendor: fingerprint.vendor, Product: fingerprint.product, Version: strings.TrimRight(m[1], ".,;:)"), Source: fingerprint.source}
			key := component.Vendor + "|" + component.Product + "|" + component.Version
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				out = append(out, component)
			}
		}
	}
	return out
}

func (r *Runner) persistComponentInventory(component detectedComponent) {
	if r.db == nil {
		return
	}
	raw, _ := json.Marshal(component)
	_, _ = r.db.SaveComponent(r.scanID, string(raw))
}

func (r *Runner) persistComponentMatch(c detectedComponent, match modcve.CatalogEntry) {
	if r.db == nil {
		return
	}
	raw, _ := json.Marshal(c)
	id, err := r.db.SaveComponent(r.scanID, string(raw))
	if err != nil {
		return
	}
	matchRaw, _ := json.Marshal(match)
	_ = r.db.SaveComponentCVEMatch(id, match.CVEID, string(matchRaw))
	entries := []map[string]interface{}{{"cve_id": match.CVEID, "vendor": match.Vendor, "product": match.Product}}
	_ = r.db.SeedCVECatalogIfEmpty(entries, "akca-embedded-v1")
}
