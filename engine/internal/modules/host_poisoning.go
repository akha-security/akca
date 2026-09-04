package modules

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

func (r *Runner) runHostPoisoning(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("host_poisoning", target); !ok {
		r.emitSkip("host_poisoning", target, reason)
		return nil
	}

	tokenBytes := make([]byte, 5)
	_, _ = rand.Read(tokenBytes)
	canaryDomain := fmt.Sprintf("akca-poison-%s.com", hex.EncodeToString(tokenBytes))

	poisonHeaders := []struct {
		header string
		value  string
		signal string
	}{
		{"Host", canaryDomain, "host_header_poisoning"},
		{"X-Forwarded-Host", canaryDomain, "x_forwarded_host_poisoning"},
		{"X-Host", canaryDomain, "x_host_poisoning"},
		{"X-Forwarded-Server", canaryDomain, "x_forwarded_server_poisoning"},
	}

	baseline, err := r.probeHeadersOnlyForModule(ctx, "host_poisoning", target, nil)
	if err != nil {
		return nil
	}

	var out []ModuleFinding

	for _, ph := range poisonHeaders {
		if ctx.Err() != nil {
			break
		}

		headers := map[string]string{ph.header: ph.value}
		rr, err := r.probeHeadersOnlyForModule(ctx, "host_poisoning", target, headers)
		if err != nil {
			continue
		}

		// 1. Check Location header poisoning (Redirect poisoning)
		locHeader := rr.Response.Headers["Location"]
		if locHeader == "" {
			locHeader = rr.Response.Headers["location"]
		}
		if locHeader != "" {
			u, parseErr := url.Parse(locHeader)
			if parseErr == nil && strings.Contains(strings.ToLower(u.Hostname()), canaryDomain) {
				p := defaultPayload("host_poisoning", ph.header, ph.value, ph.signal)
				f := r.verifyAndBuild(ctx, "host_poisoning", target, p, baseline, rr, ph.signal, false, false, "", "")
				if f != nil {
					f.Title = fmt.Sprintf("Host Header Injection via %s (Redirect Poisoning)", ph.header)
					f.Severity = "high"
					f.Description = fmt.Sprintf("Injecting custom host header '%s: %s' poisoned the HTTP Location response header to redirect clients to an untrusted domain.", ph.header, ph.value)
					r.recordFinding(ctx, &out, f, "host_poisoning", ph.signal)
					break
				}
			}
		}

		// 2. Check HTML body link poisoning (Password Reset / Email Link Poisoning)
		bodyLower := strings.ToLower(rr.Response.Body)
		baseLower := strings.ToLower(baseline.Response.Body)

		if strings.Contains(bodyLower, canaryDomain) && !strings.Contains(baseLower, canaryDomain) {
			signal := ph.signal + "_body_reflection"
			p := defaultPayload("host_poisoning", ph.header, ph.value, signal)
			f := r.verifyAndBuild(ctx, "host_poisoning", target, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Title = fmt.Sprintf("Password Reset / Body Link Poisoning via %s", ph.header)
				f.Severity = "high"
				f.Description = fmt.Sprintf("Injecting header '%s: %s' caused the application to generate body URLs pointing to the attacker-controlled host.", ph.header, ph.value)
				r.recordFinding(ctx, &out, f, "host_poisoning", signal)
				break
			}
		}
	}

	return out
}
