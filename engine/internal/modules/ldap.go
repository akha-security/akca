package modules

import (
	"context"
	"fmt"
	"strings"
)

type ldapProbe struct {
	value        string
	variant      string
	errorPattern string
}

var ldapErrorSignatures = []string{
	"ldap_search_ext_s", "ldap_search", "ldap_bind", "invalid dn syntax",
	"ipworks asp ldap", "com.sun.jndi.ldap", "javax.naming.directory",
	"unhandled exception in LDAP", "ldap_parse_result", "ldapException",
	"bad search filter", "protocol error occurred in LDAP",
	"supplied argument is not a valid ldap", "namingException",
	"org.apache.directory", "system.directoryservices", "net.sourceforge.jldap",
}

func ldapErrorSignal(body, baseline string) bool {
	bodyLower, baseLower := strings.ToLower(body), strings.ToLower(baseline)
	for _, sig := range ldapErrorSignatures {
		sig = strings.ToLower(sig)
		if strings.Contains(bodyLower, sig) && !strings.Contains(baseLower, sig) {
			return true
		}
	}
	return false
}

func (r *Runner) runLDAPInjection(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("ldap", target); !ok {
		r.emitSkip("ldap", target, reason)
		return nil
	}

	if strings.TrimSpace(target.Parameter) == "" {
		return nil
	}

	baseline, err := r.probe(ctx, target, "")
	if err != nil {
		return nil
	}

	probes := []ldapProbe{
		{value: "*", variant: "wildcard_query", errorPattern: "ldap_wildcard"},
		{value: "*)(&", variant: "parenthesis_breakout", errorPattern: "ldap_syntax_error"},
		{value: "*)(uid=*))(|(uid=*", variant: "filter_breakout", errorPattern: "ldap_filter_breakout"},
		{value: "admin*)(|(password=*))", variant: "admin_filter_bypass", errorPattern: "ldap_admin_bypass"},
		{value: "*(|(mail=*))", variant: "attribute_enumeration", errorPattern: "ldap_attribute_enum"},
		{value: "x' || '1'='1", variant: "quote_breakout", errorPattern: "ldap_quote_breakout"},
		{value: "*)(cn=*))%00", variant: "null_byte_filter", errorPattern: "ldap_filter_breakout"},
	}

	var out []ModuleFinding
	for _, p := range probes {
		if ctx.Err() != nil {
			break
		}

		rr, err := r.probe(ctx, target, p.value)
		if err != nil || isInfrastructureError(rr.Response.StatusCode) {
			continue
		}

		bodyLower := strings.ToLower(rr.Response.Body)
		baseLower := strings.ToLower(baseline.Response.Body)

		var matchedSig string
		for _, sig := range ldapErrorSignatures {
			normalizedSig := strings.ToLower(sig)
			if strings.Contains(bodyLower, normalizedSig) && !strings.Contains(baseLower, normalizedSig) {
				matchedSig = sig
				break
			}
		}

		if matchedSig != "" {
			signal := fmt.Sprintf("ldap_error_%s", p.variant)
			payloadObj := defaultPayload("ldap", p.variant, p.value, signal)
			f := r.verifyAndBuild(ctx, "ldap", target, payloadObj, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Title = "LDAP Injection (Error-Based)"
				f.Severity = "high"
				f.Description = fmt.Sprintf("Target parameter '%s' triggered an LDAP directory error signature ('%s') when probed with '%s'.", target.Parameter, matchedSig, p.value)
				r.recordFinding(ctx, &out, f, "ldap", signal)
				break
			}
		}
	}

	return out
}
