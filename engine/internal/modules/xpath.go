package modules

import (
	"context"
	"fmt"
	"strings"
)

type xpathProbe struct {
	value   string
	variant string
}

var xpathErrorSignatures = []string{
	"xpathException", "simplexml_load_string", "simplexmlelement::xpath",
	"domxpath::evaluate", "expression must evaluate to a node-set",
	"invalid expression in xpath", "unknown error in xpath",
	"xml/xpath error", "javax.xml.xpath.xpathexpressionexception",
	"system.xml.xpath.xpathexception", "msxml3.dll", "msxml4.dll",
	"org.apache.xpath.XPathException", "saxon.trans.XPathException",
	"xpath syntax error", "invalid predicate in xpath",
}

func xpathErrorSignal(body, baseline string) bool {
	bodyLower, baseLower := strings.ToLower(body), strings.ToLower(baseline)
	for _, sig := range xpathErrorSignatures {
		sig = strings.ToLower(sig)
		if strings.Contains(bodyLower, sig) && !strings.Contains(baseLower, sig) {
			return true
		}
	}
	return false
}

func (r *Runner) runXPathInjection(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("xpath", target); !ok {
		r.emitSkip("xpath", target, reason)
		return nil
	}

	if strings.TrimSpace(target.Parameter) == "" {
		return nil
	}

	baseline, err := r.probe(ctx, target, "")
	if err != nil {
		return nil
	}

	probes := []xpathProbe{
		{value: "' or '1'='1", variant: "quoted_boolean_or"},
		{value: "' or ''='", variant: "empty_quote_or"},
		{value: "'] | //user/*[1]", variant: "node_union_injection"},
		{value: "1' or count(/child::node())>0 or '1'='1", variant: "count_predicate_injection"},
		{value: "1 and count(//*)>0", variant: "count_all_nodes"},
		{value: "admin' or '1'='1' or 'a'='a", variant: "admin_or_true"},
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
		for _, sig := range xpathErrorSignatures {
			normalizedSig := strings.ToLower(sig)
			if strings.Contains(bodyLower, normalizedSig) && !strings.Contains(baseLower, normalizedSig) {
				matchedSig = sig
				break
			}
		}

		if matchedSig != "" {
			signal := fmt.Sprintf("xpath_error_%s", p.variant)
			payloadObj := defaultPayload("xpath", p.variant, p.value, signal)
			f := r.verifyAndBuild(ctx, "xpath", target, payloadObj, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Title = "XPath Injection (Error-Based)"
				f.Severity = "high"
				f.Description = fmt.Sprintf("Target parameter '%s' triggered an XML/XPath query engine error ('%s') when probed with '%s'.", target.Parameter, matchedSig, p.value)
				r.recordFinding(ctx, &out, f, "xpath", signal)
				break
			}
		}
	}

	return out
}
