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
	"xmlxpatherror", "invalid xpath expression", "xpathexception",
	"unknown xpath", "xpath error", "evaluation of xpath", "invalid token in xpath",
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
		{value: "' or string-length(name(/*[1]))>0 or 'a'='a", variant: "string_length_boolean"},
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
				return out
			}
		}
	}

	// Blind Boolean Differential Check
	if len(out) == 0 && baseline.Response.StatusCode >= 200 && baseline.Response.StatusCode < 400 {
		truePayload := "' or '1'='1' or 'a'='b"
		falsePayload := "' and '1'='2' and 'a'='a"

		trueRR, errTrue := r.probe(ctx, target, truePayload)
		falseRR, errFalse := r.probe(ctx, target, falsePayload)

		if errTrue == nil && errFalse == nil && !isInfrastructureError(trueRR.Response.StatusCode) && !isInfrastructureError(falseRR.Response.StatusCode) {
			trueLen := len(trueRR.Response.Body)
			falseLen := len(falseRR.Response.Body)
			diff := trueLen - falseLen
			if diff < 0 {
				diff = -diff
			}

			if (trueRR.Response.StatusCode == 200 && falseRR.Response.StatusCode != 200) ||
				(diff > 40 && resourceFingerprint(trueRR.Response.Body) != resourceFingerprint(falseRR.Response.Body)) {
				reTrue, reErr := r.probe(ctx, target, truePayload)
				if reErr == nil && reTrue.Response.StatusCode == trueRR.Response.StatusCode {
					signal := "xpath_blind_boolean"
					pObj := defaultPayload("xpath", "blind_boolean", truePayload, signal)
					f := r.verifyAndBuild(ctx, "xpath", target, pObj, falseRR, reTrue, signal, false, false, "", "")
					if f != nil {
						f.Title = "XPath Injection (Blind Boolean-Based)"
						f.Severity = "high"
						f.Description = fmt.Sprintf("Target parameter '%s' exhibits differential behavior between boolean XPath conditions ('%s' vs '%s').", target.Parameter, truePayload, falsePayload)
						r.recordFinding(ctx, &out, f, "xpath", signal)
					}
				}
			}
		}
	}

	return out
}
