package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/akha-security/akca/engine/internal/oast"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/verification"
	"golang.org/x/net/html"
)

func (r *Runner) runXSS(ctx context.Context, target ScanTarget) []ModuleFinding {
	var out []ModuleFinding
	baseline, err := r.probe(ctx, target, "akca-xss-base")
	if err != nil {
		return nil
	}
	probes := payloadsForClass(target.Payloads.Payloads, "xss")
	if len(probes) == 0 {
		probes = defaultXSSProbes()
	}
	for _, p := range probes {
		if p.IsControl || p.IsNegativeControl {
			continue
		}
		attempts := r.injectionProbeAttempts(ctx, target, p.Value)
		attempt := pickBodyDiffAttempt(attempts, baseline.Response.Body)
		if len(attempts) == 0 {
			continue
		}
		rr := attempt.RR
		probeTarget := attempt.Target
		if probeTarget.EndpointURL == "" {
			probeTarget = target
		}
		signal := detectXSSSignal(p, rr.Response.Body, baseline.Response.Body)
		if signal == "" {
			continue
		}
		if !xssSignalConfirmed(p, rr.Response.Body, baseline.Response.Body, signal) {
			continue
		}
		oastURL := ""
		domPresent := verification.CheckDOMPresence(rr.Response.Body, p.Value)
		domExecuted := false
		domPayload := verification.DOMXSSPayload()
		domRR, domErr := r.probe(ctx, target, domPayload)
		if domErr == nil && r.browser != nil && domRR.Request.Method == "GET" && domRR.Request.URL != "" {
			rendered, renderErr := r.browser.Render(ctx, domRR.Request.URL)
			domExecuted = renderErr == nil && verification.CheckDOMExecution(rendered)
		}
		if domExecuted && !sqliErrorRe.MatchString(domRR.Response.Body) {
			p = defaultPayload("xss", "browser_dom_canary", domPayload, "dom_execution")
			rr = domRR
			probeTarget = target
			domPresent = verification.CheckDOMPresence(domRR.Response.Body, domPayload)
			signal = "dom_execution"
		}
		marker := ""
		if target.Profile.Stable && target.Profile.ReflectionKind == reflection.ReflectionRaw {
			marker = fmt.Sprintf("akca-stored-%s-%s", target.Parameter, r.scanID)
			r.trackStoredMarker(target.EndpointURL, target.Parameter, marker)
			if signal == "reflected" {
				signal = "stored_tracking"
			}
		}
		// DOM presence/execution scoring is only for the DOM-XSS path. A raw,
		// executable reflected payload is already validated by the HTML parser;
		// treating that ordinary reflection as "DOM presence only" would apply
		// an unrelated false-positive penalty.
		domSignalPresent := domPresent && signal == "dom_execution"
		f := r.verifyAndBuild(ctx, "xss", probeTarget, p, baseline, rr, signal, domSignalPresent, domExecuted, oastURL, marker)
		if f != nil {
			_ = r.persistFinding(*f)
			out = append(out, *f)
		}
	}
	return out
}

func detectXSSSignal(p payloadgen.Payload, body, baseline string) string {
	if strings.Contains(body, p.Value) && !strings.Contains(baseline, p.Value) {
		if xssExecutableReflection(body, p.Value) && !xssExecutableReflection(baseline, p.Value) {
			return "reflected"
		}
	}
	enc := htmlEncodeSimple(p.Value)
	if enc != p.Value && strings.Contains(body, enc) && !strings.Contains(baseline, enc) {
		return "reflected_encoded"
	}
	if verification.CheckDOMExecution(body) && !verification.CheckDOMExecution(baseline) {
		return "dom_execution"
	}
	return ""
}

func xssExecutableReflection(body, payload string) bool {
	if payload == "" || !strings.Contains(body, payload) {
		return false
	}
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		return false
	}
	var walk func(*html.Node) bool
	walk = func(n *html.Node) bool {
		if n.Type == html.ElementNode {
			for _, attr := range n.Attr {
				name := strings.ToLower(attr.Key)
				value := strings.ToLower(attr.Val)
				if strings.HasPrefix(name, "on") && strings.Contains(value, "alert(1)") {
					return true
				}
				if (name == "href" || name == "src" || name == "xlink:href") && strings.HasPrefix(strings.TrimSpace(value), "javascript:") && strings.Contains(value, "alert(1)") {
					return true
				}
			}
			if n.Data == "script" && strings.Contains(strings.ToLower(nodeText(n)), "alert(1)") {
				return true
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			if walk(child) {
				return true
			}
		}
		return false
	}
	return walk(doc)
}

func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(cur *html.Node) {
		if cur.Type == html.TextNode {
			b.WriteString(cur.Data)
		}
		for child := cur.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)
	return b.String()
}

func htmlEncodeSimple(s string) string {
	r := strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

func defaultXSSProbes() []payloadgen.Payload {
	values := []struct {
		variant, value, signal string
	}{
		{"html_img_onerror", `<img src=x onerror=alert(1)>`, "dom_mutation"},
		{"html_svg_onload", `"><svg/onload=alert(1)>`, "dom_mutation_svg"},
		{"poly_script_break", `</script><svg/onload=alert(1)>`, "script_breakout"},
		{"poly_attr", `" onfocus=alert(1) autofocus="`, "event_handler"},
		{"poly_js", `';alert(1)//`, "js_execution"},
		{"poly_body", `<body onload=alert(1)>`, "dom_mutation"},
		{"poly_svg", `<svg/onload=alert(1)>`, "dom_mutation_svg"},
		{"poly_url", `javascript:alert(1)`, "url_scheme_execution"},
	}
	out := make([]payloadgen.Payload, 0, len(values))
	for _, v := range values {
		out = append(out, payloadgen.Payload{
			Value: v.value, VulnClass: "xss", Variant: v.variant, Family: "xss",
			ExpectedSignal: v.signal,
		})
	}
	return out
}

var _ OASTClient = (*oast.Listener)(nil)
