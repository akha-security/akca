package jsanalyzer

import "strings"

// DeduplicateSemantic merges endpoints by normalized template + method.
func DeduplicateSemantic(endpoints []ExtractedEndpoint) []ExtractedEndpoint {
	best := map[string]ExtractedEndpoint{}
	for _, ep := range endpoints {
		tmpl := ep.Template
		if tmpl == "" {
			tmpl = NormalizeTemplate(ep.URL)
		}
		key := strings.ToUpper(ep.Method) + " " + tmpl
		existing, ok := best[key]
		if !ok || ep.Confidence > existing.Confidence {
			ep.Template = tmpl
			best[key] = ep
		}
	}
	out := make([]ExtractedEndpoint, 0, len(best))
	for _, ep := range best {
		out = append(out, ep)
	}
	return out
}
