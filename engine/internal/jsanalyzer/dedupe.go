package jsanalyzer

import (
	"sort"
	"strings"
)

// DeduplicateSemantic merges endpoints by normalized template + method.
func DeduplicateSemantic(endpoints []ExtractedEndpoint) []ExtractedEndpoint {
	best := map[string]ExtractedEndpoint{}
	for _, ep := range endpoints {
		tmpl := ep.Template
		if javascriptDependency(ep) {
			// Chunk identifiers are filenames, not REST resource IDs. Merging
			// 123.js with 456.js can discard an entire lazy API dependency.
			tmpl = ep.URL
		}
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
	sort.Slice(out, func(i, j int) bool {
		if out[i].Method != out[j].Method {
			return out[i].Method < out[j].Method
		}
		return out[i].URL < out[j].URL
	})
	return out
}
