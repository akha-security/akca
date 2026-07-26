package jsanalyzer

import "regexp"

var (
	reSourceMapComment = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=(\S+)`)
	reSourceMapLine    = regexp.MustCompile(`(?i)sourceMappingURL=([^\s"'` + "`" + `)]+)`)
)

func DetectSourceMaps(jsURL, js string) []SourceMapRef {
	var out []SourceMapRef
	seen := map[string]struct{}{}
	for _, re := range []*regexp.Regexp{reSourceMapComment, reSourceMapLine} {
		for _, m := range re.FindAllStringSubmatch(js, -1) {
			if len(m) < 2 {
				continue
			}
			ref := m[1]
			if _, ok := seen[ref]; ok {
				continue
			}
			seen[ref] = struct{}{}
			out = append(out, SourceMapRef{
				URL: ref, FromFile: jsURL, Exposed: true, Confidence: 0.9,
			})
		}
	}
	return out
}
