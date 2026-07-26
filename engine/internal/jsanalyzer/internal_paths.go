package jsanalyzer

import (
	"regexp"
	"strings"
)

var internalPathRe = regexp.MustCompile(`(?i)(?:require|import)\s*\(\s*["']([@./][^"']+)["']`)

func DetectInternalPaths(js string) []InternalPath {
	var out []InternalPath
	seen := map[string]struct{}{}
	for _, m := range internalPathRe.FindAllStringSubmatch(js, -1) {
		p := m[1]
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		kind := "module"
		if strings.HasPrefix(p, "@/") || strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") {
			kind = "internal"
		}
		out = append(out, InternalPath{Path: p, Kind: kind, Confidence: 0.7})
	}
	return out
}
