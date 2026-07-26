package shadowapi

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

const (
	UndocumentedRuntime = "undocumented_runtime"
	DocumentedUnseen    = "documented_not_observed"
	MethodDrift         = "method_drift"
)

type Operation struct {
	URL    string
	Method string
	Source string
}

type Diff struct {
	Kind             string
	Method           string
	Path             string
	DocumentedMethod string
	ObservedMethod   string
	Source           string
	Detail           string
}

var (
	templateSegment = regexp.MustCompile(`^\{[^/{}]+\}$|^:[A-Za-z_][A-Za-z0-9_]*$`)
	numericSegment  = regexp.MustCompile(`^[0-9]{1,20}$`)
	uuidSegment     = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	versionPath     = regexp.MustCompile(`(?i)/v[0-9]+(?:/|$)`)
)

func Analyze(operations []Operation) []Diff {
	documented := map[string]Operation{}
	runtime := map[string]Operation{}
	docPaths := map[string]map[string]Operation{}
	runPaths := map[string]map[string]Operation{}

	for _, operation := range operations {
		operation.Method = normalizeMethod(operation.Method)
		keyPath, ok := normalizedPath(operation.URL)
		if !ok {
			continue
		}
		key := operation.Method + " " + keyPath
		if operation.Source == "api_import" {
			documented[key] = operation
			addPathMethod(docPaths, keyPath, operation)
			continue
		}
		if strongRuntimeSource(operation.Source) || likelyAPI(operation.Method, keyPath) {
			runtime[key] = operation
			addPathMethod(runPaths, keyPath, operation)
		}
	}

	var diffs []Diff
	for key, operation := range runtime {
		if _, ok := documented[key]; ok {
			continue
		}
		keyPath, _ := normalizedPath(operation.URL)
		if methods := docPaths[keyPath]; len(methods) > 0 {
			for documentedMethod := range methods {
				diffs = append(diffs, Diff{
					Kind: MethodDrift, Method: operation.Method, Path: keyPath,
					DocumentedMethod: documentedMethod, ObservedMethod: operation.Method, Source: operation.Source,
					Detail: fmt.Sprintf("runtime observed %s while the API definition documents %s", operation.Method, documentedMethod),
				})
			}
			continue
		}
		diffs = append(diffs, Diff{
			Kind: UndocumentedRuntime, Method: operation.Method, Path: keyPath,
			ObservedMethod: operation.Method, Source: operation.Source,
			Detail: "runtime API operation was observed but is absent from the imported API definition",
		})
	}

	for key, operation := range documented {
		if _, ok := runtime[key]; ok {
			continue
		}
		keyPath, _ := normalizedPath(operation.URL)
		if len(runPaths[keyPath]) > 0 {
			continue // represented by a method_drift entry
		}
		diffs = append(diffs, Diff{
			Kind: DocumentedUnseen, Method: operation.Method, Path: keyPath,
			DocumentedMethod: operation.Method, Source: operation.Source,
			Detail: "documented API operation was not observed during authenticated crawl or browser/API traffic",
		})
	}

	sort.Slice(diffs, func(i, j int) bool {
		if diffs[i].Kind != diffs[j].Kind {
			return diffs[i].Kind < diffs[j].Kind
		}
		if diffs[i].Path != diffs[j].Path {
			return diffs[i].Path < diffs[j].Path
		}
		return diffs[i].Method < diffs[j].Method
	})
	return diffs
}

func addPathMethod(index map[string]map[string]Operation, keyPath string, operation Operation) {
	if index[keyPath] == nil {
		index[keyPath] = map[string]Operation{}
	}
	index[keyPath][operation.Method] = operation
}

func normalizedPath(rawURL string) (string, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return "", false
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(parsed.EscapedPath(), "/"))
	segments := strings.Split(cleaned, "/")
	for index, segment := range segments {
		decoded, err := url.PathUnescape(segment)
		if err == nil {
			segment = decoded
		}
		if templateSegment.MatchString(segment) || numericSegment.MatchString(segment) || uuidSegment.MatchString(segment) {
			segments[index] = "{param}"
		}
	}
	return strings.ToLower(parsed.Host) + strings.Join(segments, "/"), true
}

func normalizeMethod(method string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return "GET"
	}
	return method
}

func strongRuntimeSource(source string) bool {
	switch strings.ToLower(source) {
	case "browser_xhr", "js_analyzer", "js_ast", "inline_js", "graphql", "api_doc", "form", "event_source":
		return true
	default:
		return false
	}
}

func likelyAPI(method, keyPath string) bool {
	if method != "GET" && method != "HEAD" && method != "OPTIONS" {
		return true
	}
	lower := strings.ToLower(keyPath)
	return strings.Contains(lower, "/api/") || strings.Contains(lower, "/graphql") || versionPath.MatchString(lower)
}
