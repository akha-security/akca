package fuzzing

import (
	"encoding/xml"
	"io"
	"net/url"
	"path"
	"strings"
)

const maxAdaptiveTasksPerDocument = 128

// DiscoverTasks extracts bounded, same-origin GET paths from well-known path
// indexes. It intentionally does not crawl arbitrary HTML; the crawler owns
// that job, while fuzzing only consumes high-signal robots and sitemap hints.
func DiscoverTasks(source FuzzTask, status int, body, contentType string) []FuzzTask {
	if status < 200 || status >= 300 || strings.TrimSpace(body) == "" {
		return nil
	}
	sourceURL, err := url.Parse(source.URL)
	if err != nil || sourceURL.Host == "" {
		return nil
	}
	sourcePath := strings.ToLower(sourceURL.Path)

	var candidates []string
	switch {
	case strings.HasSuffix(sourcePath, "/robots.txt") || sourcePath == "/robots.txt":
		candidates = robotsCandidates(body)
	case strings.Contains(sourcePath, "sitemap") &&
		(strings.Contains(strings.ToLower(contentType), "xml") || strings.Contains(body, "<loc>")):
		candidates = sitemapCandidates(body)
	default:
		return nil
	}

	seen := make(map[string]struct{})
	tasks := make([]FuzzTask, 0, min(len(candidates), maxAdaptiveTasksPerDocument))
	for _, candidate := range candidates {
		task, ok := adaptiveTask(sourceURL, candidate)
		if !ok {
			continue
		}
		key := task.Method + " " + task.URL
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		tasks = append(tasks, task)
		if len(tasks) >= maxAdaptiveTasksPerDocument {
			break
		}
	}
	return tasks
}

func robotsCandidates(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "allow", "disallow", "sitemap":
			value = strings.TrimSpace(value)
			if value != "" {
				out = append(out, value)
			}
		}
	}
	return out
}

func sitemapCandidates(body string) []string {
	if len(body) > 2<<20 {
		body = body[:2<<20]
	}
	decoder := xml.NewDecoder(strings.NewReader(body))
	var out []string
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out
		}
		start, ok := token.(xml.StartElement)
		if !ok || !strings.EqualFold(start.Name.Local, "loc") {
			continue
		}
		var value string
		if decoder.DecodeElement(&value, &start) == nil && strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
		if len(out) >= maxAdaptiveTasksPerDocument {
			break
		}
	}
	return out
}

func adaptiveTask(source *url.URL, candidate string) (FuzzTask, bool) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" || strings.ContainsAny(candidate, "*$") {
		return FuzzTask{}, false
	}
	reference, err := url.Parse(candidate)
	if err != nil {
		return FuzzTask{}, false
	}
	resolved := source.ResolveReference(reference)
	if !strings.EqualFold(resolved.Scheme, source.Scheme) || !strings.EqualFold(resolved.Host, source.Host) || resolved.User != nil {
		return FuzzTask{}, false
	}
	resolved.Fragment = ""
	// Directory fuzzing tests paths, not action-like query strings.
	resolved.RawQuery = ""
	resolved.ForceQuery = false
	if resolved.Path == "" || resolved.Path == "/" || len(resolved.String()) > 2048 || unsafeAdaptivePath(resolved.Path) {
		return FuzzTask{}, false
	}
	if len(strings.Split(strings.Trim(resolved.Path, "/"), "/")) > 10 {
		return FuzzTask{}, false
	}
	category := CategoryDiscovered
	if strings.Contains(strings.ToLower(path.Base(resolved.Path)), "sitemap") {
		category = CategoryGeneral
	}
	return FuzzTask{URL: resolved.String(), Method: "GET", Category: category, Path: resolved.Path}, true
}

func unsafeAdaptivePath(rawPath string) bool {
	lower := strings.ToLower(rawPath)
	for _, token := range []string{
		"/logout", "/log-out", "/signout", "/sign-out", "/shutdown",
		"/delete/", "/destroy/", "/terminate/",
	} {
		if strings.Contains(lower, token) || strings.HasSuffix(lower, strings.TrimSuffix(token, "/")) {
			return true
		}
	}
	return false
}
