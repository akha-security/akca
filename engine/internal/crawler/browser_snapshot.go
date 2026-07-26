package crawler

import (
	"regexp"
	"strings"
)

var (
	browserActionRE = regexp.MustCompile(`(?is)<(?:a|button|input)[^>]*(?:href|formaction|value|aria-label|title)=["']([^"']+)["']`)
	browserFormRE   = regexp.MustCompile(`(?is)<form[^>]*action=["']([^"']*)["']`)
	storageSetRE    = regexp.MustCompile(`(?i)(localStorage|sessionStorage)\.setItem\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']*)["']`)
	domSinkRE       = regexp.MustCompile(`(?i)\.(innerHTML|outerHTML)\s*=|document\.write\s*\(|eval\s*\(|setTimeout\s*\(\s*["']`)
)

func BuildBrowserSnapshot(rawURL, dom string, calls []DiscoveredEndpoint) BrowserSnapshot {
	snapshot := BrowserSnapshot{
		URL: rawURL, DOM: dom, NetworkCalls: append([]DiscoveredEndpoint(nil), calls...),
		Cookies: map[string]string{}, SessionStorage: map[string]string{}, LocalStorage: map[string]string{},
	}
	for _, match := range browserActionRE.FindAllStringSubmatch(dom, -1) {
		snapshot.VisibleActions = append(snapshot.VisibleActions, strings.TrimSpace(match[1]))
	}
	for _, match := range browserFormRE.FindAllStringSubmatch(dom, -1) {
		snapshot.Forms = append(snapshot.Forms, strings.TrimSpace(match[1]))
	}
	for _, match := range storageSetRE.FindAllStringSubmatch(dom, -1) {
		if strings.EqualFold(match[1], "localStorage") {
			snapshot.LocalStorage[match[2]] = match[3]
		} else {
			snapshot.SessionStorage[match[2]] = match[3]
		}
	}
	for _, call := range calls {
		switch call.Source {
		case SourceWebSocket:
			snapshot.WebSockets = append(snapshot.WebSockets, call.URL)
		}
		if strings.Contains(strings.ToLower(call.WhyDiscovered), "service worker") {
			snapshot.ServiceWorkers = append(snapshot.ServiceWorkers, call.URL)
		}
	}
	for _, match := range domSinkRE.FindAllStringSubmatch(dom, -1) {
		snapshot.DOMSinkEvents = append(snapshot.DOMSinkEvents, strings.TrimSpace(match[0]))
	}
	snapshot.VisibleActions = uniqueStrings(snapshot.VisibleActions)
	snapshot.Forms = uniqueStrings(snapshot.Forms)
	snapshot.WebSockets = uniqueStrings(snapshot.WebSockets)
	snapshot.ServiceWorkers = uniqueStrings(snapshot.ServiceWorkers)
	snapshot.DOMSinkEvents = uniqueStrings(snapshot.DOMSinkEvents)
	return snapshot
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
