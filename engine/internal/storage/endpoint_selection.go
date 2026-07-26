package storage

import (
	"net/url"
	"sort"
	"strings"
)

// selectEndpointsBalanced prioritizes high-value endpoints then round-robins across hosts.
func selectEndpointsBalanced(all []DiscoveryEndpoint, limit int) []DiscoveryEndpoint {
	if limit <= 0 || len(all) == 0 {
		return nil
	}
	if len(all) <= limit {
		return all
	}

	sort.SliceStable(all, func(i, j int) bool {
		return endpointProbeScore(all[i]) > endpointProbeScore(all[j])
	})

	byHost := map[string][]DiscoveryEndpoint{}
	hostOrder := make([]string, 0)
	for _, ep := range all {
		host := endpointHost(ep.URL)
		if _, ok := byHost[host]; !ok {
			hostOrder = append(hostOrder, host)
		}
		byHost[host] = append(byHost[host], ep)
	}
	sort.Strings(hostOrder)

	out := make([]DiscoveryEndpoint, 0, limit)
	idx := make([]int, len(hostOrder))
	for len(out) < limit {
		added := false
		for i, host := range hostOrder {
			if idx[i] >= len(byHost[host]) {
				continue
			}
			out = append(out, byHost[host][idx[i]])
			idx[i]++
			added = true
			if len(out) >= limit {
				break
			}
		}
		if !added {
			break
		}
	}
	return out
}

func endpointProbeScore(ep DiscoveryEndpoint) int {
	score := 0
	raw := strings.ToLower(ep.URL)
	method := strings.ToUpper(ep.Method)

	if u, err := url.Parse(ep.URL); err == nil && u.RawQuery != "" {
		score += 60
	}
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		score += 35
	}
	for _, hint := range []string{"/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/oauth", "/login", "/search", "/admin"} {
		if strings.Contains(raw, hint) {
			score += 25
			break
		}
	}
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".ico", ".map"} {
		if strings.HasSuffix(raw, ext) {
			score -= 80
			break
		}
	}
	if strings.Contains(raw, "/static/") || strings.Contains(raw, "/assets/") {
		score -= 40
	}
	return score
}

func endpointHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Hostname()
}
