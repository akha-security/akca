package planner

import (
	"sort"
	"strings"

	"github.com/akha-security/akca/engine/internal/learning"
)

type RequestItem struct {
	URL       string
	Method    string
	Parameter string
	Priority  int
	Reason    string
}

type Planner struct {
	domainProfiles map[string]learning.Profile
}

func New(plannerProfiles map[string]learning.Profile) *Planner {
	if plannerProfiles == nil {
		plannerProfiles = map[string]learning.Profile{}
	}
	return &Planner{domainProfiles: plannerProfiles}
}

func (p *Planner) Order(items []RequestItem) []RequestItem {
	out := append([]RequestItem{}, items...)
	for i := range out {
		out[i].Priority = p.score(out[i])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority == out[j].Priority {
			return out[i].URL < out[j].URL
		}
		return out[i].Priority > out[j].Priority
	})
	return out
}

func (p *Planner) score(item RequestItem) int {
	base := item.Priority
	if base == 0 {
		base = 50
	}
	host := hostFromURL(item.URL)
	prof, ok := p.domainProfiles[host]
	if !ok {
		return base
	}
	for _, w := range prof.Worked {
		if strings.Contains(item.Parameter, w) || strings.Contains(item.URL, w) {
			base += 15
		}
	}
	for _, b := range append(prof.Blocked, prof.FalsePositive...) {
		if strings.Contains(item.Parameter, b) || strings.Contains(item.URL, b) {
			base -= 20
		}
	}
	return base
}

func hostFromURL(raw string) string {
	raw = strings.TrimPrefix(strings.ToLower(raw), "https://")
	raw = strings.TrimPrefix(raw, "http://")
	if idx := strings.Index(raw, "/"); idx >= 0 {
		raw = raw[:idx]
	}
	return raw
}
