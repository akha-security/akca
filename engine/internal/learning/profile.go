package learning

import (
	"encoding/json"
	"time"
)

type Outcome string

const (
	OutcomeWorked        Outcome = "worked"
	OutcomeFailed        Outcome = "failed"
	OutcomeWAFBlocked    Outcome = "waf_blocked"
	OutcomeUnstable      Outcome = "unstable"
	OutcomeFalsePositive Outcome = "false_positive"
	OutcomeInconclusive  Outcome = "inconclusive"
)

type Profile struct {
	OutcomeCounts map[string]map[string]int `json:"outcome_counts,omitempty"`
	Domain        string                    `json:"domain"`
	EndpointURL   string                    `json:"endpoint_url,omitempty"`
	Worked        []string                  `json:"worked,omitempty"`
	Blocked       []string                  `json:"blocked,omitempty"`
	Noisy         []string                  `json:"noisy,omitempty"`
	FalsePositive []string                  `json:"false_positive,omitempty"`
	Stability     map[string]int            `json:"stability,omitempty"`
	WAFBlocks     map[string]int            `json:"waf_blocks,omitempty"`
	UpdatedAt     time.Time                 `json:"updated_at"`
}

func NewProfile(domain, endpointURL string) Profile {
	return Profile{
		Domain: domain, EndpointURL: endpointURL,
		Stability: map[string]int{}, WAFBlocks: map[string]int{},
		UpdatedAt: time.Now().UTC(),
	}
}

func (p Profile) Record(family string, outcome Outcome) Profile {
	p.UpdatedAt = time.Now().UTC()
	p.OutcomeCounts = cloneOutcomeCounts(p.OutcomeCounts)
	if p.OutcomeCounts[family] == nil {
		p.OutcomeCounts[family] = map[string]int{}
	}
	p.OutcomeCounts[family][string(outcome)]++
	switch outcome {
	case OutcomeWorked:
		p.Worked = appendUnique(p.Worked, family)
	case OutcomeWAFBlocked:
		p.Blocked = appendUnique(p.Blocked, family)
		if p.WAFBlocks == nil {
			p.WAFBlocks = map[string]int{}
		}
		p.WAFBlocks[family]++
	case OutcomeUnstable:
		p.Noisy = appendUnique(p.Noisy, family)
		if p.Stability == nil {
			p.Stability = map[string]int{}
		}
		p.Stability[family]++
	case OutcomeFalsePositive:
		p.FalsePositive = appendUnique(p.FalsePositive, family)
	case OutcomeFailed:
		// tracked via stability counter only
		if p.Stability == nil {
			p.Stability = map[string]int{}
		}
		p.Stability[family]++
	}
	return p
}

func (p Profile) BoostPriority(family string, base int) int {
	for _, w := range p.Worked {
		if w == family {
			return base + 10
		}
	}
	return base
}

func (p Profile) IsBlocked(key string) bool {
	for _, b := range append(append(p.Blocked, p.Noisy...), p.FalsePositive...) {
		if b == key {
			return true
		}
	}
	return false
}

func (p Profile) FalsePositiveRate(family string) float64 {
	counts := p.OutcomeCounts[family]
	fp, worked := counts[string(OutcomeFalsePositive)], counts[string(OutcomeWorked)]
	if fp+worked == 0 {
		return 0
	}
	return float64(fp) / float64(fp+worked)
}

func cloneOutcomeCounts(in map[string]map[string]int) map[string]map[string]int {
	out := make(map[string]map[string]int, len(in))
	for family, counts := range in {
		out[family] = map[string]int{}
		for outcome, n := range counts {
			out[family][outcome] = n
		}
	}
	return out
}

func (p Profile) ExportJSON() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

func ImportJSON(raw []byte) (Profile, error) {
	var p Profile
	if err := json.Unmarshal(raw, &p); err != nil {
		return Profile{}, err
	}
	if p.Stability == nil {
		p.Stability = map[string]int{}
	}
	if p.WAFBlocks == nil {
		p.WAFBlocks = map[string]int{}
	}
	return p, nil
}

func Merge(base, overlay Profile) Profile {
	out := base
	out.Stability = cloneCounters(base.Stability)
	out.WAFBlocks = cloneCounters(base.WAFBlocks)
	out.OutcomeCounts = cloneOutcomeCounts(base.OutcomeCounts)
	for family, counts := range overlay.OutcomeCounts {
		if out.OutcomeCounts[family] == nil {
			out.OutcomeCounts[family] = map[string]int{}
		}
		for outcome, n := range counts {
			out.OutcomeCounts[family][outcome] += n
		}
	}
	out.Worked = union(out.Worked, overlay.Worked)
	out.Blocked = union(out.Blocked, overlay.Blocked)
	out.Noisy = union(out.Noisy, overlay.Noisy)
	out.FalsePositive = union(out.FalsePositive, overlay.FalsePositive)
	for k, v := range overlay.Stability {
		out.Stability[k] += v
	}
	for k, v := range overlay.WAFBlocks {
		out.WAFBlocks[k] += v
	}
	if overlay.UpdatedAt.After(out.UpdatedAt) {
		out.UpdatedAt = overlay.UpdatedAt
	}
	return out
}

func appendUnique(items []string, v string) []string {
	for _, i := range items {
		if i == v {
			return items
		}
	}
	return append(items, v)
}

func union(a, b []string) []string {
	out := append([]string{}, a...)
	for _, v := range b {
		out = appendUnique(out, v)
	}
	return out
}

// ToPayloadGen converts to the lightweight struct used by payloadgen.
func (p Profile) ToPayloadGen() (worked, blocked, noisy, falsePositive []string) {
	return p.Worked, p.Blocked, p.Noisy, p.FalsePositive
}

func cloneCounters(in map[string]int) map[string]int {
	out := map[string]int{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
