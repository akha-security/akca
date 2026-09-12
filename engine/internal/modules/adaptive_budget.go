package modules

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
)

var estimatedXSSRequests = len(defaultXSSProbes()) + 10

// The estimates size a bounded scan; they are never caps in unlimited mode.
func estimatedTargetRequests(module string, target ScanTarget) int64 {
	n := ModuleDefaultProbesPerTarget(module)
	switch module {
	case "xss":
		n = estimatedXSSRequests // baseline and replay proof
	case "sqli":
		n = 128 // baseline, error, matched boolean, timing and union families
	}
	if generated := len(payloadsForClass(target.Payloads.Payloads, module)); generated > 0 && generated+10 > n {
		n = generated + 10
	}
	return int64(n)
}

// Values in the query do not multiply a URL's budget; method and parameter
// carriers remain distinct work items within that URL's allocation.
func budgetEndpointKey(t ScanTarget) string {
	raw := t.EndpointURL
	if u, err := url.Parse(raw); err == nil {
		u.RawQuery, u.Fragment = "", ""
		raw = u.String()
	}
	return targetSurfaceKey(raw, t.Method)
}

func (r *Runner) budgetEligible(module string, target ScanTarget) bool {
	if r.scope != nil && !r.scope.IsInScope(target.EndpointURL) {
		return false
	}
	// Do not use heuristic recommendations to remove coverage. Only surfaces
	// that the injection implementations cannot mutate are excluded here.
	switch module {
	case "xss", "sqli", "nosql", "blind_xss", "ssti", "command_injection":
		return strings.TrimSpace(target.Parameter) != ""
	}
	return true
}

type adaptiveScanBudget struct {
	remaining   int64
	derivedURLs int
	completed   map[string]bool
}

// WithRemainingRequestBudget preserves the distinction between an exhausted
// explicit global limit (zero remaining) and an unlimited scan.
func WithRemainingRequestBudget(remaining int) RunnerOption {
	return func(r *Runner) { n := max(0, remaining); r.remainingRequestBudget = &n }
}

type moduleAllocation struct {
	mu        sync.Mutex
	remaining []int64
	shared    int64
	allocated int64
	used      int64
}

func (b *moduleAllocation) reserve(index int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.remaining[index] > 0 {
		b.remaining[index]--
	} else if b.shared > 0 {
		b.shared--
	} else {
		return fmt.Errorf("request budget exhausted for target allocation; other targets retain their reserved requests")
	}
	b.used++
	return nil
}

func (b *moduleAllocation) release(index int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.shared += b.remaining[index]
	b.remaining[index] = 0
}

// splitBudget is deterministic, conserves the budget, and gives each work item
// one request before distributing weighted shares when the limit allows it.
func splitBudget(total int64, weights []int64) []int64 {
	out := make([]int64, len(weights))
	var sum int64
	active := int64(0)
	for _, w := range weights {
		if w > 0 {
			sum += w
			active++
		}
	}
	if total <= 0 || sum == 0 {
		return out
	}
	if total >= active {
		for i, w := range weights {
			if w > 0 {
				out[i] = 1
			}
		}
		total -= active
	}
	left := total
	for i, w := range weights {
		if w <= 0 {
			continue
		}
		// Floating point avoids overflowing a user-provided int budget.
		fraction := float64(total) * (float64(w) / float64(sum))
		share := left
		if fraction < float64(left) {
			share = int64(fraction)
		}
		out[i] += share
		left -= share
	}
	for i := 0; left > 0; i = (i + 1) % len(weights) {
		if weights[i] > 0 {
			out[i]++
			left--
		}
	}
	return out
}

func (r *Runner) allocateModuleBudget(module string, targets []ScanTarget) *moduleAllocation {
	r.adaptiveBudgetMu.Lock()
	defer r.adaptiveBudgetMu.Unlock()
	urls := map[string]bool{}
	for _, t := range targets {
		if r.scope == nil || r.scope.IsInScope(t.EndpointURL) {
			urls[budgetEndpointKey(t)] = true
		}
	}
	if r.remainingRequestBudget == nil && r.cfg.RequestBudget == 0 && r.cfg.RequestsPerTarget == 0 {
		return nil
	}
	if r.adaptiveBudget == nil {
		n := r.cfg.EffectiveRequestBudget(len(urls))
		if r.remainingRequestBudget != nil {
			n = *r.remainingRequestBudget
		}
		r.adaptiveBudget = &adaptiveScanBudget{remaining: int64(n), derivedURLs: len(urls), completed: map[string]bool{}}
	} else if r.remainingRequestBudget == nil && r.cfg.RequestBudget == 0 && len(urls) > r.adaptiveBudget.derivedURLs {
		// Newly discovered URLs expand only an explicitly URL-derived budget.
		old := r.cfg.EffectiveRequestBudget(r.adaptiveBudget.derivedURLs)
		r.adaptiveBudget.remaining += int64(r.cfg.EffectiveRequestBudget(len(urls)) - old)
		r.adaptiveBudget.derivedURLs = len(urls)
	}
	plan := r.adaptiveBudget
	names := ModuleCatalog()
	if !containsModuleName(names, module) {
		names = append(names, module)
		sort.Strings(names)
	}
	weights := make([]int64, len(names))
	current := 0
	for i, name := range names {
		if name == module {
			current = i
		}
		if !r.cfg.AllowsModule(name) || plan.completed[name] && name != module {
			continue
		}
		for _, target := range targets {
			if r.budgetEligible(name, target) {
				weights[i] += estimatedTargetRequests(name, target)
			}
		}
	}
	shares := splitBudget(plan.remaining, weights)
	amount := shares[current]
	plan.remaining -= amount
	// Reserve equally across URLs, then split each URL's share across its
	// parameters. A URL with many parameters cannot consume all other URLs.
	groups := map[string][]int{}
	var keys []string
	for i, t := range targets {
		if !r.budgetEligible(module, t) {
			continue
		}
		key := budgetEndpointKey(t)
		if _, ok := groups[key]; !ok {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], i)
	}
	urlWeights := make([]int64, len(keys))
	for i := range urlWeights {
		urlWeights[i] = 1
	}
	urlShares := splitBudget(amount, urlWeights)
	b := &moduleAllocation{remaining: make([]int64, len(targets)), allocated: amount}
	for i, key := range keys {
		indices := groups[key]
		targetWeights := make([]int64, len(indices))
		for j, index := range indices {
			targetWeights[j] = estimatedTargetRequests(module, targets[index])
		}
		for j, share := range splitBudget(urlShares[i], targetWeights) {
			b.remaining[indices[j]] = share
		}
	}
	return b
}

func containsModuleName(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

func (r *Runner) finishModuleBudget(module string, b *moduleAllocation) {
	if b == nil {
		return
	}
	r.adaptiveBudgetMu.Lock()
	defer r.adaptiveBudgetMu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	r.adaptiveBudget.remaining += b.allocated - b.used
	r.adaptiveBudget.completed[module] = true
}
