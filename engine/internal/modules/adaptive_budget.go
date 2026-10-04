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
	case "backup_archives":
		n = 1_500 // one origin dictionary plus route-derived candidates
	case "sensitive_file_discovery":
		n = 32 // root/prefix wildcard plus fingerprinted paths
	case "prototype_pollution":
		n = 13 // server family or one baseline plus two browser replays per family
	case "cookie_security":
		n = 1 // passive header analysis of one concrete response
	}
	if generated := len(payloadsForClass(target.Payloads.Payloads, module)); generated > 0 && generated+10 > n {
		n = generated + 10
	}
	return int64(n)
}

// budgetWorkKey represents the security-relevant work unit, rather than the
// raw parameter row loaded from discovery. This prevents origin and route
// modules from receiving (and appearing to need) one allocation per parameter.
func budgetWorkKey(module string, t ScanTarget) string {
	parsed, err := url.Parse(t.EndpointURL)
	if err != nil {
		return module + "::" + budgetEndpointKey(t) + "::" + t.Parameter + "::" + t.Location
	}
	parsed.Fragment = ""
	method := strings.ToUpper(strings.TrimSpace(t.Method))
	if method == "" {
		method = "GET"
	}
	if originScopedModule(module) {
		return module + "::" + parsed.Scheme + "://" + parsed.Host
	}
	if routePrefixScopedModule(module) {
		return module + "::" + parsed.Scheme + "://" + parsed.Host + firstRoutePrefix(parsed.Path)
	}
	switch module {
	case "cookie_security", "sensitive_data", "secret_exposure", "script_source":
		return module + "::" + method + "::" + parsed.String()
	case "prototype_pollution":
		if clientPrototypeEligible(t) {
			return module + "::browser::" + clientPrototypeWorkKey(t.EndpointURL)
		}
	}
	return module + "::" + method + "::" + parsed.String() + "::" + t.Parameter + "::" + t.Location
}

// budgetReservationKey keeps endpoint fairness for parameterized injection
// modules, while modules already deduplicated at origin/prefix/content level
// reserve exactly once for that coarser work item.
func budgetReservationKey(module string, t ScanTarget) string {
	if pooledOriginBudgetModule(module) {
		if parsed, err := url.Parse(t.EndpointURL); err == nil {
			return module + "::" + parsed.Scheme + "://" + parsed.Host
		}
	}
	switch module {
	case "cookie_security", "sensitive_data", "secret_exposure", "script_source":
		return budgetWorkKey(module, t)
	case "prototype_pollution":
		if clientPrototypeEligible(t) {
			return budgetWorkKey(module, t)
		}
	}
	if originScopedModule(module) || routePrefixScopedModule(module) {
		return budgetWorkKey(module, t)
	}
	return module + "::" + budgetEndpointKey(t)
}

func pooledOriginBudgetModule(module string) bool {
	return module == "backup_archives" || module == "sensitive_file_discovery"
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
	mu          sync.Mutex
	remaining   []int64
	targetGroup []int
	groupRefs   []int
	shared      int64
	allocated   int64
	used        int64
}

func (b *moduleAllocation) reserve(index int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	group := -1
	if index >= 0 && index < len(b.targetGroup) {
		group = b.targetGroup[index]
	}
	if group >= 0 && group < len(b.remaining) && b.remaining[group] > 0 {
		b.remaining[group]--
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
	if index < 0 || index >= len(b.targetGroup) {
		return
	}
	group := b.targetGroup[index]
	if group < 0 || group >= len(b.groupRefs) || b.groupRefs[group] <= 0 {
		return
	}
	b.groupRefs[group]--
	// Duplicate parameter rows can map to one security-relevant work item.
	// Release that item's unused reserve only after every row sharing it has
	// finished, so the row which wins the once-guard cannot lose its budget.
	if b.groupRefs[group] == 0 {
		b.shared += b.remaining[group]
		b.remaining[group] = 0
	}
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
		seenWork := make(map[string]struct{})
		for _, target := range targets {
			if r.budgetEligible(name, target) {
				key := budgetWorkKey(name, target)
				if pooledOriginBudgetModule(name) {
					key = budgetReservationKey(name, target)
				}
				if _, exists := seenWork[key]; exists {
					continue
				}
				seenWork[key] = struct{}{}
				weights[i] += estimatedTargetRequests(name, target)
			}
		}
	}
	shares := splitBudget(plan.remaining, weights)
	amount := shares[current]
	plan.remaining -= amount
	// Reserve directly for security-relevant work items. Origin/prefix/content
	// modules often receive many duplicate parameter rows; every such row maps
	// to the same shared reserve, so whichever worker wins the once-guard can
	// perform the complete work without multiplying its allocation.
	workTargets := map[string][]int{}
	var workKeys []string
	for i, t := range targets {
		if !r.budgetEligible(module, t) {
			continue
		}
		key := budgetWorkKey(module, t)
		if _, ok := workTargets[key]; !ok {
			workKeys = append(workKeys, key)
		}
		workTargets[key] = append(workTargets[key], i)
	}
	workWeights := make([]int64, len(workKeys))
	reservationGroups := map[string][]int{}
	var reservationKeys []string
	for i, key := range workKeys {
		for _, index := range workTargets[key] {
			workWeights[i] = max(workWeights[i], estimatedTargetRequests(module, targets[index]))
		}
		reservationKey := budgetReservationKey(module, targets[workTargets[key][0]])
		if _, ok := reservationGroups[reservationKey]; !ok {
			reservationKeys = append(reservationKeys, reservationKey)
		}
		reservationGroups[reservationKey] = append(reservationGroups[reservationKey], i)
	}
	reservationWeights := make([]int64, len(reservationKeys))
	for i := range reservationWeights {
		reservationWeights[i] = 1
	}
	reservationShares := splitBudget(amount, reservationWeights)
	workShares := make([]int64, len(workKeys))
	for i, reservationKey := range reservationKeys {
		workIndices := reservationGroups[reservationKey]
		weights := make([]int64, len(workIndices))
		for j, workIndex := range workIndices {
			weights[j] = workWeights[workIndex]
		}
		for j, share := range splitBudget(reservationShares[i], weights) {
			workShares[workIndices[j]] = share
		}
	}
	remaining := workShares
	groupCount := len(workKeys)
	if pooledOriginBudgetModule(module) {
		remaining = reservationShares
		groupCount = len(reservationKeys)
	}
	b := &moduleAllocation{
		remaining:   remaining,
		targetGroup: make([]int, len(targets)),
		groupRefs:   make([]int, groupCount),
		allocated:   amount,
	}
	for i := range b.targetGroup {
		b.targetGroup[i] = -1
	}
	if pooledOriginBudgetModule(module) {
		for group, reservationKey := range reservationKeys {
			for _, workIndex := range reservationGroups[reservationKey] {
				for _, index := range workTargets[workKeys[workIndex]] {
					b.targetGroup[index] = group
					b.groupRefs[group]++
				}
			}
		}
	} else {
		for i, key := range workKeys {
			b.groupRefs[i] = len(workTargets[key])
			for _, index := range workTargets[key] {
				b.targetGroup[index] = i
			}
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
