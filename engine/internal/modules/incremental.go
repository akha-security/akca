package modules

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

func completedWorkKey(t ScanTarget) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join([]string{t.EndpointURL, t.Method, t.Parameter, t.Location, t.BodyTemplate, t.RequestTemplate.Body}, "\x00"))))
}

func (r *Runner) markCompletedWork(module string, t ScanTarget) {
	r.completedWorkMu.Lock()
	defer r.completedWorkMu.Unlock()
	if r.completedWork == nil {
		r.completedWork = map[string]map[string]bool{}
	}
	if r.completedWork[module] == nil {
		r.completedWork[module] = map[string]bool{}
	}
	r.completedWork[module][completedWorkKey(t)] = true
}

func (r *Runner) PendingTargets(module string, targets []ScanTarget) []ScanTarget {
	if module == "php2shell" && !r.cfg.OnlyPHP2Shell() {
		targets = r.php2ShellFullScanTargets(targets)
	}
	r.completedWorkMu.Lock()
	defer r.completedWorkMu.Unlock()
	out := make([]ScanTarget, 0, len(targets))
	seen := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		key := completedWorkKey(t)
		if r.completedWork[module][key] {
			continue
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, t)
	}
	return out
}

// HasRunnableTargets avoids showing a follow-up module phase when newly
// discovered URLs contain only static resources or no mutation surface.
func (r *Runner) HasRunnableTargets(module string, targets []ScanTarget) bool {
	for _, target := range targets {
		if r.budgetEligible(module, target) {
			return true
		}
	}
	return false
}

func (r *Runner) CompletedWork() map[string]map[string]bool {
	r.completedWorkMu.Lock()
	defer r.completedWorkMu.Unlock()
	out := map[string]map[string]bool{}
	for module, entries := range r.completedWork {
		out[module] = map[string]bool{}
		for key, value := range entries {
			out[module][key] = value
		}
	}
	return out
}

func (r *Runner) RestoreCompletedWork(work map[string]map[string]bool) {
	r.completedWorkMu.Lock()
	defer r.completedWorkMu.Unlock()
	r.completedWork = work
}
