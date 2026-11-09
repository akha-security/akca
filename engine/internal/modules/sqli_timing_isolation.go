package modules

import (
	"context"
	"net/url"
	"strings"
	"sync"
)

type sqliTimingIsolationKey struct{}

// Each timing comparison needs a quiet SQLi request window on its host.
// Ordinary SQLi probes share the gate; a delay/control series holds it
// exclusively so concurrent scanner traffic cannot make controls appear slow.
func (r *Runner) sqliTimingGate(endpoint string) *sync.RWMutex {
	u, err := url.Parse(endpoint)
	key := strings.ToLower(u.Host)
	if err != nil || key == "" {
		key = endpoint
	}
	r.sqliTimingGateMu.Lock()
	defer r.sqliTimingGateMu.Unlock()
	if r.sqliTimingGates == nil {
		r.sqliTimingGates = make(map[string]*sync.RWMutex)
	}
	if r.sqliTimingGates[key] == nil {
		r.sqliTimingGates[key] = &sync.RWMutex{}
	}
	return r.sqliTimingGates[key]
}

func sqliTimingIsolated(ctx context.Context, gate *sync.RWMutex) bool {
	isolated, _ := ctx.Value(sqliTimingIsolationKey{}).(*sync.RWMutex)
	return isolated == gate
}
