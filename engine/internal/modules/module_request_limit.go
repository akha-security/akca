package modules

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

var errModuleHardProbeLimit = errors.New("module hard probe limit reached")

// limitedModuleDo enforces a non-negotiable per-module/per-origin ceiling for
// expensive discovery modules. It deliberately remains active when the scan's
// global request budget is unlimited (Full Scan), because unlimited coverage
// must not mean an unbounded wordlist Cartesian product.
func (r *Runner) limitedModuleDo(
	ctx context.Context,
	module string,
	limit int,
	method string,
	rawURL string,
	body []byte,
	headers map[string]string,
) (httpclient.RequestResponse, error) {
	if limit <= 0 {
		return r.client.Do(ctx, method, rawURL, body, headers)
	}
	if !r.reserveHardModuleProbe(module, limit, rawURL) {
		host := rawURL
		if parsed, err := url.Parse(rawURL); err == nil && parsed.Host != "" {
			host = parsed.Hostname()
		}
		return httpclient.RequestResponse{}, fmt.Errorf("%w for %s on %s (%d)", errModuleHardProbeLimit, module, host, limit)
	}
	return r.client.Do(ctx, method, rawURL, body, headers)
}

func (r *Runner) reserveHardModuleProbe(module string, limit int, rawURL string) bool {
	if limit <= 0 {
		return true
	}
	host := rawURL
	if parsed, err := url.Parse(rawURL); err == nil && parsed.Host != "" {
		host = parsed.Hostname()
	}
	key := module + "::" + host
	r.hardProbeMu.Lock()
	defer r.hardProbeMu.Unlock()
	used := r.hardProbeUsage[key]
	if used >= limit {
		return false
	}
	r.hardProbeUsage[key] = used + 1
	return true
}
