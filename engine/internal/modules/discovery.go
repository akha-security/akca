package modules

import "strings"

func (r *Runner) privateCanary(module string, target ScanTarget) string {
	for _, p := range r.cfg.ContentProofPolicies {
		if p.Module == module && p.URLContains != "" && strings.Contains(target.EndpointURL, p.URLContains) && len(strings.TrimSpace(p.PrivateCanary)) >= 12 {
			return p.PrivateCanary
		}
	}
	return ""
}

// emitDiscovery preserves observed capabilities without claiming a security
// boundary was crossed. These events remain available in the scan timeline.
func (r *Runner) emitDiscovery(module string, target ScanTarget, signal, message string) {
	if r.emit != nil {
		_ = r.emit("module_discovery", message, map[string]interface{}{
			"scan_id": r.scanID, "module": module, "endpoint": target.EndpointURL,
			"method": target.Method, "parameter": target.Parameter, "location": target.Location,
			"signal": signal, "verification_status": "unproven",
		})
	}
}
