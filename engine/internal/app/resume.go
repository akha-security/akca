package app

import (
	"encoding/json"

	"github.com/akha-security/akca/engine/internal/config"
)

func (e *Engine) ResumeScan(input CommandInput) error {
	e.mu.Lock()
	if e.scanning {
		e.mu.Unlock()
		return errScanRunning
	}
	if e.platform == nil {
		e.initPlatform(platformDataDir())
	}
	cfg := e.session.Config
	scanID := cfg.ScanID
	if scanID == "" {
		scanID = e.session.ID
	}
	plat := e.platform
	e.mu.Unlock()

	// Allow the caller to specify which scan to resume.
	if len(input.Config) > 0 {
		var override config.ScanConfig
		if json.Unmarshal(input.Config, &override) == nil && override.ScanID != "" {
			scanID = override.ScanID
		}
	}

	st, ok, err := plat.checkpoint.Latest(scanID)
	if err != nil {
		return err
	}
	if !ok {
		// Nothing to resume from; run a fresh scan with whatever config we have.
		if len(input.Config) > 0 {
			_ = json.Unmarshal(input.Config, &cfg)
		}
		cfg.ScanID = scanID
		return e.startScan(cfg, nil)
	}

	// Restore the full scan configuration captured in the checkpoint so targets
	// and scope survive an engine restart, then overlay any caller overrides.
	if len(st.Config) > 0 {
		var saved config.ScanConfig
		if json.Unmarshal(st.Config, &saved) == nil {
			cfg = saved
		}
	}
	if len(input.Config) > 0 {
		_ = json.Unmarshal(input.Config, &cfg)
	}
	cfg.ScanID = scanID

	completed := map[string]bool{}
	for _, p := range st.Completed {
		completed[p] = true
	}
	_ = e.Emit("scan_resumed", "resuming from checkpoint", map[string]interface{}{
		"scan_id":   scanID,
		"phase":     plat.checkpoint.ResumeFromPhase(st),
		"completed": st.Completed,
	})
	return e.startScan(cfg, completed)
}
