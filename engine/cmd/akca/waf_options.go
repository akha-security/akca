package main

import "github.com/akha-security/akca/engine/internal/config"

func wafPayloadModeForFlags(enabled, disabled, enabledSet, disabledSet bool) config.WAFPayloadMode {
	if enabledSet {
		if enabled {
			return config.WAFPayloadOn
		}
		return config.WAFPayloadOff
	}
	if disabledSet && disabled {
		return config.WAFPayloadOff
	}
	return config.WAFPayloadAuto
}
