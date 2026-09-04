package app

const (
	bytesPerMiB          = uint64(1024 * 1024)
	autoMemoryPercent    = uint64(60)
	autoMemoryFloorMB    = 256
	autoMemoryCapMB      = 32 * 1024
	autoMemoryFallbackMB = 1024
)

// resolveMemoryLimitMB returns a manual limit unchanged or derives a safe Go
// heap ceiling from memory currently available to the host/container.
func resolveMemoryLimitMB(configuredMB int) (limitMB int, source string, availableMB int) {
	if configuredMB > 0 {
		return configuredMB, "manual", 0
	}
	availableBytes, detectedSource, err := availableMemoryBytes()
	if err != nil || availableBytes == 0 {
		return autoMemoryFallbackMB, "automatic_fallback", 0
	}
	availableMB = int(availableBytes / bytesPerMiB)
	limitMB = automaticLimitForAvailableBytes(availableBytes)
	return limitMB, "automatic_" + detectedSource, availableMB
}

func automaticLimitForAvailableBytes(availableBytes uint64) int {
	availableMB := int(availableBytes / bytesPerMiB)
	limitMB := int((availableBytes * autoMemoryPercent / 100) / bytesPerMiB)
	if limitMB < autoMemoryFloorMB {
		// Never claim more than 60% of genuinely scarce memory.
		if availableMB*int(autoMemoryPercent)/100 < autoMemoryFloorMB {
			limitMB = availableMB * int(autoMemoryPercent) / 100
		} else {
			limitMB = autoMemoryFloorMB
		}
	}
	if limitMB < 64 {
		limitMB = 64
		if scarceLimit := availableMB * int(autoMemoryPercent) / 100; scarceLimit > 0 && limitMB > scarceLimit {
			limitMB = scarceLimit
		}
	}
	if limitMB > autoMemoryCapMB {
		limitMB = autoMemoryCapMB
	}
	return limitMB
}
