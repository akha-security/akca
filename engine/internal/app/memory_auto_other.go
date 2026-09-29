//go:build !windows && !linux

package app

import (
	"fmt"
	"runtime"
)

func memoryCapacityBytes() (uint64, uint64, string, error) {
	return 0, 0, "unsupported", fmt.Errorf("automatic memory detection is unavailable on this platform")
}

func processMemoryBytes() (uint64, error) {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	return memory.Sys, nil
}
