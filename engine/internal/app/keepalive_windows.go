//go:build windows

package app

import "syscall"

const (
	esContinuous       = 0x80000000
	esSystemRequired   = 0x00000001
	esAwayModeRequired = 0x00000040
)

var (
	kernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procSetThreadExecutionState = kernel32.NewProc("SetThreadExecutionState")
)

// preventSleep tells the Windows kernel to prevent system sleep and power throttling
// while a critical long-running security scan is executing.
func preventSleep() {
	_, _, _ = procSetThreadExecutionState.Call(uintptr(esContinuous | esSystemRequired | esAwayModeRequired))
}

// restoreSleep resets the Windows execution state to allow normal sleep.
func restoreSleep() {
	_, _, _ = procSetThreadExecutionState.Call(uintptr(esContinuous))
}
