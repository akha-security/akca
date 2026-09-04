//go:build !windows

package app

func preventSleep() {}
func restoreSleep() {}
