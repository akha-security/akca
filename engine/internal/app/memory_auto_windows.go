//go:build windows

package app

import (
	"fmt"
	"syscall"
	"unsafe"
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

var globalMemoryStatusEx = syscall.NewLazyDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")
var getCurrentProcess = syscall.NewLazyDLL("kernel32.dll").NewProc("GetCurrentProcess")
var getProcessMemoryInfo = syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo")

type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func availableMemoryBytes() (uint64, string, error) {
	status := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	ok, _, callErr := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status)))
	if ok == 0 {
		return 0, "windows", fmt.Errorf("GlobalMemoryStatusEx: %v", callErr)
	}
	if status.AvailPhys == 0 {
		return 0, "windows", fmt.Errorf("GlobalMemoryStatusEx returned zero available memory")
	}
	return status.AvailPhys, "windows_available", nil
}

func processMemoryBytes() (uint64, error) {
	counters := processMemoryCounters{CB: uint32(unsafe.Sizeof(processMemoryCounters{}))}
	handle, _, _ := getCurrentProcess.Call()
	ok, _, callErr := getProcessMemoryInfo.Call(handle, uintptr(unsafe.Pointer(&counters)), uintptr(counters.CB))
	if ok == 0 {
		return 0, fmt.Errorf("GetProcessMemoryInfo: %v", callErr)
	}
	return uint64(counters.WorkingSetSize), nil
}
