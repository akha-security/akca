//go:build linux

package app

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func memoryCapacityBytes() (uint64, uint64, string, error) {
	hostTotal, hostAvailable, err := linuxMemoryCapacity()
	if err != nil {
		return 0, 0, "linux", err
	}
	containerTotal, containerAvailable := linuxCgroupCapacity()
	if containerTotal > 0 && containerAvailable > 0 && containerTotal < hostTotal {
		return containerTotal, containerAvailable, "linux_cgroup", nil
	}
	return hostTotal, hostAvailable, "linux", nil
}

func processMemoryBytes() (uint64, error) {
	raw, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return 0, fmt.Errorf("/proc/self/statm has no resident-set field")
	}
	residentPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, err
	}
	return residentPages * uint64(os.Getpagesize()), nil
}

func linuxMemoryCapacity() (uint64, uint64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	var total, available uint64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		kb, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = kb * 1024
		case "MemAvailable:":
			available = kb * 1024
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	if total == 0 || available == 0 {
		return 0, 0, fmt.Errorf("MemTotal or MemAvailable not found in /proc/meminfo")
	}
	return total, available, nil
}

func linuxCgroupCapacity() (uint64, uint64) {
	for _, pair := range [][2]string{
		{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current"},
		{"/sys/fs/cgroup/memory/memory.limit_in_bytes", "/sys/fs/cgroup/memory/memory.usage_in_bytes"},
	} {
		limit, limitOK := readMemoryNumber(pair[0])
		used, usedOK := readMemoryNumber(pair[1])
		if limitOK && usedOK && limit > used {
			return limit, limit - used
		}
	}
	return 0, 0
}

func readMemoryNumber(path string) (uint64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	value := strings.TrimSpace(string(raw))
	if value == "" || value == "max" {
		return 0, false
	}
	number, err := strconv.ParseUint(value, 10, 64)
	return number, err == nil
}
