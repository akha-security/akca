//go:build linux

package app

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func availableMemoryBytes() (uint64, string, error) {
	hostAvailable, err := linuxMemAvailable()
	if err != nil {
		return 0, "linux", err
	}
	containerAvailable := linuxCgroupAvailable()
	if containerAvailable > 0 && containerAvailable < hostAvailable {
		return containerAvailable, "linux_cgroup", nil
	}
	return hostAvailable, "linux_available", nil
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

func linuxMemAvailable() (uint64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "MemAvailable:" {
			kb, parseErr := strconv.ParseUint(fields[1], 10, 64)
			if parseErr != nil {
				return 0, parseErr
			}
			return kb * 1024, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("MemAvailable not found in /proc/meminfo")
}

func linuxCgroupAvailable() uint64 {
	for _, pair := range [][2]string{
		{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory.current"},
		{"/sys/fs/cgroup/memory/memory.limit_in_bytes", "/sys/fs/cgroup/memory/memory.usage_in_bytes"},
	} {
		limit, limitOK := readMemoryNumber(pair[0])
		used, usedOK := readMemoryNumber(pair[1])
		if limitOK && usedOK && limit > used {
			return limit - used
		}
	}
	return 0
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
