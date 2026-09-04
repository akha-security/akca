//go:build !windows

package main

import (
	"os"
	"strconv"
	"strings"
)

func terminalColumns(_ *os.File) int {
	width, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("COLUMNS")))
	return width
}

func enableVirtualTerminal(_ *os.File) bool { return true }
