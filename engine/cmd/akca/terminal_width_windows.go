//go:build windows

package main

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
)

func terminalColumns(file *os.File) int {
	if file != nil {
		var info windows.ConsoleScreenBufferInfo
		if err := windows.GetConsoleScreenBufferInfo(windows.Handle(file.Fd()), &info); err == nil {
			width := int(info.Window.Right-info.Window.Left) + 1
			if width > 0 {
				return width
			}
		}
	}
	width, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("COLUMNS")))
	return width
}

func enableVirtualTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	handle := windows.Handle(file.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	const enableVirtualTerminalProcessing = 0x0004
	if mode&enableVirtualTerminalProcessing != 0 {
		return true
	}
	return windows.SetConsoleMode(handle, mode|enableVirtualTerminalProcessing) == nil
}
