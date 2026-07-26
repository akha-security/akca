package deeptraversal

import "testing"

func TestPayloadsCoverage(t *testing.T) {
	payloads := Payloads()
	if len(payloads) < 20 {
		t.Fatalf("expected linux+windows traversal set, got %d", len(payloads))
	}
	win, linux := 0, 0
	for _, p := range payloads {
		if p.OS == "windows" {
			win++
		}
		if p.OS == "linux" {
			linux++
		}
	}
	if win < 10 || linux < 8 {
		t.Fatalf("expected both OS families, win=%d linux=%d", win, linux)
	}
}

func TestMergeBalancedWindowsFirst(t *testing.T) {
	merged := MergeBalanced(
		[]Payload{{OS: "linux", Value: "a"}},
		[]Payload{{OS: "windows", Value: "b"}},
	)
	if len(merged) != 2 || merged[0].OS != "windows" {
		t.Fatalf("expected windows first, got %+v", merged)
	}
}

func TestDetectLinuxPasswd(t *testing.T) {
	if !DetectSignal("root:x:0:0:root:/root:/bin/bash", "welcome", "linux_passwd") {
		t.Fatal("expected linux passwd detection")
	}
}

func TestDetectWindowsHosts(t *testing.T) {
	body := "# Copyright (c) 1993-2009 Microsoft Corp.\r\n127.0.0.1 localhost"
	if !DetectSignal(body, "welcome", "windows_hosts") {
		t.Fatal("expected windows hosts detection")
	}
}

func TestDetectWindowsIni(t *testing.T) {
	body := "[extensions]\nfor 16-bit app support"
	if !DetectSignal(body, "welcome", "windows_ini") {
		t.Fatal("expected win.ini detection")
	}
}

func TestDetectNoFalsePositive(t *testing.T) {
	if DetectSignal("welcome page", "welcome page", "linux_passwd") {
		t.Fatal("expected no signal on identical bodies")
	}
}
