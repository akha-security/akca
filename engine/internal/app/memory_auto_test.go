package app

import (
	"strings"
	"testing"
)

func TestResolveMemoryLimitHonorsManualOverride(t *testing.T) {
	limit, source, available, total := resolveMemoryLimitMB(4096)
	if limit != 4096 || source != "manual" || total < available {
		t.Fatalf("manual memory limit was not preserved: limit=%d source=%q available=%d total=%d", limit, source, available, total)
	}
}

func TestAutomaticMemoryLimitScalesAndCaps(t *testing.T) {
	if got := automaticLimitForAvailableBytes(8 * 1024 * bytesPerMiB); got != 4915 {
		t.Fatalf("8 GiB automatic limit = %d MB, want 4915 MB", got)
	}
	if got := automaticLimitForAvailableBytes(64 * 1024 * bytesPerMiB); got != autoMemoryCapMB {
		t.Fatalf("automatic limit cap = %d MB, want %d MB", got, autoMemoryCapMB)
	}
}

func TestAutomaticLimitNeverExceedsSafeShareOnTinySystems(t *testing.T) {
	const availableMB = 32
	got := automaticLimitForAvailableBytes(availableMB * bytesPerMiB)
	if got > availableMB*int(autoMemoryPercent)/100 {
		t.Fatalf("automatic limit %d MB exceeds the safe share of %d MB", got, availableMB)
	}
}

func TestAutomaticMemoryDetectionReturnsUsableLimit(t *testing.T) {
	limit, source, available, total := resolveMemoryLimitMB(0)
	if limit < 64 || !strings.HasPrefix(source, "automatic_") || available <= 0 || total < available {
		t.Fatalf("automatic detection returned limit=%d source=%q available=%d total=%d", limit, source, available, total)
	}
}

func TestProcessMemoryDetectionReturnsUsage(t *testing.T) {
	used, err := processMemoryBytes()
	if err != nil || used == 0 {
		t.Fatalf("process memory detection returned used=%d err=%v", used, err)
	}
}
