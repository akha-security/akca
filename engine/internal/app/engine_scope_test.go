package app

import (
	"reflect"
	"testing"

	"github.com/akha-security/akca/engine/internal/events"
	"github.com/akha-security/akca/engine/internal/storage"
)

type noopWriter struct{}

func (noopWriter) WriteEvent(events.Event) error { return nil }

func TestDeriveIncludeDomainsExactHost(t *testing.T) {
	got := deriveIncludeDomains([]string{"https://app.example.com"})
	if len(got) != 1 || got[0] != "app.example.com" {
		t.Fatalf("expected [app.example.com], got %v", got)
	}
}

func TestDeriveIncludeDomainsDedup(t *testing.T) {
	got := deriveIncludeDomains([]string{"app.example.com", "https://app.example.com"})
	if len(got) != 1 || got[0] != "app.example.com" {
		t.Fatalf("expected single exact host app.example.com, got %v", got)
	}
}

func TestUniqueURLSeedsAddsSiteRootForDeepLink(t *testing.T) {
	got := uniqueURLSeeds([]string{"https://example.test/ssti"})
	want := []string{
		"https://example.test/ssti",
		"https://example.test/",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("crawl seeds = %v, want %v", got, want)
	}
}

func TestUniqueURLSeedsDeduplicatesSharedSiteRoot(t *testing.T) {
	got := uniqueURLSeeds([]string{
		"https://example.com/ssti?name=test",
		"https://example.com/xss",
		"https://example.com/",
	})
	want := []string{
		"https://example.com/ssti?name=test",
		"https://example.com/",
		"https://example.com/xss",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("crawl seeds = %v, want %v", got, want)
	}
}

func TestNewDoesNotStartDefaultOAST(t *testing.T) {
	storage.SetDataDirOverride(t.TempDir())
	e, err := New(noopWriter{})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.oast != nil {
		t.Fatal("engine constructor should not start OAST before scan config is applied")
	}
}
