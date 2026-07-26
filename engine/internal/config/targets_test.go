package config

import "testing"

func TestNormalizeTargets(t *testing.T) {
	got, err := NormalizeTargets([]string{"domain.com", "https://domain.com/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "https://domain.com/" {
		t.Fatalf("got %#v", got)
	}
}

func TestNormalizeTargetURLRejectsEmpty(t *testing.T) {
	if _, err := NormalizeTargetURL("  "); err == nil {
		t.Fatal("expected error")
	}
}
