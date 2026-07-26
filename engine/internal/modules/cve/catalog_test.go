package cve_test

import (
	"testing"

	"github.com/akha-security/akca/engine/internal/modules/cve"
)

func TestMatchComponentLog4j(t *testing.T) {
	matches := cve.MatchComponent("apache", "log4j", "2.14.1")
	if len(matches) == 0 {
		t.Fatal("expected CVE match for log4j")
	}
	if matches[0].CVEID != "CVE-2021-44228" {
		t.Fatalf("unexpected cve: %s", matches[0].CVEID)
	}
}

func TestMatchCPE(t *testing.T) {
	matches := cve.MatchCPE("cpe:2.3:a:openssl:openssl:1.0.1", "1.0.1")
	if len(matches) == 0 {
		t.Fatal("expected openssl CVE match")
	}
}

func TestVersionRangesDoNotMatchUnaffectedVersions(t *testing.T) {
	for _, tc := range []struct {
		vendor, product, version string
	}{
		{"apache", "log4j", "2.15.0"},
		{"apache", "log4j", "1.2.17"},
		{"openssl", "openssl", "1.0.1g"},
		{"nghttp2", "nghttp2", "1.57.0"},
		{"php", "php-fpm", "7.3.11"},
	} {
		if matches := cve.MatchComponent(tc.vendor, tc.product, tc.version); len(matches) != 0 {
			t.Fatalf("%s %s should not match, got %#v", tc.product, tc.version, matches)
		}
	}
}

func TestVersionRangesMatchInteriorVersions(t *testing.T) {
	for _, tc := range []struct {
		vendor, product, version string
	}{
		{"apache", "log4j", "2.12.4"},
		{"apache", "struts2", "2.3.20"},
		{"openssl", "openssl", "1.0.1f"},
		{"nghttp2", "nghttp2", "1.56.0"},
		{"php", "php-fpm", "7.2.10"},
	} {
		if matches := cve.MatchComponent(tc.vendor, tc.product, tc.version); len(matches) == 0 {
			t.Fatalf("%s %s should match an affected range", tc.product, tc.version)
		}
	}
}
