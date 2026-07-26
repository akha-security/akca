package cve

import (
	"regexp"
	"strconv"
	"strings"
)

type CatalogEntry struct {
	CVEID            string   `json:"cve_id"`
	Vendor           string   `json:"vendor"`
	Product          string   `json:"product"`
	CPE              string   `json:"cpe"`
	AffectedVersions []string `json:"affected_versions"`
	Severity         string   `json:"severity"`
}

// EmbeddedSnapshot is a minimal local NVD/OSV-style catalog for safe version matching.
var EmbeddedSnapshot = []CatalogEntry{
	{CVEID: "CVE-2021-44228", Vendor: "apache", Product: "log4j", CPE: "cpe:2.3:a:apache:log4j", AffectedVersions: []string{"2.0.0-2.14.1"}, Severity: "Critical"},
	{CVEID: "CVE-2017-5638", Vendor: "apache", Product: "struts2", CPE: "cpe:2.3:a:apache:struts", AffectedVersions: []string{"2.3.5-2.3.31"}, Severity: "Critical"},
	{CVEID: "CVE-2014-0160", Vendor: "openssl", Product: "openssl", CPE: "cpe:2.3:a:openssl:openssl", AffectedVersions: []string{"1.0.1-1.0.1f"}, Severity: "High"},
	{CVEID: "CVE-2023-44487", Vendor: "nghttp2", Product: "nghttp2", CPE: "cpe:2.3:a:nghttp2:nghttp2", AffectedVersions: []string{"<1.57.0"}, Severity: "High"},
	{CVEID: "CVE-2019-11043", Vendor: "php", Product: "php-fpm", CPE: "cpe:2.3:a:php:php", AffectedVersions: []string{"7.1.0-7.1.32", "7.2.0-7.2.23", "7.3.0-7.3.10"}, Severity: "Critical"},
}

func MatchComponent(vendor, product, version string) []CatalogEntry {
	var out []CatalogEntry
	v := strings.ToLower(strings.TrimSpace(vendor))
	p := strings.ToLower(strings.TrimSpace(product))
	ver := strings.ToLower(strings.TrimSpace(version))
	for _, e := range EmbeddedSnapshot {
		if v != "" && !strings.Contains(strings.ToLower(e.Vendor), v) && !strings.Contains(v, strings.ToLower(e.Vendor)) {
			continue
		}
		if p != "" && !strings.Contains(strings.ToLower(e.Product), p) && !strings.Contains(p, strings.ToLower(e.Product)) {
			continue
		}
		if ver != "" && versionMatches(ver, e.AffectedVersions) {
			out = append(out, e)
		}
	}
	return out
}

func MatchCPE(cpe, version string) []CatalogEntry {
	var out []CatalogEntry
	lower := strings.ToLower(cpe)
	for _, e := range EmbeddedSnapshot {
		if strings.Contains(lower, strings.ToLower(e.Vendor)) && strings.Contains(lower, strings.ToLower(e.Product)) {
			if version == "" || versionMatches(version, e.AffectedVersions) {
				out = append(out, e)
			}
		}
	}
	return out
}

func versionMatches(version string, ranges []string) bool {
	v := normalizeVersion(version)
	if v == "" || v == "unknown" {
		return false
	}
	for _, constraint := range ranges {
		constraint = strings.ToLower(strings.TrimSpace(constraint))
		if constraint == "" {
			continue
		}
		if versionSatisfies(v, constraint) {
			return true
		}
	}
	return false
}

var versionRangePattern = regexp.MustCompile(`^([0-9][0-9a-z._+]*)\s*-\s*([0-9][0-9a-z._+]*)$`)

func versionSatisfies(version, constraint string) bool {
	for _, operator := range []string{"<=", ">=", "<", ">", "="} {
		if strings.HasPrefix(constraint, operator) {
			other := normalizeVersion(strings.TrimSpace(strings.TrimPrefix(constraint, operator)))
			cmp := compareVersions(version, other)
			switch operator {
			case "<=":
				return cmp <= 0
			case ">=":
				return cmp >= 0
			case "<":
				return cmp < 0
			case ">":
				return cmp > 0
			case "=":
				return cmp == 0
			}
		}
	}
	if match := versionRangePattern.FindStringSubmatch(constraint); len(match) == 3 {
		return compareVersions(version, normalizeVersion(match[1])) >= 0 &&
			compareVersions(version, normalizeVersion(match[2])) <= 0
	}
	if strings.Contains(constraint, "x") || strings.Contains(constraint, "*") {
		prefix := strings.TrimRight(strings.ReplaceAll(constraint, "*", "x"), ".x")
		return version == prefix || strings.HasPrefix(version, prefix+".")
	}
	return compareVersions(version, normalizeVersion(constraint)) == 0
}

func normalizeVersion(version string) string {
	version = strings.ToLower(strings.TrimSpace(version))
	version = strings.TrimPrefix(version, "v")
	if index := strings.IndexAny(version, "+ "); index >= 0 {
		version = version[:index]
	}
	return strings.TrimSpace(version)
}

var versionTokenPattern = regexp.MustCompile(`[0-9]+|[a-z]+`)

func compareVersions(left, right string) int {
	lTokens := versionTokenPattern.FindAllString(normalizeVersion(left), -1)
	rTokens := versionTokenPattern.FindAllString(normalizeVersion(right), -1)
	max := len(lTokens)
	if len(rTokens) > max {
		max = len(rTokens)
	}
	for i := 0; i < max; i++ {
		l, r := "", ""
		if i < len(lTokens) {
			l = lTokens[i]
		}
		if i < len(rTokens) {
			r = rTokens[i]
		}
		if l == r {
			continue
		}
		ln, lErr := strconv.Atoi(l)
		rn, rErr := strconv.Atoi(r)
		if l == "" && rErr == nil {
			ln, lErr = 0, nil
		}
		if r == "" && lErr == nil {
			rn, rErr = 0, nil
		}
		if lErr == nil && rErr == nil {
			if ln < rn {
				return -1
			}
			if ln > rn {
				return 1
			}
			continue
		}
		if l == "" {
			return -1
		}
		if r == "" {
			return 1
		}
		if l < r {
			return -1
		}
		return 1
	}
	return 0
}
