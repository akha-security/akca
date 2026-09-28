package cve

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type CatalogEntry struct {
	CVEID            string   `json:"cve_id"`
	Vendor           string   `json:"vendor"`
	Product          string   `json:"product"`
	CPE              string   `json:"cpe"`
	AffectedVersions []string `json:"affected_versions"`
	Severity         string   `json:"severity"`
	Source           string   `json:"source"`
	Published        string   `json:"published,omitempty"`
	Modified         string   `json:"modified,omitempty"`
	Status           string   `json:"status"`
}

const (
	// EmbeddedSnapshotVersion is intentionally date based. It is surfaced in
	// scan events and reports so a stale offline catalog can never look current.
	EmbeddedSnapshotVersion = "nvd-curated-2026-09-27"
	EmbeddedSnapshotDate    = "2026-09-27"
)

// EmbeddedSnapshot is a deliberately small, curated offline fallback. Entries
// must be traceable to a published primary/NVD record and are validated at
// startup. The online rule-pack path may add records, but it must never weaken
// the vendor/product/version checks performed here.
var EmbeddedSnapshot = []CatalogEntry{
	{CVEID: "CVE-2021-44228", Vendor: "apache", Product: "log4j", CPE: "cpe:2.3:a:apache:log4j", AffectedVersions: []string{"2.0.0-2.14.1"}, Severity: "Critical", Source: "NVD", Published: "2021-12-10", Status: "published"},
	{CVEID: "CVE-2017-5638", Vendor: "apache", Product: "struts2", CPE: "cpe:2.3:a:apache:struts", AffectedVersions: []string{"2.3.5-2.3.31", "2.5.0-2.5.10.1"}, Severity: "Critical", Source: "NVD", Published: "2017-03-11", Status: "published"},
	{CVEID: "CVE-2014-0160", Vendor: "openssl", Product: "openssl", CPE: "cpe:2.3:a:openssl:openssl", AffectedVersions: []string{"1.0.1-1.0.1f"}, Severity: "High", Source: "NVD", Published: "2014-04-07", Status: "published"},
	{CVEID: "CVE-2023-44487", Vendor: "nghttp2", Product: "nghttp2", CPE: "cpe:2.3:a:nghttp2:nghttp2", AffectedVersions: []string{"<1.57.0"}, Severity: "High", Source: "NVD", Published: "2023-10-10", Status: "published"},
	{CVEID: "CVE-2019-11043", Vendor: "php", Product: "php-fpm", CPE: "cpe:2.3:a:php:php", AffectedVersions: []string{"7.1.0-7.1.32", "7.2.0-7.2.23", "7.3.0-7.3.10"}, Severity: "Critical", Source: "NVD", Published: "2019-10-28", Status: "published"},
	{CVEID: "CVE-2025-55182", Vendor: "facebook", Product: "react-server-dom", CPE: "cpe:2.3:a:facebook:react", AffectedVersions: []string{"19.0.0", "19.1.0-19.1.1", "19.2.0"}, Severity: "Critical", Source: "NVD", Published: "2025-12-03", Modified: "2026-08-04", Status: "published"},
	{CVEID: "CVE-2025-55182", Vendor: "vercel", Product: "nextjs", CPE: "cpe:2.3:a:vercel:next.js", AffectedVersions: []string{"15.0.0-15.0.4", "15.1.0-15.1.8", "15.2.0-15.2.5", "15.3.0-15.3.5", "15.4.0-15.4.7", "15.5.0-15.5.6", "16.0.0-16.0.6"}, Severity: "Critical", Source: "NVD", Published: "2025-12-03", Modified: "2026-08-04", Status: "published"},
	{CVEID: "CVE-2026-49975", Vendor: "apache", Product: "http_server", CPE: "cpe:2.3:a:apache:http_server", AffectedVersions: []string{"2.4.17-2.4.67"}, Severity: "High", Source: "NVD", Published: "2026-06-08", Status: "published"},
}

var cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// ValidateCatalog rejects data mistakes before they can become findings. CVE
// data is security-sensitive input; duplicate product bindings and malformed
// dates/ranges must fail closed rather than silently matching every version.
func ValidateCatalog(entries []CatalogEntry) error {
	seen := make(map[string]struct{}, len(entries))
	for index, entry := range entries {
		if !cveIDPattern.MatchString(entry.CVEID) {
			return fmt.Errorf("catalog entry %d has invalid CVE ID %q", index, entry.CVEID)
		}
		if strings.TrimSpace(entry.Vendor) == "" || strings.TrimSpace(entry.Product) == "" || strings.TrimSpace(entry.CPE) == "" {
			return fmt.Errorf("%s has incomplete vendor/product/CPE identity", entry.CVEID)
		}
		if len(entry.AffectedVersions) == 0 {
			return fmt.Errorf("%s %s/%s has no affected version constraint", entry.CVEID, entry.Vendor, entry.Product)
		}
		if !strings.EqualFold(entry.Status, "published") {
			return fmt.Errorf("%s is not a published record", entry.CVEID)
		}
		if strings.TrimSpace(entry.Source) == "" {
			return fmt.Errorf("%s has no provenance", entry.CVEID)
		}
		for _, value := range []string{entry.Published, entry.Modified} {
			if value == "" {
				continue
			}
			if _, err := time.Parse("2006-01-02", value); err != nil {
				return fmt.Errorf("%s has invalid catalog date %q", entry.CVEID, value)
			}
		}
		key := strings.ToLower(strings.Join([]string{entry.CVEID, entry.Vendor, entry.Product, strings.Join(entry.AffectedVersions, ",")}, "|"))
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate catalog binding %s", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func init() {
	if err := ValidateCatalog(EmbeddedSnapshot); err != nil {
		panic("invalid embedded CVE catalog: " + err.Error())
	}
}

// SnapshotAge reports the age of the offline fallback. Consumers should emit
// a warning once it is older than their accepted freshness window.
func SnapshotAge(now time.Time) time.Duration {
	created, err := time.Parse("2006-01-02", EmbeddedSnapshotDate)
	if err != nil || now.Before(created) {
		return 0
	}
	return now.Sub(created)
}

func MatchComponent(vendor, product, version string) []CatalogEntry {
	var out []CatalogEntry
	v, p := normalizeIdentity(vendor, product)
	ver := strings.ToLower(strings.TrimSpace(version))
	if v == "" || p == "" || ver == "" {
		return nil
	}
	for _, e := range EmbeddedSnapshot {
		ev, ep := normalizeIdentity(e.Vendor, e.Product)
		if v != "" && ev != v {
			continue
		}
		if p != "" && ep != p {
			continue
		}
		if ver != "" && versionMatches(ver, e.AffectedVersions) {
			out = append(out, e)
		}
	}
	return out
}

func normalizeIdentity(vendor, product string) (string, string) {
	v := strings.ToLower(strings.TrimSpace(vendor))
	p := strings.ToLower(strings.TrimSpace(product))
	p = strings.NewReplacer(".", "_", "-", "_", " ", "_").Replace(p)
	switch p {
	case "apache", "apache_http_server", "httpd":
		v, p = "apache", "http_server"
	case "struts", "apache_struts", "struts_2":
		v, p = "apache", "struts2"
	case "php_fpm":
		v, p = "php", "php_fpm"
	case "next_js":
		v, p = "vercel", "nextjs"
	case "react_server_dom_webpack", "react_server_dom_turbopack", "react_server_dom_parcel":
		v, p = "facebook", "react_server_dom"
	}
	return v, p
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
