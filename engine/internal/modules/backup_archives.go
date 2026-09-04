package modules

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/akha-security/akca/engine/internal/httpclient"
)

type binaryMagic struct {
	name       string
	magicBytes []byte
}

var archiveMagicSignatures = []binaryMagic{
	{name: "ZIP Archive", magicBytes: parseHex("504B0304")},
	{name: "7z Archive", magicBytes: parseHex("377ABCAF271C")},
	{name: "RAR Archive v1.5", magicBytes: parseHex("526172211A0700")},
	{name: "RAR Archive v5.0", magicBytes: parseHex("526172211A070100")},
	{name: "GZ / Tar.Gz Archive", magicBytes: parseHex("1F8B")},
	{name: "BZ2 Archive", magicBytes: parseHex("314159265359")},
	{name: "XZ Archive", magicBytes: parseHex("FD377A585A0000")},
	{name: "SQLite Database", magicBytes: parseHex("53514c69746520666f726d6174203300")},
	{name: "TAR Archive", magicBytes: parseHex("7573746172202000")},
	{name: "TAR Archive v2", magicBytes: parseHex("7573746172003030")},
	{name: "LZ Archive", magicBytes: parseHex("4C5A4950")},
	{name: "Z Archive", magicBytes: parseHex("1F9D")},
}

func parseHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func (r *Runner) runBackupArchives(ctx context.Context, target ScanTarget) []ModuleFinding {
	if ok, reason := r.shouldRunModule("backup_archives", target); !ok {
		r.emitSkip("backup_archives", target, reason)
		return nil
	}

	u, err := url.Parse(target.EndpointURL)
	if err != nil || u.Host == "" {
		return nil
	}
	originTarget, ok := originScanTarget(target)
	if !ok {
		return nil
	}

	hostname := strings.ToLower(u.Hostname())
	parts := strings.Split(hostname, ".")

	domainName := hostname
	subdomainName := parts[0]
	if len(parts) >= 2 {
		domainName = parts[len(parts)-2]
	}

	currentYear := fmt.Sprintf("%d", time.Now().Year())

	// Dynamic FILENAME candidates
	fileCandidates := []string{
		hostname,
		domainName,
		subdomainName,
		currentYear,
		fmt.Sprintf("%d", time.Now().Year()-1),
		"ROOT", "wwwroot", "htdocs", "www", "html", "web", "webapps", "public", "public_html",
		"uploads", "website", "api", "test", "app", "backup", "backup_1", "backup_2", "backup_3", "backup_4", "backups",
		"bin", "temp", "bak", "db", "sql", "dump", "database", "Release", "inetpub", "package", "site",
		"tmp", "data", "admin", "upload", "src", "source", "old", "Scripts", "static", "assets", "dist",
		"build", "frontend", "backend", "client", "server", "services", "controllers", "models",
		"config", "database", "core", "modules", "components", "dashboard", "portal", "lib", "vendor",
		"includes", "middleware", "handlers", "views",
	}

	var directPathCandidates []string

	// Dynamic Path Segment & Subpath Extraction (e.g., /v1/checkout/main.js -> "v1", "checkout", "main")
	if u.Path != "" && u.Path != "/" {
		segments := strings.Split(strings.Trim(u.Path, "/"), "/")
		accumulated := ""
		for _, seg := range segments {
			cleanSeg := strings.TrimSpace(seg)
			if cleanSeg == "" {
				continue
			}
			rawName := cleanSeg
			if dotIdx := strings.LastIndex(cleanSeg, "."); dotIdx > 0 {
				rawName = cleanSeg[:dotIdx]
			}
			fileCandidates = append(fileCandidates, rawName)
			fileCandidates = append(fileCandidates, cleanSeg)
			fileCandidates = append(fileCandidates, rawName+"_backup")
			fileCandidates = append(fileCandidates, rawName+"-old")
			fileCandidates = append(fileCandidates, rawName+"."+currentYear)

			accumulated += "/" + cleanSeg
			directPathCandidates = append(directPathCandidates, accumulated)
		}
	}

	// Archive Extensions
	extensions := []string{
		"zip", "tar.gz", "7z", "rar", "gz", "bz2", "xz", "tgz", "tar", "db", "sqlite",
		"sqlitedb", "sql.zip", "sql.gz", "sql.tar.gz", "sql.7z", "sql.rar", "war", "bak", "old",
	}

	baseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
	baseline, baselineErr := r.cachedEmptyProbe(ctx, originTarget)
	if baselineErr != nil {
		return nil
	}
	var out []ModuleFinding
	seenPath := map[string]struct{}{}

	probePath := func(path string, ext string) {
		if _, exists := seenPath[path]; exists || ctx.Err() != nil {
			return
		}
		seenPath[path] = struct{}{}

		targetURL := baseURL + path
		probeTarget := originTarget
		probeTarget.EndpointURL = targetURL
		probeTarget.Parameter = ""
		probeTarget.Location = ""

		rr, err := r.probe(ctx, probeTarget, "")
		if err != nil || rr.Response.StatusCode != 200 {
			return
		}

		// Strict Binary Magic Bytes Matching (Zero False Positive Proof Contract)
		bodyBytes := []byte(rr.Response.Body)
		if len(bodyBytes) < 4 {
			return
		}

		var matchedMagic *binaryMagic
		for _, m := range archiveMagicSignatures {
			if len(m.magicBytes) > 0 && len(bodyBytes) >= len(m.magicBytes) {
				if bytesHasPrefix(bodyBytes, m.magicBytes) || bytesContains(bodyBytes[:minInt(len(bodyBytes), 512)], m.magicBytes) {
					matchedMagic = &m
					break
				}
			}
		}

		if matchedMagic != nil {
			signal := fmt.Sprintf("compressed_backup_disclosure_%s", strings.ReplaceAll(strings.ToLower(ext), ".", "_"))
			p := defaultPayload("backup_archives", path, path, signal)
			f := r.verifyAndBuild(ctx, "backup_archives", probeTarget, p, baseline, rr, signal, false, false, "", "")
			if f != nil {
				f.Title = fmt.Sprintf("Exposed Compressed Backup File (%s - %s)", path, matchedMagic.name)
				f.Severity = "critical"
				f.Description = fmt.Sprintf("A compressed backup archive '%s' was publicly accessible and verified via binary magic byte signature (%s).", path, matchedMagic.name)
				r.recordFinding(ctx, &out, f, "backup_archives", signal)
			}
		}
	}

	// 1. Probe root-level archive files
	for _, fname := range fileCandidates {
		for _, ext := range extensions {
			probePath(fmt.Sprintf("/%s.%s", fname, ext), ext)
		}
	}

	// 2. Probe direct hierarchical subpaths (e.g. /v1/checkout.zip, /app/static.tar.gz)
	for _, subPath := range directPathCandidates {
		for _, ext := range extensions {
			probePath(fmt.Sprintf("%s.%s", subPath, ext), ext)
		}
	}

	return out
}

func bytesHasPrefix(s, prefix []byte) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := range prefix {
		if s[i] != prefix[i] {
			return false
		}
	}
	return true
}

func bytesContains(s, substr []byte) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := range substr {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func backupArchiveSignalConfirmed(signal string, response httpclient.ResponseRecord) bool {
	if response.StatusCode != 200 || !strings.HasPrefix(signal, "compressed_backup_disclosure_") {
		return false
	}
	bodyBytes := []byte(response.Body)
	if len(bodyBytes) < 4 {
		return false
	}
	for _, m := range archiveMagicSignatures {
		if len(m.magicBytes) == 0 || len(bodyBytes) < len(m.magicBytes) {
			continue
		}
		if bytesHasPrefix(bodyBytes, m.magicBytes) || bytesContains(bodyBytes[:minInt(len(bodyBytes), 512)], m.magicBytes) {
			return true
		}
	}
	return false
}
