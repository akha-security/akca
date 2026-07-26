package fuzzing

import "strings"

var archiveExtensions = []string{
	".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z", ".bz2", ".gz",
	".sql", ".sql.gz", ".bak", ".backup", ".old", ".copy",
}

func IsArchiveExposure(url string, status int, contentType string) bool {
	if status != 200 {
		return false
	}
	lower := strings.ToLower(url)
	ct := strings.ToLower(contentType)
	htmlLike := strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
	for _, ext := range archiveExtensions {
		if strings.HasSuffix(lower, ext) {
			// A catch-all page rendered as HTML at an archive-looking URL is
			// not a real archive download; avoid the false positive.
			return !htmlLike
		}
	}
	if strings.Contains(ct, "application/zip") ||
		strings.Contains(ct, "application/x-gzip") ||
		strings.Contains(ct, "application/gzip") ||
		strings.Contains(ct, "application/x-tar") ||
		strings.Contains(ct, "application/octet-stream") {
		return strings.Contains(lower, "backup") || strings.Contains(lower, "archive") || strings.Contains(lower, ".sql")
	}
	return false
}
