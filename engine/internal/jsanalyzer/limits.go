package jsanalyzer

// PrepareContent applies size limits and returns content suitable for analysis.
func PrepareContent(body string, maxBytes, previewBytes int) (content string, truncated, previewOnly bool) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxJSBytes
	}
	if previewBytes <= 0 {
		previewBytes = DefaultPreviewBytes
	}
	if len(body) <= maxBytes {
		return body, false, false
	}
	// previewBytes is retained for configuration compatibility, but it must not
	// reduce a multi-megabyte bundle to a tiny runtime-only prefix. Analyse the
	// entire configured budget and mark the result as a truncated preview.
	_ = previewBytes
	return body[:maxBytes], true, true
}
