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
	truncated = true
	if len(body) > previewBytes {
		return body[:previewBytes], true, true
	}
	return body[:maxBytes], true, false
}
