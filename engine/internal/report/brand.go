package report

import (
	_ "embed"
	"encoding/base64"
)

// Embed the original AKCA logo so exported reports work offline and can be
// shared as a single HTML file, regardless of the scanner's install location.
//
//go:embed logo.png
var reportLogo []byte

var reportLogoURL = "data:image/png;base64," + base64.StdEncoding.EncodeToString(reportLogo)
