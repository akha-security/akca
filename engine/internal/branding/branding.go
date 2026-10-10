package branding

import "strings"

const (
	ProductName  = "AKCA ADVANCED WEB SECURITY SCANNER"
	Version      = "0.2.8"
	VersionLabel = "v" + Version
	UserAgent    = ProductName + "/" + Version
)

// CommitSHA and BuildDate are injected by release builds. They deliberately
// remain valid defaults for go install and local development builds.
var (
	CommitSHA = "unknown"
	BuildDate = "unknown"
)

func BuildIdentity() string {
	commit := strings.TrimSpace(CommitSHA)
	if len(commit) > 12 {
		commit = commit[:12]
	}
	if commit == "" {
		commit = "unknown"
	}
	date := strings.TrimSpace(BuildDate)
	if date == "" {
		date = "unknown"
	}
	return commit + " (" + date + ")"
}
