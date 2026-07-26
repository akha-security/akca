package testlab

import "strings"

func stringsLower(s string) string       { return strings.ToLower(s) }
func stringsContains(s, sub string) bool { return strings.Contains(s, sub) }
