package oast

import (
	"strings"
)

func ExtractCorrelationToken(uniqueID, domain string) string {
	uniqueID = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(uniqueID, ".")))
	if uniqueID == "" {
		return ""
	}
	domain = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(domain), "."))
	suffix := "." + domain
	if domain != "" && strings.HasSuffix(uniqueID, suffix) {
		return strings.TrimSuffix(uniqueID, suffix)
	}
	if domain != "" {
		if !strings.Contains(uniqueID, ".") {
			return uniqueID
		}
		return ""
	}
	parts := strings.Split(uniqueID, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return uniqueID
}

func ExtractPayloadID(correlationToken string) string {
	parts := strings.SplitN(correlationToken, ".", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func MatchInteraction(interaction Interaction, domain string, correlations map[string]Correlation) (Correlation, bool) {
	identifiers := []string{interaction.UniqueID, interaction.FullID}
	for _, identifier := range identifiers {
		identifier = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(identifier, ".")))
		if c, ok := correlations[identifier]; ok {
			return c, true
		}
		token := ExtractCorrelationToken(identifier, domain)
		if token == "" {
			continue
		}
		if c, ok := correlations[strings.ToLower(token)]; ok {
			return c, true
		}
	}
	// Payload IDs and token substrings are deliberately not accepted: they can
	// repeat across parameters, endpoints, and scans.
	return Correlation{}, false
}
