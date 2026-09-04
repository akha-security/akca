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
	if domain != "" {
		suffix := "." + domain
		if strings.HasSuffix(uniqueID, suffix) {
			return strings.TrimSuffix(uniqueID, suffix)
		}
		if uniqueID == domain {
			return ""
		}
		parts := strings.Split(domain, ".")
		if len(parts) > 0 && parts[0] != "" {
			corrID := parts[0]
			if strings.HasSuffix(uniqueID, "."+corrID) {
				return strings.TrimSuffix(uniqueID, "."+corrID)
			}
		}
		if strings.Contains(uniqueID, ".") {
			return ""
		}
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
	identifiers := []string{interaction.FullID, interaction.UniqueID}
	for _, identifier := range identifiers {
		identifier = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(identifier, ".")))
		if identifier == "" {
			continue
		}
		if c, ok := correlations[identifier]; ok {
			return c, true
		}
		token := ExtractCorrelationToken(identifier, domain)
		if token != "" {
			if c, ok := correlations[strings.ToLower(token)]; ok {
				return c, true
			}
		}
	}
	return Correlation{}, false
}
