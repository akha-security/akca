package crawler

// CommonAPIDocPaths returns well-known API documentation paths to probe.
func CommonAPIDocPaths(baseURL string) []DiscoveredEndpoint {
	paths := []string{
		"/graphql",
		"/api/graphql",
		"/graphiql",
		"/swagger.json",
		"/swagger/v1/swagger.json",
		"/openapi.json",
		"/asyncapi.json",
		"/api/asyncapi.json",
		"/api-docs",
		"/v3/api-docs",
		"/docs",
		"/.well-known/openid-configuration",
		"/.well-known/security.txt",
	}
	var out []DiscoveredEndpoint
	for _, p := range paths {
		resolved, err := ResolveReference(baseURL, p)
		if err != nil || resolved == "" {
			continue
		}
		source := SourceAPIDoc
		method := "GET"
		if p == "/graphql" || p == "/api/graphql" {
			source = SourceGraphQL
			method = "POST"
		}
		out = append(out, DiscoveredEndpoint{
			URL: resolved, Method: method, Source: source, Confidence: 0.6, WhyDiscovered: "common API/OIDC/AsyncAPI discovery path",
		})
	}
	return out
}
