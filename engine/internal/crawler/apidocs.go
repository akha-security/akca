package crawler

// CommonAPIDocPaths returns well-known API documentation paths to probe.
func CommonAPIDocPaths(baseURL string) []DiscoveredEndpoint {
	paths := []string{
		"/swagger.json",
		"/swagger/v1/swagger.json",
		"/openapi.json",
		"/api-docs",
		"/v2/api-docs",
		"/v3/api-docs",
		"/api/swagger.json",
		"/graphql",
		"/graphiql",
		"/api/graphql",
		"/postman/collection.json",
		"/docs",
		"/api/docs",
		"/redoc",
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
			URL: resolved, Method: method, Source: source, Confidence: 0.6, WhyDiscovered: "common api docs path",
		})
	}
	return out
}
