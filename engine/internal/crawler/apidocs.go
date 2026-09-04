package crawler

// CommonAPIDocPaths returns well-known API documentation paths to probe.
func CommonAPIDocPaths(baseURL string) []DiscoveredEndpoint {
	paths := []string{
		"/graphql",
		"/api/graphql",
		"/v1/graphql",
		"/v2/graphql",
		"/graphiql",
		"/altair",
		"/playground",
		"/query",
		"/api/query",
		"/swagger.json",
		"/swagger/v1/swagger.json",
		"/openapi.json",
		"/asyncapi.json",
		"/asyncapi.yaml",
		"/asyncapi.yml",
		"/api/asyncapi.json",
		"/api/asyncapi.yaml",
		"/api/asyncapi.yml",
		"/api-docs",
		"/v1/api-docs",
		"/v2/api-docs",
		"/v3/api-docs",
		"/api/swagger.json",
		"/api/v1/swagger.json",
		"/api/v2/swagger.json",
		"/swagger-ui.html",
		"/swagger-ui/",
		"/postman/collection.json",
		"/docs",
		"/api/docs",
		"/redoc",
		"/api/v1",
		"/api/v2",
		"/api/v3",
		"/actuator/env",
		"/actuator/health",
		"/actuator/httptrace",
		"/actuator/mappings",
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
