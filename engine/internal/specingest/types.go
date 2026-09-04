package specingest

// ParameterLocation specifies where the parameter appears in the HTTP request.
type ParameterLocation string

const (
	LocationQuery  ParameterLocation = "query"
	LocationPath   ParameterLocation = "path"
	LocationHeader ParameterLocation = "header"
	LocationCookie ParameterLocation = "cookie"
	LocationBody   ParameterLocation = "body"
	LocationForm   ParameterLocation = "form"
)

// ParameterSpec describes an individual parameter extracted from an API spec.
type ParameterSpec struct {
	Name        string            `json:"name"`
	Location    ParameterLocation `json:"location"`
	Required    bool              `json:"required"`
	Type        string            `json:"type"`
	Default     string            `json:"default,omitempty"`
	Description string            `json:"description,omitempty"`
	EnumValues  []string          `json:"enum_values,omitempty"`
}

// ParsedEndpoint represents a normalized endpoint extracted from specs or traffic.
type ParsedEndpoint struct {
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	Summary      string            `json:"summary,omitempty"`
	Description  string            `json:"description,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	Parameters   []ParameterSpec   `json:"parameters,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	ContentType  string            `json:"content_type,omitempty"`
	BodyTemplate string            `json:"body_template,omitempty"`
	AuthType     string            `json:"auth_type,omitempty"`
}

// IngestFormat represents the detected format of the ingested specification.
type IngestFormat string

const (
	FormatOpenAPI3 IngestFormat = "openapi_3"
	FormatSwagger2 IngestFormat = "swagger_2"
	FormatPostman  IngestFormat = "postman_collection"
	FormatHAR      IngestFormat = "har_traffic"
	FormatUnknown  IngestFormat = "unknown"
)

// IngestResult contains all extracted endpoints and metadata.
type IngestResult struct {
	Format    IngestFormat     `json:"format"`
	Title     string           `json:"title,omitempty"`
	Version   string           `json:"version,omitempty"`
	BaseURL   string           `json:"base_url,omitempty"`
	Endpoints []ParsedEndpoint `json:"endpoints"`
}
