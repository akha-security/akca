package params

type Location string

const (
	LocationQuery      Location = "query"
	LocationForm       Location = "form"
	LocationJSON       Location = "json"
	LocationXML        Location = "xml"
	LocationMultipart  Location = "multipart"
	LocationHeader     Location = "header"
	LocationCookie     Location = "cookie"
	LocationPath       Location = "path"
	LocationGraphQL    Location = "graphql"
	LocationWebSocket  Location = "websocket"
	LocationOAuth      Location = "oauth"
	LocationHidden     Location = "hidden"
	LocationHTMLAttr   Location = "html_attr"
	LocationDataAttr   Location = "data_attr"
	LocationJSBuilder  Location = "js_builder"
	LocationStateBlob  Location = "state_blob"
)

type DiscoveredParameter struct {
	Name              string   `json:"name"`
	Location          Location `json:"location"`
	Priority          int      `json:"priority"`
	MethodDependent   bool     `json:"method_dependent,omitempty"`
	AcceptedMethods   []string `json:"accepted_methods,omitempty"`
	Confidence        float64  `json:"confidence"`
	Source            string   `json:"source"` // passive | differential
	EndpointURL       string   `json:"endpoint_url"`
	EndpointMethod    string   `json:"endpoint_method"`
}

type ResponseFingerprint struct {
	StatusCode int
	BodyLength int
	BodyHash   string
	DurationMs int64
	HeaderHash string
}

type EventSink func(eventType, message string, payload map[string]interface{}) error
