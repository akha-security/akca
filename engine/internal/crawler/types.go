package crawler

import "time"

type DiscoverySource string

const (
	SourceLink          DiscoverySource = "link"
	SourceForm          DiscoverySource = "form"
	SourceMetaRefresh   DiscoverySource = "meta_refresh"
	SourceCanonical     DiscoverySource = "canonical"
	SourceScript        DiscoverySource = "script"
	SourceInlineJS      DiscoverySource = "inline_js"
	SourceHTMLComment   DiscoverySource = "html_comment"
	SourceCSS           DiscoverySource = "css"
	SourceDataAttr      DiscoverySource = "data_attribute"
	SourceSrcset        DiscoverySource = "srcset"
	SourceImage         DiscoverySource = "image"
	SourceMedia         DiscoverySource = "media"
	SourceIframe        DiscoverySource = "iframe"
	SourceLinkHeader    DiscoverySource = "link_header"
	SourceRobots        DiscoverySource = "robots_txt"
	SourceSitemap       DiscoverySource = "sitemap"
	SourceJSBundle      DiscoverySource = "js_bundle"
	SourceSPARoute      DiscoverySource = "spa_route"
	SourceAPIDoc        DiscoverySource = "api_doc"
	SourceGraphQL       DiscoverySource = "graphql"
	SourceWebSocket     DiscoverySource = "websocket"
	SourceSeed          DiscoverySource = "seed"
	SourceSeedIngest    DiscoverySource = "seed_ingest"
	SourceBrowserXHR    DiscoverySource = "browser_xhr"
	SourceAST           DiscoverySource = "js_ast"
	SourceEventSource   DiscoverySource = "event_source"
)

type DiscoveredEndpoint struct {
	URL              string          `json:"url"`
	Method           string          `json:"method"`
	NormalizedURL    string          `json:"normalized_url"`
	Source           DiscoverySource `json:"source"`
	Confidence       float64         `json:"confidence"`
	Depth            int             `json:"depth"`
	Priority         int             `json:"priority"`
	WhyDiscovered    string          `json:"why_discovered"`
	RequestTemplate  *RequestTemplate `json:"request_template,omitempty"`
}

type RequestTemplate struct {
	Method                string            `json:"method"`
	URL                   string            `json:"url"`
	Headers               map[string]string `json:"headers,omitempty"`
	Body                  string            `json:"body,omitempty"`
	ContentType           string            `json:"content_type,omitempty"`
	ResponseStatus        int               `json:"response_status,omitempty"`
	ResponseHeaders       map[string]string `json:"response_headers,omitempty"`
	ResponseBody          string            `json:"response_body,omitempty"`
	FetchedViaGETFallback bool              `json:"fetched_via_get_fallback,omitempty"`
}

type Budget struct {
	MaxDepth      int
	MaxPages      int
	RequestBudget int
	TimeBudget    time.Duration
}

type EventSink func(eventType, message string, payload map[string]interface{}) error
