package jsanalyzer

import "time"

const (
	DefaultMaxJSBytes   = 2 * 1024 * 1024
	DefaultPreviewBytes = 8 * 1024
	MinConfidence       = 0.60
)

type ExtractedEndpoint struct {
	URL           string  `json:"url"`
	Method        string  `json:"method"`
	Template      string  `json:"template"`
	Source        string  `json:"source"`
	Extraction    string  `json:"extraction"` // ast | heuristic
	Confidence    float64 `json:"confidence"`
	Why           string  `json:"why"`
}

type SecretMatch struct {
	Kind       string  `json:"kind"`
	Value      string  `json:"value"`
	Redacted   string  `json:"redacted"`
	LineHint   int     `json:"line_hint,omitempty"`
	Confidence float64 `json:"confidence"`
}

type SourceMapRef struct {
	URL        string  `json:"url"`
	FromFile   string  `json:"from_file"`
	Exposed    bool    `json:"exposed"`
	Confidence float64 `json:"confidence"`
}

type InternalPath struct {
	Path       string  `json:"path"`
	Kind       string  `json:"kind"` // package | module | internal
	Confidence float64 `json:"confidence"`
}

type AnalysisResult struct {
	JSURL           string              `json:"js_url"`
	Truncated       bool                `json:"truncated"`
	PreviewOnly     bool                `json:"preview_only"`
	BytesAnalyzed   int                 `json:"bytes_analyzed"`
	Endpoints       []ExtractedEndpoint `json:"endpoints"`
	Secrets         []SecretMatch       `json:"secrets"`
	SourceMaps      []SourceMapRef      `json:"source_maps"`
	InternalPaths   []InternalPath      `json:"internal_paths"`
	AnalyzedAt      string              `json:"analyzed_at"`
}

type EventSink func(eventType, message string, payload map[string]interface{}) error

func nowTS() string {
	return time.Now().UTC().Format(time.RFC3339)
}
