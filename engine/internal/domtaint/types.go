package domtaint

import "time"

// SourceCategory categorizes where client-side tainted data originates.
type SourceCategory string

const (
	SourceURL         SourceCategory = "url_source"
	SourceStorage     SourceCategory = "storage_source"
	SourceMessage     SourceCategory = "message_source"
	SourceEnvironment SourceCategory = "environment_source"
)

// SinkCategory categorizes the impact of the DOM sink.
type SinkCategory string

const (
	SinkCodeExecution SinkCategory = "code_execution" // eval, Function, setTimeout
	SinkDOMInjection  SinkCategory = "dom_injection"  // innerHTML, document.write
	SinkNavigation    SinkCategory = "navigation"     // location.href, window.open
	SinkScriptLoad    SinkCategory = "script_load"    // script.src, iframe.src
)

// SourceSpec represents a DOM source.
type SourceSpec struct {
	Name        string         `json:"name"`
	Category    SourceCategory `json:"category"`
	Expression  string         `json:"expression"`
	Description string         `json:"description"`
}

// SinkSpec represents a dangerous DOM sink.
type SinkSpec struct {
	Name        string       `json:"name"`
	Category    SinkCategory `json:"category"`
	Object      string       `json:"object"`
	Property    string       `json:"property"`
	Severity    string       `json:"severity"`
	Description string       `json:"description"`
}

// TaintReport represents a detected client-side source-to-sink flow.
type TaintReport struct {
	Source     string       `json:"source"`
	Sink       string       `json:"sink"`
	SinkValue  string       `json:"sink_value"`
	Category   SinkCategory `json:"category"`
	Severity   string       `json:"severity"`
	StackTrace string       `json:"stack_trace,omitempty"`
	URL        string       `json:"url"`
	Canary     string       `json:"canary"`
	Confirmed  bool         `json:"confirmed"`
	DetectedAt time.Time    `json:"detected_at"`
}
