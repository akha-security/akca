package fuzzing

type Category string

const (
	CategoryGeneral    Category = "general"
	CategoryArchive    Category = "archive"
	CategoryAdmin      Category = "admin"
	CategoryArtifact   Category = "artifact"
	CategoryFramework  Category = "framework"
	CategoryActuator   Category = "actuator"
	CategoryAPI        Category = "api"
	CategoryConfig     Category = "config"
	CategoryDiscovered Category = "discovered"
)

type FuzzTask struct {
	URL      string
	Method   string
	Category Category
	Path     string
}

type FuzzResult struct {
	URL        string `json:"url"`
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
	Category   string `json:"category"`
	Signal     string `json:"signal"`
	BodyLength int    `json:"body_length"`
	IsSoft404  bool   `json:"is_soft_404"`
	IsArchive  bool   `json:"is_archive"`
}

type QueueEntry struct {
	URL      string `json:"url"`
	Method   string `json:"method"`
	Priority int    `json:"priority"`
}

type EventSink func(eventType, message string, payload map[string]interface{}) error
