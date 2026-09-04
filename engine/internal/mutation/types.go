package mutation

// ValueType represents the semantic type of a parameter value.
type ValueType int

const (
	TypeUnknown ValueType = iota
	TypeInteger
	TypeFloat
	TypeBoolean
	TypeUUID
	TypeEmail
	TypeTimestamp
	TypeDate
	TypeIPv4
	TypeIPv6
	TypePath
	TypeEnum
	TypeSequentialID
	TypeStructuredCode
	TypeJWT
	TypeBase64
	TypeHexEncoded
	TypeURL
	TypePhoneNumber
	TypeCreditCard
	TypeSlug
	TypeJSON
	TypeEmpty
)

func (v ValueType) String() string {
	switch v {
	case TypeUnknown:
		return "unknown"
	case TypeInteger:
		return "integer"
	case TypeFloat:
		return "float"
	case TypeBoolean:
		return "boolean"
	case TypeUUID:
		return "uuid"
	case TypeEmail:
		return "email"
	case TypeTimestamp:
		return "timestamp"
	case TypeDate:
		return "date"
	case TypeIPv4:
		return "ipv4"
	case TypeIPv6:
		return "ipv6"
	case TypePath:
		return "path"
	case TypeEnum:
		return "enum"
	case TypeSequentialID:
		return "sequential_id"
	case TypeStructuredCode:
		return "structured_code"
	case TypeJWT:
		return "jwt"
	case TypeBase64:
		return "base64"
	case TypeHexEncoded:
		return "hex_encoded"
	case TypeURL:
		return "url"
	case TypePhoneNumber:
		return "phone_number"
	case TypeCreditCard:
		return "credit_card"
	case TypeSlug:
		return "slug"
	case TypeJSON:
		return "json"
	case TypeEmpty:
		return "empty"
	default:
		return "unknown"
	}
}

// MutationIntent describes the security purpose of a generated mutation.
type MutationIntent int

const (
	IntentNeighbor   MutationIntent = iota // Semantically close variants (increment, swap)
	IntentBoundary                         // Edge cases, limits, overflows
	IntentEscalation                       // Privilege escalation variants
	IntentFormat                           // Format/type confusion
	IntentEmpty                            // Null, empty, undefined
)

func (m MutationIntent) String() string {
	switch m {
	case IntentNeighbor:
		return "neighbor"
	case IntentBoundary:
		return "boundary"
	case IntentEscalation:
		return "escalation"
	case IntentFormat:
		return "format"
	case IntentEmpty:
		return "empty"
	default:
		return "unknown"
	}
}

// Mutation represents a single mutated value with metadata.
type Mutation struct {
	Value  string         `json:"value"`
	Intent MutationIntent `json:"intent"`
	Label  string         `json:"label"`
}

// MutationSet holds classified mutations for a single insertion point.
type MutationSet struct {
	OriginalValue string     `json:"original_value"`
	DetectedType  ValueType  `json:"detected_type"`
	Mutations     []Mutation `json:"mutations"`
}

// SchemaHint provides optional type information from OpenAPI or other specs.
type SchemaHint struct {
	Type      string   `json:"type,omitempty"`
	Format    string   `json:"format,omitempty"`
	Enum      []string `json:"enum,omitempty"`
	Minimum   *float64 `json:"minimum,omitempty"`
	Maximum   *float64 `json:"maximum,omitempty"`
	MinLength *int     `json:"min_length,omitempty"`
	MaxLength *int     `json:"max_length,omitempty"`
	Pattern   string   `json:"pattern,omitempty"`
	ParamName string   `json:"param_name,omitempty"`
}

// GenerateOptions controls variant generation.
type GenerateOptions struct {
	Intents      []MutationIntent
	MaxPerIntent int
	SchemaHint   *SchemaHint
}

func DefaultGenerateOptions() *GenerateOptions {
	return &GenerateOptions{
		Intents: []MutationIntent{
			IntentNeighbor,
			IntentBoundary,
			IntentEscalation,
			IntentFormat,
			IntentEmpty,
		},
		MaxPerIntent: 5,
	}
}

func (o *GenerateOptions) hasIntent(intent MutationIntent) bool {
	if o == nil || len(o.Intents) == 0 {
		return true
	}
	for _, i := range o.Intents {
		if i == intent {
			return true
		}
	}
	return false
}
