package rulesdk

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const Version = "1.0.0"

type Bundle struct {
	SDKVersion string   `json:"sdk_version"`
	Modules    []Module `json:"modules"`
}

type Module struct {
	Manifest      Manifest      `json:"manifest"`
	Preconditions Preconditions `json:"preconditions"`
	Payloads      []Family      `json:"payload_families"`
	Proof         ProofPolicy   `json:"proof_policy"`
	Controls      []Control     `json:"controls"`
	Report        ReportText    `json:"report"`
	Tests         []TestCase    `json:"tests"`
}

type Manifest struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	Compatibility string `json:"compatibility"`
	Description   string `json:"description,omitempty"`
}

type Preconditions struct {
	EndpointTypes []string `json:"endpoint_types,omitempty"`
	Methods       []string `json:"methods,omitempty"`
	Locations     []string `json:"locations,omitempty"`
	ContentTypes  []string `json:"content_types,omitempty"`
	Technologies  []string `json:"technologies,omitempty"`
	RequiresAuth  bool     `json:"requires_auth,omitempty"`
	RequiresState bool     `json:"requires_state,omitempty"`
	RequiresOAST  bool     `json:"requires_oast,omitempty"`
}

type Family struct {
	ID       string    `json:"id"`
	Payloads []Payload `json:"payloads"`
}

type Payload struct {
	ID        string `json:"id"`
	Value     string `json:"value"`
	Location  string `json:"location,omitempty"`
	Encoding  string `json:"encoding,omitempty"`
	RiskLevel string `json:"risk_level,omitempty"`
}

type ProofPolicy struct {
	AllowedProofTypes []string `json:"allowed_proof_types"`
	ConfirmationRules []string `json:"confirmation_rules"`
	MinimumAttempts   int      `json:"minimum_attempts"`
	RequiresControl   bool     `json:"requires_control"`
}

type Control struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Value       string `json:"value,omitempty"`
}

type ReportText struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Remediation string `json:"remediation"`
}

type TestCase struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

func Parse(raw []byte) (Bundle, error) {
	var bundle Bundle
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, fmt.Errorf("invalid rule SDK bundle: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Bundle{}, fmt.Errorf("invalid rule SDK bundle: trailing JSON content")
	}
	if err := bundle.Validate(); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

func (b Bundle) Validate() error {
	if !compatible(Version, b.SDKVersion) {
		return fmt.Errorf("rule SDK %q is incompatible with engine SDK %q", b.SDKVersion, Version)
	}
	if len(b.Modules) == 0 {
		return fmt.Errorf("rule SDK bundle has no modules")
	}
	seen := make(map[string]struct{}, len(b.Modules))
	for i, module := range b.Modules {
		if err := validateModule(module); err != nil {
			return fmt.Errorf("module %d: %w", i, err)
		}
		if _, exists := seen[module.Manifest.ID]; exists {
			return fmt.Errorf("duplicate module id %q", module.Manifest.ID)
		}
		seen[module.Manifest.ID] = struct{}{}
	}
	return nil
}

func validateModule(module Module) error {
	m := module.Manifest
	if strings.TrimSpace(m.ID) == "" || strings.TrimSpace(m.Name) == "" ||
		strings.TrimSpace(m.Version) == "" || strings.TrimSpace(m.Compatibility) == "" {
		return fmt.Errorf("manifest id, name, version and compatibility are required")
	}
	if !semanticVersion(m.Version) || !semanticVersion(m.Compatibility) ||
		!compatible(Version, m.Compatibility) {
		return fmt.Errorf("invalid or incompatible manifest version")
	}
	if len(module.Payloads) == 0 {
		return fmt.Errorf("at least one payload family is required")
	}
	payloadIDs := map[string]struct{}{}
	for _, family := range module.Payloads {
		if strings.TrimSpace(family.ID) == "" || len(family.Payloads) == 0 {
			return fmt.Errorf("payload family id and payloads are required")
		}
		for _, payload := range family.Payloads {
			if strings.TrimSpace(payload.ID) == "" || strings.TrimSpace(payload.Value) == "" {
				return fmt.Errorf("payload id and value are required")
			}
			if _, exists := payloadIDs[payload.ID]; exists {
				return fmt.Errorf("duplicate payload id %q", payload.ID)
			}
			payloadIDs[payload.ID] = struct{}{}
		}
	}
	if len(module.Proof.AllowedProofTypes) == 0 || len(module.Proof.ConfirmationRules) == 0 ||
		module.Proof.MinimumAttempts < 1 {
		return fmt.Errorf("proof policy must define proof types, confirmation rules and attempts")
	}
	if len(module.Controls) == 0 {
		return fmt.Errorf("at least one negative control is required")
	}
	if strings.TrimSpace(module.Report.Title) == "" || strings.TrimSpace(module.Report.Description) == "" ||
		strings.TrimSpace(module.Report.Impact) == "" || strings.TrimSpace(module.Report.Remediation) == "" {
		return fmt.Errorf("complete report text is required")
	}
	testKinds := map[string]bool{}
	for _, test := range module.Tests {
		testKinds[strings.ToLower(strings.TrimSpace(test.Kind))] = strings.TrimSpace(test.Name) != ""
	}
	for _, kind := range []string{"positive", "negative", "control"} {
		if !testKinds[kind] {
			return fmt.Errorf("%s test fixture is required", kind)
		}
	}
	return nil
}

func compatible(engine, required string) bool {
	left, right := major(engine), major(required)
	return left != "" && right != "" && left == right
}

func major(version string) string {
	version = strings.TrimSpace(strings.TrimPrefix(version, "v"))
	if version == "" {
		return ""
	}
	if dot := strings.IndexByte(version, '.'); dot >= 0 {
		version = version[:dot]
	}
	for _, r := range version {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return version
}

func semanticVersion(version string) bool {
	version = strings.TrimSpace(strings.TrimPrefix(version, "v"))
	core := strings.SplitN(version, "-", 2)[0]
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func IsSemanticVersion(version string) bool {
	return semanticVersion(version)
}
