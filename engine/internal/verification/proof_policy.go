package verification

import "strings"

const CurrentProofPolicyVersion = "3.0"

type ModuleProofPolicy struct {
	Module                   string            `json:"module"`
	Version                  string            `json:"version"`
	RequiredObservationRoles []ObservationRole `json:"required_observation_roles,omitempty"`
	MinimumIndependentRuns   int               `json:"minimum_independent_runs"`
	RequiresNativeBaseline   bool              `json:"requires_native_baseline"`
	RequiresNegativeControl  bool              `json:"requires_negative_control"`
	RequiresStateProof       bool              `json:"requires_state_proof"`
	RequiresIdentityProof    bool              `json:"requires_identity_proof"`
	RequiresOAST             bool              `json:"requires_oast"`
	AllowedProofTypes        []ProofType       `json:"allowed_proof_types"`
	EvidenceClass            string            `json:"evidence_class"`
	RequiresTypedSignal      bool              `json:"requires_typed_signal"`
}

var proofPolicies = map[string]ModuleProofPolicy{
	"sqli":                   replayPolicy("sqli", ProofDifferentialReplay, ProofBooleanPair, ProofTiming, ProofOAST, ProofRuntimeTrace),
	"xss":                    xssPolicy("xss"),
	"ssti":                   replayPolicy("ssti", ProofDifferentialReplay, ProofTiming, ProofOAST, ProofRuntimeTrace),
	"ssrf":                   replayPolicy("ssrf", ProofDifferentialReplay, ProofOAST, ProofRuntimeTrace),
	"xxe":                    replayPolicy("xxe", ProofDifferentialReplay, ProofOAST, ProofRuntimeTrace),
	"command_injection":      replayPolicy("command_injection", ProofDifferentialReplay, ProofTiming, ProofOAST, ProofRuntimeTrace),
	"lfi":                    replayPolicy("lfi", ProofDifferentialReplay, ProofFileRetrieval, ProofRuntimeTrace),
	"nosql":                  replayPolicy("nosql", ProofDifferentialReplay),
	"prototype_pollution":    replayPolicy("prototype_pollution", ProofDifferentialReplay),
	"ldap_xpath_injection":   replayPolicy("ldap_xpath_injection", ProofDifferentialReplay, ProofHeaderEvidence, ProofRuntimeTrace),
	"crlf":                   headerPolicy("crlf"),
	"open_redirect":          headerPolicy("open_redirect"),
	"host_header":            headerPolicy("host_header"),
	"cors":                   headerPolicy("cors"),
	"second_order":           storedPolicy("second_order"),
	"client_ssti":            domPolicy("client_ssti"),
	"blind_xss":              oastPolicy("blind_xss"),
	"file_upload":            statePolicy("file_upload", ProofFileRetrieval),
	"idor":                   identityPolicy("idor"),
	"bfla":                   identityPolicy("bfla"),
	"mass_assignment":        statePolicy("mass_assignment", ProofStateMutation),
	"race_condition":         statePolicy("race_condition", ProofStateMutation),
	"business_logic":         statePolicy("business_logic", ProofStateMutation),
	"jwt":                    identityPolicy("jwt"),
	"oauth":                  replayPolicy("oauth", ProofDifferentialReplay),
	"rate_limit":             replayPolicy("rate_limit", ProofDifferentialReplay, ProofPolicyViolation),
	"account_enum":           replayPolicy("account_enum", ProofDifferentialReplay, ProofTiming),
	"cache_poisoning":        replayPolicy("cache_poisoning", ProofDifferentialReplay),
	"cache_deception":        replayPolicy("cache_deception", ProofDifferentialReplay),
	"hpp":                    statePolicy("hpp", ProofStateMutation),
	"broken_auth":            anonymousPolicy("broken_auth"),
	"csrf":                   requestPolicy("csrf"),
	"smuggling":              protocolPolicy("smuggling"),
	"graphql":                schemaPolicy("graphql"),
	"websocket":              replayPolicy("websocket", ProofDifferentialReplay),
	"api_exposure":           contentPolicy("api_exposure"),
	"api_versioning":         contentPolicy("api_versioning"),
	"debug_admin":            contentPolicy("debug_admin"),
	"wordpress_fuzz":         contentPolicy("wordpress_fuzz"),
	"secret_exposure":        contentPolicy("secret_exposure"),
	"sensitive_data":         contentPolicy("sensitive_data"),
	"cicd_exposure":          contentPolicy("cicd_exposure"),
	"git_recovery":           contentPolicy("git_recovery"),
	"source_code_disclosure": contentPolicy("source_code_disclosure"),
	"cloud_storage":          contentPolicy("cloud_storage"),
	"cloud_posture":          contentPolicy("cloud_posture"),
	"script_source":          contentPolicy("script_source"),
	"vulnerable_components":  contentPolicy("vulnerable_components"),
	// Version/banner matching is inventory, not exploitability proof. A CVE
	// finding therefore needs the same replay/control discipline as an active
	// differential probe.
	"known_cve":        replayPolicy("known_cve", ProofDifferentialReplay, ProofOAST, ProofRuntimeTrace),
	"security_headers": configurationPolicy("security_headers"),
	"tls_misconfig":    configurationPolicy("tls_misconfig"),
	"auth_bypass":      identityPolicy("auth_bypass"),
	"deserialization":  replayPolicy("deserialization", ProofDifferentialReplay, ProofOAST, ProofRuntimeTrace),
	"rce":              replayPolicy("rce", ProofDifferentialReplay, ProofOAST, ProofRuntimeTrace),
}

func replayPolicy(module string, allowed ...ProofType) ModuleProofPolicy {
	return ModuleProofPolicy{
		Module: module, Version: CurrentProofPolicyVersion, MinimumIndependentRuns: 3,
		RequiresNativeBaseline: true, RequiresNegativeControl: true, AllowedProofTypes: allowed,
		EvidenceClass: "active_differential", RequiresTypedSignal: true,
	}
}

func statePolicy(module string, allowed ...ProofType) ModuleProofPolicy {
	return ModuleProofPolicy{
		Module: module, Version: CurrentProofPolicyVersion, MinimumIndependentRuns: 2,
		RequiresNativeBaseline: true, RequiresNegativeControl: true, RequiresStateProof: true,
		AllowedProofTypes: allowed, EvidenceClass: "state_mutation", RequiresTypedSignal: true,
	}
}

func identityPolicy(module string) ModuleProofPolicy {
	return ModuleProofPolicy{
		Module: module, Version: CurrentProofPolicyVersion, MinimumIndependentRuns: 2,
		RequiresNativeBaseline: true, RequiresNegativeControl: true, RequiresIdentityProof: true,
		AllowedProofTypes: []ProofType{ProofIdentityBoundary, ProofStateMutation},
		EvidenceClass:     "identity_boundary", RequiresTypedSignal: true,
	}
}

func headerPolicy(module string) ModuleProofPolicy {
	return ModuleProofPolicy{
		Module: module, Version: CurrentProofPolicyVersion, MinimumIndependentRuns: 3,
		RequiresNativeBaseline: true, RequiresNegativeControl: true,
		AllowedProofTypes: []ProofType{ProofHeaderEvidence},
		EvidenceClass:     "header_differential", RequiresTypedSignal: true,
	}
}

func contentPolicy(module string) ModuleProofPolicy {
	return ModuleProofPolicy{
		Module: module, Version: CurrentProofPolicyVersion, MinimumIndependentRuns: 1,
		AllowedProofTypes: []ProofType{ProofContentEvidence},
		EvidenceClass:     "typed_content", RequiresTypedSignal: true,
	}
}

func configurationPolicy(module string) ModuleProofPolicy {
	return ModuleProofPolicy{
		Module: module, Version: CurrentProofPolicyVersion, MinimumIndependentRuns: 1,
		AllowedProofTypes: []ProofType{ProofConfiguration},
		EvidenceClass:     "configuration", RequiresTypedSignal: true,
	}
}

func schemaPolicy(module string) ModuleProofPolicy {
	return ModuleProofPolicy{
		Module: module, Version: CurrentProofPolicyVersion, MinimumIndependentRuns: 2,
		AllowedProofTypes: []ProofType{ProofSchemaExposure},
		EvidenceClass:     "schema", RequiresTypedSignal: true,
	}
}

func protocolPolicy(module string) ModuleProofPolicy {
	return ModuleProofPolicy{
		Module: module, Version: CurrentProofPolicyVersion, MinimumIndependentRuns: 2,
		RequiresNativeBaseline: true, RequiresNegativeControl: true,
		AllowedProofTypes: []ProofType{ProofProtocolDesync},
		EvidenceClass:     "protocol", RequiresTypedSignal: true,
	}
}

func requestPolicy(module string) ModuleProofPolicy {
	return ModuleProofPolicy{
		Module: module, Version: CurrentProofPolicyVersion, MinimumIndependentRuns: 1,
		RequiresNativeBaseline: true, RequiresNegativeControl: true,
		AllowedProofTypes: []ProofType{ProofRequestPolicy},
		EvidenceClass:     "request_policy", RequiresTypedSignal: true,
	}
}

func anonymousPolicy(module string) ModuleProofPolicy {
	return ModuleProofPolicy{
		Module: module, Version: CurrentProofPolicyVersion, MinimumIndependentRuns: 2,
		RequiresNativeBaseline: true, AllowedProofTypes: []ProofType{ProofAnonymousAccess},
		EvidenceClass: "anonymous_access", RequiresTypedSignal: true,
	}
}

func storedPolicy(module string) ModuleProofPolicy {
	return ModuleProofPolicy{
		Module: module, Version: CurrentProofPolicyVersion, MinimumIndependentRuns: 1,
		RequiresNativeBaseline: true, AllowedProofTypes: []ProofType{ProofStoredExecution},
		EvidenceClass: "stored_execution", RequiresTypedSignal: true,
	}
}

func domPolicy(module string) ModuleProofPolicy {
	return ModuleProofPolicy{
		Module: module, Version: CurrentProofPolicyVersion, MinimumIndependentRuns: 1,
		RequiresNativeBaseline: true, AllowedProofTypes: []ProofType{ProofDOMExecution},
		EvidenceClass: "browser_execution", RequiresTypedSignal: true,
	}
}

// Reflected XSS can be proven without navigating a GET URL in a browser. This
// matters for form, JSON and header injection surfaces where the original
// request method/body must be preserved. DOM execution remains the strongest
// path; otherwise the payload must parse as executable HTML/JS, reproduce on
// three independent requests and pass a non-executable negative control.
func xssPolicy(module string) ModuleProofPolicy {
	return ModuleProofPolicy{
		Module: module, Version: CurrentProofPolicyVersion, MinimumIndependentRuns: 3,
		RequiresNativeBaseline: true, RequiresNegativeControl: true,
		AllowedProofTypes: []ProofType{ProofDOMExecution, ProofDifferentialReplay},
		EvidenceClass:     "browser_or_executable_replay", RequiresTypedSignal: true,
	}
}

func oastPolicy(module string) ModuleProofPolicy {
	return ModuleProofPolicy{
		Module: module, Version: CurrentProofPolicyVersion, MinimumIndependentRuns: 1,
		AllowedProofTypes: []ProofType{ProofOAST},
		EvidenceClass:     "oast", RequiresTypedSignal: true,
	}
}

func ProofPolicy(module string) (ModuleProofPolicy, bool) {
	policy, ok := proofPolicies[strings.ToLower(strings.TrimSpace(module))]
	return policy, ok
}

func ProofPolicyCatalog() map[string]ModuleProofPolicy {
	out := make(map[string]ModuleProofPolicy, len(proofPolicies))
	for module, policy := range proofPolicies {
		out[module] = policy
	}
	return out
}

func DefaultProofType(module string) ProofType {
	policy, ok := ProofPolicy(module)
	if !ok || len(policy.AllowedProofTypes) != 1 {
		return ProofNone
	}
	return policy.AllowedProofTypes[0]
}

func inferProofType(candidate Candidate, result Result) ProofType {
	if candidate.RequestedProofType != ProofNone {
		return candidate.RequestedProofType
	}
	switch {
	case result.OASTConfirmed:
		return ProofOAST
	case candidate.DOMExecuted:
		return ProofDOMExecution
	case result.TimingConfirmed:
		return ProofTiming
	case validBooleanPairProof(candidate.BooleanPairProof):
		return ProofBooleanPair
	case candidate.NegativeControlSet && result.NegativeControlOK && result.TypedReplayRatio >= 2.0/3.0:
		return ProofDifferentialReplay
	default:
		return ProofNone
	}
}

func evaluateProofPolicy(candidate Candidate, result Result) (ProofType, bool) {
	proofType := inferProofType(candidate, result)
	policy, exists := ProofPolicy(candidateModule(candidate))
	// Raw Candidate callers predating proof policies retain compatibility.
	// Every scanner module candidate sets ProofPolicyVersion, so the active
	// DAST pipeline remains fail-closed for an unknown or stale policy.
	if candidate.ProofPolicyVersion == "" {
		return proofType, true
	}
	if !exists {
		return proofType, false
	}
	if candidate.ProofPolicyVersion != policy.Version || !ValidateObservations(candidate.Observations) {
		return proofType, false
	}
	if !proofAllowed(policy.AllowedProofTypes, proofType) {
		return proofType, false
	}
	if policy.RequiresTypedSignal && (!candidate.DirectTypedSignal || strings.TrimSpace(candidate.Signal) == "") {
		return proofType, false
	}
	roles := observationRoles(candidate.Observations)
	if policy.RequiresNativeBaseline && roles[RoleNativeBaseline] == 0 {
		return proofType, false
	}
	switch proofType {
	case ProofOAST:
		return proofType, roles[RoleOASTCallback] > 0
	case ProofDOMExecution:
		return proofType, roles[RoleDOMExecution] > 0 && roles[RolePositiveProbe] > 0
	case ProofRuntimeTrace:
		return proofType, roles[RoleRuntimeTrace] > 0
	case ProofBooleanPair:
		return proofType, validBooleanPairProof(candidate.BooleanPairProof) &&
			roles[RoleTrueBranch] >= 3 && roles[RoleFalseBranch] >= 3 && roles[RoleSyntaxControl] > 0
	case ProofTiming:
		return proofType, result.TimingConfirmed && len(candidate.TimingSamples) >= 3 &&
			len(candidate.TimingControl) >= 3
	case ProofStateMutation:
		return proofType, negativeControlSatisfied(candidate, result, roles, policy.RequiresIdentityProof) &&
			roles[RoleStateBefore] > 0 && roles[RoleStateAfter] > 0
	case ProofFileRetrieval:
		return proofType, negativeControlSatisfied(candidate, result, roles, false) &&
			roles[RolePositiveProbe] > 0 && roles[RoleStateAfter] > 0
	case ProofIdentityBoundary:
		return proofType, negativeControlSatisfied(candidate, result, roles, true) &&
			roles[RoleIdentityA] > 0 && roles[RoleIdentityB] > 0 &&
			roles[RoleAnonymousControl] > 0
	case ProofPolicyViolation:
		return proofType, negativeControlSatisfied(candidate, result, roles, false) &&
			roles[RolePositiveProbe]+roles[RolePositiveReplay] >= policy.MinimumIndependentRuns &&
			roles[RoleNegativeControl] >= 2
	case ProofDifferentialReplay:
		return proofType, negativeControlSatisfied(candidate, result, roles, false) &&
			roles[RolePositiveProbe]+roles[RolePositiveReplay] >= policy.MinimumIndependentRuns
	case ProofHeaderEvidence:
		return proofType, negativeControlSatisfied(candidate, result, roles, false) &&
			roles[RolePositiveProbe]+roles[RolePositiveReplay] >= policy.MinimumIndependentRuns
	case ProofContentEvidence, ProofConfiguration:
		return proofType, roles[RolePositiveProbe] >= policy.MinimumIndependentRuns
	case ProofSchemaExposure:
		return proofType, roles[RolePositiveProbe]+roles[RolePositiveReplay] >= policy.MinimumIndependentRuns
	case ProofProtocolDesync:
		return proofType, negativeControlSatisfied(candidate, result, roles, false) &&
			roles[RolePositiveProbe]+roles[RolePositiveReplay] >= policy.MinimumIndependentRuns
	case ProofRequestPolicy:
		return proofType, negativeControlSatisfied(candidate, result, roles, false) &&
			roles[RoleBaselineReplay] > 0 && roles[RolePositiveProbe] > 0
	case ProofAnonymousAccess:
		return proofType, roles[RoleIdentityA] > 0 && roles[RoleAnonymousProbe] >= policy.MinimumIndependentRuns
	case ProofStoredExecution:
		return proofType, roles[RolePositiveProbe] > 0
	default:
		return proofType, false
	}
}

func negativeControlSatisfied(candidate Candidate, result Result, roles map[ObservationRole]int, allowAnonymous bool) bool {
	observations := roles[RoleNegativeControl]
	if allowAnonymous {
		observations += roles[RoleAnonymousControl]
	}
	return candidate.NegativeControlSet && result.NegativeControlOK && observations > 0
}

func proofAllowed(allowed []ProofType, value ProofType) bool {
	for _, item := range allowed {
		if item == value {
			return true
		}
	}
	return false
}

func observationRoles(items []Observation) map[ObservationRole]int {
	out := make(map[ObservationRole]int)
	for _, item := range items {
		out[item.Role]++
	}
	return out
}
