package rulesdk

import (
	"strings"
	"testing"
)

func TestParseValidBundle(t *testing.T) {
	bundle, err := Parse([]byte(exampleBundleJSON("sqli")))
	if err != nil {
		t.Fatal(err)
	}
	if bundle.SDKVersion != Version || bundle.Modules[0].Manifest.ID != "sqli" {
		t.Fatalf("unexpected bundle: %+v", bundle)
	}
}

func TestValidationRejectsUnknownFieldsAndMissingTwin(t *testing.T) {
	raw := strings.Replace(exampleBundleJSON("sqli"), `"kind":"control"`, `"kind":"dynamic"`, 1)
	if _, err := Parse([]byte(raw)); err == nil {
		t.Fatal("bundle without control fixture must be rejected")
	}
	raw = strings.Replace(exampleBundleJSON("sqli"), `"sdk_version":"1.0.0"`, `"sdk_version":"1.0.0","surprise":true`, 1)
	if _, err := Parse([]byte(raw)); err == nil {
		t.Fatal("unknown bundle fields must be rejected")
	}
	if _, err := Parse([]byte(exampleBundleJSON("sqli") + `{}`)); err == nil {
		t.Fatal("trailing JSON must be rejected")
	}
	raw = strings.Replace(exampleBundleJSON("sqli"), `"version":"1.0.0"`, `"version":"1"`, 1)
	if _, err := Parse([]byte(raw)); err == nil {
		t.Fatal("non-semantic module version must be rejected")
	}
}

func exampleBundleJSON(id string) string {
	return `{
	  "sdk_version":"1.0.0",
	  "modules":[{
	    "manifest":{"id":"` + id + `","name":"SQL injection","version":"1.0.0","compatibility":"1.0.0"},
	    "preconditions":{"methods":["GET"],"locations":["query","header"]},
	    "payload_families":[{"id":"boolean","payloads":[{"id":"true","value":"' OR 1=1--","location":"query","risk_level":"safe"}]}],
	    "proof_policy":{"allowed_proof_types":["boolean_pair"],"confirmation_rules":["true_false_delta"],"minimum_attempts":2,"requires_control":true},
	    "controls":[{"id":"syntax-control","type":"negative","value":"' OR 1=2--"}],
	    "report":{"title":"SQL injection","description":"Differential proof","impact":"Database access","remediation":"Use parameters"},
	    "tests":[{"kind":"positive","name":"vulnerable"},{"kind":"negative","name":"safe"},{"kind":"control","name":"control"}]
	  }]
	}`
}
