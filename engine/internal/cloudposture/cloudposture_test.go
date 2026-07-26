package cloudposture

import (
	"strings"
	"testing"
)

const sampleJS = `
const awsConfig = {
  region: "us-east-1",
  userPoolId: "us-east-1_AbCdEfGhI",
  clientId: "1234567890abcdefghij",
  identityPoolId: "us-east-1:12345678-1234-1234-1234-123456789012"
};
const firebaseConfig = {
  apiKey: "AIzaSy0123456789abcdefghijklmnopqrstuvx",
  projectId: "my-app-prod",
  appId: "1:1234567890:web:abc123def456"
};
`

func TestExtractCredentials(t *testing.T) {
	c := ExtractCredentials(sampleJS)
	if !c.HasCognito() {
		t.Fatal("expected cognito credentials")
	}
	if !c.HasIdentityPool() {
		t.Fatal("expected identity pool")
	}
	if !c.HasFirebase() {
		t.Fatal("expected firebase api key")
	}
	if c.AWSRegion != "us-east-1" {
		t.Fatalf("region=%q", c.AWSRegion)
	}
}

func TestBuildProbes(t *testing.T) {
	c := ExtractCredentials(sampleJS)
	probes := BuildProbes(c)
	if len(probes) < 3 {
		t.Fatalf("expected multiple probes, got %d", len(probes))
	}
}

func TestAnalyzeTFState(t *testing.T) {
	body := `{
		"terraform_version": "1.5.0",
		"resources": [{
			"type": "aws_db_instance",
			"instances": [{
				"attributes": {
					"password": "SuperSecretDbPass123",
					"username": "admin"
				}
			}]
		}]
	}`
	findings := AnalyzeTFState(body)
	if len(findings) == 0 {
		t.Fatal("expected tfstate secret finding")
	}
}

func TestIsTFState(t *testing.T) {
	if !IsTFState(`{"terraform_version":"1.0","resources":[]}`) {
		t.Fatal("expected tfstate detection")
	}
}

func TestInterpretFirebaseSignup(t *testing.T) {
	ok, sig := InterpretAbuseResponse(AbuseProbe{Signal: "firebase_open_signup"}, 200, `{"idToken":"abc","localId":"xyz"}`)
	if !ok || !strings.Contains(sig, "firebase") {
		t.Fatalf("unexpected ok=%v sig=%q", ok, sig)
	}
}

func TestBuildCognitoSignUpProbe(t *testing.T) {
	c := Credentials{AWSRegion: "eu-west-1", CognitoClientID: "abc123", CognitoUserPoolID: "eu-west-1_XXX"}
	p := BuildCognitoSignUpProbe(c, "test@example.com")
	if !strings.Contains(p.URL, "cognito-idp.eu-west-1.amazonaws.com") {
		t.Fatalf("unexpected url %q", p.URL)
	}
}
