// Package testfixtures provides synthetic provider-shaped values for tests.
//
// Values are assembled at runtime so source control and secret-scanning tools
// never see a complete credential-shaped string. None of these values are real.
package testfixtures

import "strings"

func join(parts ...string) string {
	return strings.Join(parts, "")
}

func AWSExampleAccessKey() string {
	return join("AK", "IAIOSFODNN7EXAMPLE")
}

func AWSDetectableAccessKey() string {
	return join("AK", "IAIOSFODNN7EXAMP1A")
}

func GitHubToken() string {
	return join("gh", "p_", "1234567890", "abcdefghijklmnopqrstuvwxyz")
}

func GitHubShortToken() string {
	return join("gh", "p_", "abcdefghijklmnopqrstuvwxyz")
}

func GitHubHintToken() string {
	return join("gh", "p_", "abcdefghijklmnop")
}

func GitHubReportToken() string {
	return join("gh", "p_", "supersecret1234567890")
}

func GitHubQueryToken() string {
	return join("gh", "p_", "testtesttoken123")
}

func GoogleAPIKey() string {
	return join("AI", "za", "012345678901234567890123456789abcde")
}

func GoogleCloudAPIKey() string {
	return join("AI", "za", "Sy0123456789abcdefghijklmnopqrstuvx")
}

func StripeSecretKey() string {
	return join("sk", "_live_", "0123456789abcdefghij0123")
}

func SlackWebhook() string {
	return join("https://hooks.slack.com/", "services/", "T00000000/", "B00000000/", "abcdefABCDEF1234")
}

func SlackToken() string {
	return join("xo", "xb-", "1234567890-", "abcdefghijklmnop")
}

func OpenAIKey() string {
	return join("sk", "-proj-", "abcdefghijklmnopqrstuvwxyz0123")
}

func AnthropicKey() string {
	return join("sk", "-ant-", "abcdefghijklmnopqrstuvwxyz0123")
}

func HuggingFaceToken() string {
	return join("hf", "_", "abcdefghijklmnopqrstuvwxyz0123456789")
}
