package resilience

import "fmt"

const (
	TargetEndpoints = 100_000
	TargetFindings  = 50_000
	TargetEvents    = 1_000_000
	MaxPayloadBytes = 64 * 1024
)

func GenerateEndpoints(n int) []string {
	if n <= 0 {
		return nil
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = fmt.Sprintf("https://api.massive.test/v1/resource/%d", i)
	}
	return out
}

func OversizedPayload(size int) map[string]interface{} {
	if size > MaxPayloadBytes {
		size = MaxPayloadBytes
	}
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = 'A'
	}
	return map[string]interface{}{"blob": string(buf), "size": size}
}
