package mutation

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// Generate produces mutations for the given value and detected type.
func Generate(value string, vtype ValueType, opts *GenerateOptions) MutationSet {
	if opts == nil {
		opts = DefaultGenerateOptions()
	}
	if opts.MaxPerIntent <= 0 {
		opts.MaxPerIntent = 5
	}

	ms := MutationSet{
		OriginalValue: value,
		DetectedType:  vtype,
	}

	var generators []func(string, *GenerateOptions) []Mutation

	switch vtype {
	case TypeInteger:
		generators = append(generators, generateInteger)
	case TypeFloat:
		generators = append(generators, generateFloat)
	case TypeBoolean:
		generators = append(generators, generateBoolean)
	case TypeUUID:
		generators = append(generators, generateUUID)
	case TypeEmail:
		generators = append(generators, generateEmail)
	case TypeTimestamp:
		generators = append(generators, generateTimestamp)
	case TypeDate:
		generators = append(generators, generateDate)
	case TypeIPv4:
		generators = append(generators, generateIPv4)
	case TypeIPv6:
		generators = append(generators, generateIPv6)
	case TypePath:
		generators = append(generators, generatePath)
	case TypeEnum:
		generators = append(generators, generateEnum)
	case TypeSequentialID:
		generators = append(generators, generateSequentialID)
	case TypeStructuredCode:
		generators = append(generators, generateStructuredCode)
	case TypeJWT:
		generators = append(generators, generateJWT)
	case TypeBase64:
		generators = append(generators, generateBase64)
	case TypeHexEncoded:
		generators = append(generators, generateHexEncoded)
	case TypeURL:
		generators = append(generators, generateURL)
	case TypePhoneNumber:
		generators = append(generators, generatePhoneNumber)
	case TypeCreditCard:
		generators = append(generators, generateCreditCard)
	case TypeSlug:
		generators = append(generators, generateSlug)
	case TypeJSON:
		generators = append(generators, generateJSON)
	case TypeEmpty, TypeUnknown:
		generators = append(generators, generateEmptyUnknown)
	}

	for _, gen := range generators {
		mutations := gen(value, opts)
		ms.Mutations = append(ms.Mutations, mutations...)
	}

	ms.Mutations = dedup(ms.Mutations, value, opts.MaxPerIntent)
	return ms
}

func dedup(mutations []Mutation, original string, maxPerIntent int) []Mutation {
	type dedupKey struct {
		intent MutationIntent
		value  string
	}
	seen := make(map[dedupKey]bool, len(mutations))
	intentCounts := make(map[MutationIntent]int)
	result := make([]Mutation, 0, len(mutations))

	for _, m := range mutations {
		if m.Value == original {
			continue
		}
		key := dedupKey{intent: m.Intent, value: m.Value}
		if seen[key] {
			continue
		}
		if intentCounts[m.Intent] >= maxPerIntent {
			continue
		}
		seen[key] = true
		intentCounts[m.Intent]++
		result = append(result, m)
	}
	return result
}

// --- Generator Implementations ---

func generateInteger(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		n = 1
	}

	if opts.hasIntent(IntentNeighbor) {
		m = append(m,
			Mutation{Value: strconv.FormatInt(n+1, 10), Intent: IntentNeighbor, Label: "increment by 1"},
			Mutation{Value: strconv.FormatInt(n-1, 10), Intent: IntentNeighbor, Label: "decrement by 1"},
			Mutation{Value: "0", Intent: IntentNeighbor, Label: "zero value"},
		)
	}
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: "-1", Intent: IntentBoundary, Label: "negative one"},
			Mutation{Value: strconv.FormatInt(math.MaxInt32, 10), Intent: IntentBoundary, Label: "int32 max"},
			Mutation{Value: strconv.FormatInt(math.MinInt32, 10), Intent: IntentBoundary, Label: "int32 min"},
			Mutation{Value: strconv.FormatInt(math.MaxInt64, 10), Intent: IntentBoundary, Label: "int64 max"},
			Mutation{Value: "9999999999", Intent: IntentBoundary, Label: "large overflow integer"},
		)
	}
	if opts.hasIntent(IntentEscalation) {
		m = append(m,
			Mutation{Value: "1", Intent: IntentEscalation, Label: "admin ID (1)"},
			Mutation{Value: "0", Intent: IntentEscalation, Label: "system ID (0)"},
		)
	}
	if opts.hasIntent(IntentFormat) {
		m = append(m,
			Mutation{Value: strconv.FormatInt(n, 10) + ".0", Intent: IntentFormat, Label: "float format"},
			Mutation{Value: "true", Intent: IntentFormat, Label: "boolean format"},
			Mutation{Value: "[" + strconv.FormatInt(n, 10) + "]", Intent: IntentFormat, Label: "array format"},
			Mutation{Value: `{"id":` + strconv.FormatInt(n, 10) + `}`, Intent: IntentFormat, Label: "object format"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m,
			Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"},
			Mutation{Value: "null", Intent: IntentEmpty, Label: "null string"},
		)
	}
	return m
}

func generateFloat(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		f = 1.0
	}

	if opts.hasIntent(IntentNeighbor) {
		m = append(m,
			Mutation{Value: strconv.FormatFloat(f+0.1, 'f', 2, 64), Intent: IntentNeighbor, Label: "increment float"},
			Mutation{Value: strconv.FormatFloat(f-0.1, 'f', 2, 64), Intent: IntentNeighbor, Label: "decrement float"},
			Mutation{Value: "0.0", Intent: IntentNeighbor, Label: "zero float"},
		)
	}
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: "-1.0", Intent: IntentBoundary, Label: "negative float"},
			Mutation{Value: "1e308", Intent: IntentBoundary, Label: "large float"},
			Mutation{Value: "NaN", Intent: IntentBoundary, Label: "NaN"},
			Mutation{Value: "Infinity", Intent: IntentBoundary, Label: "Infinity"},
		)
	}
	if opts.hasIntent(IntentFormat) {
		m = append(m,
			Mutation{Value: strconv.FormatInt(int64(f), 10), Intent: IntentFormat, Label: "integer conversion"},
			Mutation{Value: "true", Intent: IntentFormat, Label: "boolean format"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"})
	}
	return m
}

func generateBoolean(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	lower := strings.ToLower(value)
	isTrue := (lower == "true" || lower == "1" || lower == "yes" || lower == "on")

	if opts.hasIntent(IntentNeighbor) {
		if isTrue {
			m = append(m, Mutation{Value: "false", Intent: IntentNeighbor, Label: "invert to false"})
		} else {
			m = append(m, Mutation{Value: "true", Intent: IntentNeighbor, Label: "invert to true"})
		}
	}
	if opts.hasIntent(IntentEscalation) {
		m = append(m,
			Mutation{Value: "true", Intent: IntentEscalation, Label: "privilege enable (true)"},
			Mutation{Value: "1", Intent: IntentEscalation, Label: "privilege enable (1)"},
		)
	}
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: "2", Intent: IntentBoundary, Label: "integer 2"},
			Mutation{Value: "-1", Intent: IntentBoundary, Label: "integer -1"},
		)
	}
	if opts.hasIntent(IntentFormat) {
		m = append(m,
			Mutation{Value: "yes", Intent: IntentFormat, Label: "yes string"},
			Mutation{Value: "no", Intent: IntentFormat, Label: "no string"},
			Mutation{Value: "null", Intent: IntentFormat, Label: "null"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"})
	}
	return m
}

func generateUUID(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	if opts.hasIntent(IntentNeighbor) {
		m = append(m,
			Mutation{Value: uuid.New().String(), Intent: IntentNeighbor, Label: "random valid v4 UUID"},
		)
	}
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: "00000000-0000-0000-0000-000000000000", Intent: IntentBoundary, Label: "nil UUID"},
			Mutation{Value: "ffffffff-ffff-ffff-ffff-ffffffffffff", Intent: IntentBoundary, Label: "max UUID"},
		)
	}
	if opts.hasIntent(IntentEscalation) {
		m = append(m,
			Mutation{Value: "00000000-0000-0000-0000-000000000001", Intent: IntentEscalation, Label: "system/admin UUID 1"},
		)
	}
	if opts.hasIntent(IntentFormat) {
		m = append(m,
			Mutation{Value: "invalid-uuid-token", Intent: IntentFormat, Label: "invalid UUID string"},
			Mutation{Value: "123", Intent: IntentFormat, Label: "numeric ID format"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"})
	}
	return m
}

func generateEmail(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	domain := "example.com"
	parts := strings.Split(value, "@")
	if len(parts) == 2 {
		domain = parts[1]
	}

	if opts.hasIntent(IntentNeighbor) {
		m = append(m,
			Mutation{Value: "admin@" + domain, Intent: IntentNeighbor, Label: "admin email"},
			Mutation{Value: "root@" + domain, Intent: IntentNeighbor, Label: "root email"},
			Mutation{Value: "support@" + domain, Intent: IntentNeighbor, Label: "support email"},
		)
	}
	if opts.hasIntent(IntentEscalation) {
		m = append(m,
			Mutation{Value: "admin@localhost", Intent: IntentEscalation, Label: "admin localhost"},
			Mutation{Value: "root@127.0.0.1", Intent: IntentEscalation, Label: "root loopback"},
		)
	}
	if opts.hasIntent(IntentFormat) {
		m = append(m,
			Mutation{Value: parts[0] + "+test@" + domain, Intent: IntentFormat, Label: "plus addressing"},
			Mutation{Value: parts[0] + "%00@" + domain, Intent: IntentFormat, Label: "null byte email"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"})
	}
	return m
}

func generateTimestamp(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	if opts.hasIntent(IntentNeighbor) {
		m = append(m,
			Mutation{Value: "2026-01-01T00:00:00Z", Intent: IntentNeighbor, Label: "start of year"},
			Mutation{Value: "2030-01-01T00:00:00Z", Intent: IntentNeighbor, Label: "future timestamp"},
		)
	}
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: "1970-01-01T00:00:00Z", Intent: IntentBoundary, Label: "unix epoch start"},
			Mutation{Value: "9999-12-31T23:59:59Z", Intent: IntentBoundary, Label: "max timestamp"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"})
	}
	return m
}

func generateDate(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	if opts.hasIntent(IntentNeighbor) {
		m = append(m,
			Mutation{Value: "2026-01-01", Intent: IntentNeighbor, Label: "start of year"},
			Mutation{Value: "2030-01-01", Intent: IntentNeighbor, Label: "future date"},
		)
	}
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: "1970-01-01", Intent: IntentBoundary, Label: "epoch date"},
			Mutation{Value: "0000-00-00", Intent: IntentBoundary, Label: "zero date"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"})
	}
	return m
}

func generateIPv4(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	if opts.hasIntent(IntentNeighbor) {
		m = append(m,
			Mutation{Value: "127.0.0.1", Intent: IntentNeighbor, Label: "loopback 127.0.0.1"},
			Mutation{Value: "169.254.169.254", Intent: IntentNeighbor, Label: "cloud IMDS IP"},
			Mutation{Value: "10.0.0.1", Intent: IntentNeighbor, Label: "internal private IP 10.x"},
			Mutation{Value: "192.168.1.1", Intent: IntentNeighbor, Label: "internal router IP 192.168.x"},
		)
	}
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: "0.0.0.0", Intent: IntentBoundary, Label: "any IP (0.0.0.0)"},
			Mutation{Value: "255.255.255.255", Intent: IntentBoundary, Label: "broadcast IP"},
		)
	}
	if opts.hasIntent(IntentFormat) {
		m = append(m,
			Mutation{Value: "2130706433", Intent: IntentFormat, Label: "decimal loopback"},
			Mutation{Value: "0x7f000001", Intent: IntentFormat, Label: "hex loopback"},
			Mutation{Value: "127.1", Intent: IntentFormat, Label: "short loopback"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"})
	}
	return m
}

func generateIPv6(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	if opts.hasIntent(IntentNeighbor) {
		m = append(m,
			Mutation{Value: "::1", Intent: IntentNeighbor, Label: "IPv6 loopback"},
			Mutation{Value: "::", Intent: IntentNeighbor, Label: "IPv6 any"},
			Mutation{Value: "[0:0:0:0:0:ffff:127.0.0.1]", Intent: IntentNeighbor, Label: "IPv6 mapped IPv4"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"})
	}
	return m
}

func generatePath(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	if opts.hasIntent(IntentNeighbor) {
		m = append(m,
			Mutation{Value: "/admin", Intent: IntentNeighbor, Label: "admin path"},
			Mutation{Value: "/api", Intent: IntentNeighbor, Label: "api root"},
			Mutation{Value: "/", Intent: IntentNeighbor, Label: "root path"},
		)
	}
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: "/..;/admin", Intent: IntentBoundary, Label: "matrix bypass path"},
			Mutation{Value: "/%2e%2e/admin", Intent: IntentBoundary, Label: "url encoded traversal path"},
			Mutation{Value: "/../../../../../../etc/passwd", Intent: IntentBoundary, Label: "traversal path"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty path"})
	}
	return m
}

func generateEnum(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	if opts.hasIntent(IntentEscalation) {
		m = append(m,
			Mutation{Value: "admin", Intent: IntentEscalation, Label: "admin role"},
			Mutation{Value: "administrator", Intent: IntentEscalation, Label: "administrator role"},
			Mutation{Value: "root", Intent: IntentEscalation, Label: "root role"},
			Mutation{Value: "superuser", Intent: IntentEscalation, Label: "superuser role"},
			Mutation{Value: "system", Intent: IntentEscalation, Label: "system role"},
		)
	}
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: "INVALID_ENUM_STATE", Intent: IntentBoundary, Label: "invalid enum"},
			Mutation{Value: "null", Intent: IntentBoundary, Label: "null enum"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty enum"})
	}
	return m
}

func generateSequentialID(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		n = 1000
	}

	if opts.hasIntent(IntentNeighbor) {
		m = append(m,
			Mutation{Value: strconv.FormatInt(n+1, 10), Intent: IntentNeighbor, Label: "next sequential ID"},
			Mutation{Value: strconv.FormatInt(n-1, 10), Intent: IntentNeighbor, Label: "prev sequential ID"},
			Mutation{Value: strconv.FormatInt(n+10, 10), Intent: IntentNeighbor, Label: "sequential ID +10"},
			Mutation{Value: strconv.FormatInt(n-10, 10), Intent: IntentNeighbor, Label: "sequential ID -10"},
		)
	}
	if opts.hasIntent(IntentEscalation) {
		m = append(m,
			Mutation{Value: "1", Intent: IntentEscalation, Label: "first user/admin ID (1)"},
			Mutation{Value: "2", Intent: IntentEscalation, Label: "second user ID (2)"},
			Mutation{Value: "0", Intent: IntentEscalation, Label: "system ID (0)"},
		)
	}
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: "-1", Intent: IntentBoundary, Label: "negative ID"},
			Mutation{Value: "0", Intent: IntentBoundary, Label: "zero ID"},
			Mutation{Value: strconv.FormatInt(math.MaxInt32, 10), Intent: IntentBoundary, Label: "max int32 ID"},
		)
	}
	if opts.hasIntent(IntentFormat) {
		m = append(m,
			Mutation{Value: "[" + strconv.FormatInt(n, 10) + "]", Intent: IntentFormat, Label: "array wrapped ID"},
			Mutation{Value: `{"id":` + strconv.FormatInt(n, 10) + `}`, Intent: IntentFormat, Label: "object wrapped ID"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty ID"})
	}
	return m
}

var reCodeNum = regexp.MustCompile(`^(.*?)(\d+)$`)

func generateStructuredCode(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	match := reCodeNum.FindStringSubmatch(value)
	if len(match) == 3 {
		prefix := match[1]
		numStr := match[2]
		num, _ := strconv.ParseInt(numStr, 10, 64)
		format := "%s%0" + strconv.Itoa(len(numStr)) + "d"

		if opts.hasIntent(IntentNeighbor) {
			m = append(m,
				Mutation{Value: fmt.Sprintf(format, prefix, num+1), Intent: IntentNeighbor, Label: "next code"},
				Mutation{Value: fmt.Sprintf(format, prefix, num-1), Intent: IntentNeighbor, Label: "prev code"},
				Mutation{Value: fmt.Sprintf(format, prefix, int64(1)), Intent: IntentNeighbor, Label: "first code (1)"},
			)
		}
		if opts.hasIntent(IntentBoundary) {
			m = append(m,
				Mutation{Value: fmt.Sprintf(format, prefix, int64(0)), Intent: IntentBoundary, Label: "zero code"},
			)
		}
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty code"})
	}
	return m
}

func generateJWT(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	parts := strings.Split(value, ".")
	if len(parts) == 3 {
		// None alg attack
		headerJSON := `{"alg":"none","typ":"JWT"}`
		noneHeader := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))

		if opts.hasIntent(IntentEscalation) {
			// Try decoding payload and injecting admin role
			payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err == nil {
				var pMap map[string]interface{}
				if json.Unmarshal(payloadBytes, &pMap) == nil {
					pMap["role"] = "admin"
					pMap["admin"] = true
					pMap["is_admin"] = true
					mutPayload, _ := json.Marshal(pMap)
					encPayload := base64.RawURLEncoding.EncodeToString(mutPayload)
					m = append(m,
						Mutation{Value: noneHeader + "." + encPayload + ".", Intent: IntentEscalation, Label: "none alg with admin role"},
						Mutation{Value: parts[0] + "." + encPayload + "." + parts[2], Intent: IntentEscalation, Label: "tampered payload with original signature"},
					)
				}
			}
			m = append(m,
				Mutation{Value: noneHeader + "." + parts[1] + ".", Intent: IntentEscalation, Label: "none alg with original payload"},
				Mutation{Value: parts[0] + "." + parts[1] + ".", Intent: IntentEscalation, Label: "empty signature"},
			)
		}
		if opts.hasIntent(IntentBoundary) {
			m = append(m,
				Mutation{Value: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.", Intent: IntentBoundary, Label: "minimal empty JWT"},
			)
		}
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty JWT"})
	}
	return m
}

func generateBase64(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, _ = base64.URLEncoding.DecodeString(value)
	}

	if len(decoded) > 0 && opts.hasIntent(IntentNeighbor) {
		// Mutate inner decoded value if it's JSON or text
		if isJSON(string(decoded)) {
			adminJSON := `{"admin":true,"role":"admin"}`
			m = append(m, Mutation{Value: base64.StdEncoding.EncodeToString([]byte(adminJSON)), Intent: IntentNeighbor, Label: "base64 admin JSON"})
		}
	}
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: base64.StdEncoding.EncodeToString([]byte("0")), Intent: IntentBoundary, Label: "base64 zero"},
			Mutation{Value: "AAA=", Intent: IntentBoundary, Label: "base64 null bytes"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"})
	}
	return m
}

func generateHexEncoded(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: strings.Repeat("0", len(value)), Intent: IntentBoundary, Label: "zero hex"},
			Mutation{Value: strings.Repeat("f", len(value)), Intent: IntentBoundary, Label: "max hex"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty hex"})
	}
	return m
}

func generateURL(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	if opts.hasIntent(IntentNeighbor) {
		m = append(m,
			Mutation{Value: "http://127.0.0.1/", Intent: IntentNeighbor, Label: "loopback SSRF URL"},
			Mutation{Value: "http://169.254.169.254/latest/meta-data/", Intent: IntentNeighbor, Label: "IMDS SSRF URL"},
			Mutation{Value: "http://localhost/", Intent: IntentNeighbor, Label: "localhost SSRF URL"},
		)
	}
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: "javascript:alert(1)", Intent: IntentBoundary, Label: "javascript URI"},
			Mutation{Value: "data:text/html,<script>alert(1)</script>", Intent: IntentBoundary, Label: "data URI"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty URL"})
	}
	return m
}

func generatePhoneNumber(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	if opts.hasIntent(IntentNeighbor) {
		m = append(m,
			Mutation{Value: "+15551234567", Intent: IntentNeighbor, Label: "test US phone"},
			Mutation{Value: "0000000000", Intent: IntentNeighbor, Label: "zero phone"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty phone"})
	}
	return m
}

func generateCreditCard(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	if opts.hasIntent(IntentNeighbor) {
		m = append(m,
			Mutation{Value: "4532015112830366", Intent: IntentNeighbor, Label: "Luhn-valid test Visa"},
		)
	}
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: "0000000000000000", Intent: IntentBoundary, Label: "zero card"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty card"})
	}
	return m
}

func generateSlug(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	if opts.hasIntent(IntentNeighbor) {
		m = append(m,
			Mutation{Value: "admin", Intent: IntentNeighbor, Label: "admin slug"},
			Mutation{Value: "dashboard", Intent: IntentNeighbor, Label: "dashboard slug"},
			Mutation{Value: "root", Intent: IntentNeighbor, Label: "root slug"},
			Mutation{Value: "settings", Intent: IntentNeighbor, Label: "settings slug"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty slug"})
	}
	return m
}

func generateJSON(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	if opts.hasIntent(IntentEscalation) {
		m = append(m,
			Mutation{Value: `{"admin":true,"role":"admin"}`, Intent: IntentEscalation, Label: "admin JSON object"},
			Mutation{Value: `{"is_admin":1,"user_id":1}`, Intent: IntentEscalation, Label: "privilege JSON"},
		)
	}
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: `{}`, Intent: IntentBoundary, Label: "empty JSON object"},
			Mutation{Value: `[]`, Intent: IntentBoundary, Label: "empty JSON array"},
			Mutation{Value: `null`, Intent: IntentBoundary, Label: "null JSON"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"})
	}
	return m
}

func generateEmptyUnknown(value string, opts *GenerateOptions) []Mutation {
	var m []Mutation
	if opts.hasIntent(IntentBoundary) {
		m = append(m,
			Mutation{Value: "0", Intent: IntentBoundary, Label: "zero value"},
			Mutation{Value: "-1", Intent: IntentBoundary, Label: "negative one"},
			Mutation{Value: "null", Intent: IntentBoundary, Label: "null string"},
			Mutation{Value: "undefined", Intent: IntentBoundary, Label: "undefined string"},
			Mutation{Value: "true", Intent: IntentBoundary, Label: "true string"},
			Mutation{Value: "false", Intent: IntentBoundary, Label: "false string"},
		)
	}
	if opts.hasIntent(IntentEscalation) {
		m = append(m,
			Mutation{Value: "admin", Intent: IntentEscalation, Label: "admin word"},
			Mutation{Value: "1", Intent: IntentEscalation, Label: "admin ID (1)"},
		)
	}
	if opts.hasIntent(IntentEmpty) {
		m = append(m, Mutation{Value: "", Intent: IntentEmpty, Label: "empty string"})
	}
	return m
}
