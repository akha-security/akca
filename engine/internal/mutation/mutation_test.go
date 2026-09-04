package mutation

import (
	"testing"
)

func TestClassifier(t *testing.T) {
	tests := []struct {
		value    string
		hint     *SchemaHint
		expected ValueType
	}{
		{"12345", nil, TypeInteger},
		{"1001", &SchemaHint{ParamName: "user_id"}, TypeSequentialID},
		{"550e8400-e29b-41d4-a716-446655440000", nil, TypeUUID},
		{"user@example.com", nil, TypeEmail},
		{"true", nil, TypeBoolean},
		{"192.168.1.1", nil, TypeIPv4},
		{"2026-01-15T10:30:00Z", nil, TypeTimestamp},
		{"ORD-00042", nil, TypeStructuredCode},
		{"https://example.com/api", nil, TypeURL},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M", nil, TypeJWT},
		{"", nil, TypeEmpty},
	}

	for _, tt := range tests {
		got := Classify(tt.value, tt.hint)
		if got != tt.expected {
			t.Errorf("Classify(%q) = %v, expected %v", tt.value, got, tt.expected)
		}
	}
}

func TestGenerator(t *testing.T) {
	// Test sequential ID mutation
	ms := Generate("1001", TypeSequentialID, nil)
	if len(ms.Mutations) == 0 {
		t.Fatal("expected mutations for sequential ID")
	}

	foundNext := false
	for _, m := range ms.Mutations {
		if m.Value == "1002" {
			foundNext = true
			break
		}
	}
	if !foundNext {
		t.Errorf("expected mutation '1002' for '1001', got: %+v", ms.Mutations)
	}

	// Test UUID mutation
	uMs := Generate("550e8400-e29b-41d4-a716-446655440000", TypeUUID, nil)
	foundNil := false
	for _, m := range uMs.Mutations {
		if m.Value == "00000000-0000-0000-0000-000000000000" {
			foundNil = true
			break
		}
	}
	if !foundNil {
		t.Errorf("expected nil UUID in mutations, got: %+v", uMs.Mutations)
	}
}
