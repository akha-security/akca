package modules

import "testing"

func TestSensitiveDataSignalConfirmationIsKindAndValueSpecific(t *testing.T) {
	body := `{"card_number":"4539578763621486","beneficiary_iban":"GB82WEST12345698765432"}`
	if !sensitiveDataSignalConfirmed(body, `{}`, "credit_card", "4539578763621486") {
		t.Fatal("expected exact card signal")
	}
	if sensitiveDataSignalConfirmed(body, `{}`, "credit_card", "GB82WEST12345698765432") {
		t.Fatal("IBAN must not satisfy card proof")
	}
	if sensitiveDataSignalConfirmed(body, body, "credit_card", "4539578763621486") {
		t.Fatal("baseline-identical data must not satisfy proof")
	}
}
