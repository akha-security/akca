package businesslogic

import "strings"

// Probe describes a financial / cart manipulation test value.
type Probe struct {
	Name   string
	Value  string
	Signal string
}

// FinancialProbes returns floating-point and rounding edge-case values.
func FinancialProbes() []Probe {
	return []Probe{
		{Name: "float_micro", Value: "0.00000001", Signal: "float_rounding_anomaly"},
		{Name: "float_max", Value: "9999999999999.99", Signal: "float_overflow_anomaly"},
		{Name: "float_nan", Value: "NaN", Signal: "nan_accepted"},
		{Name: "float_infinity", Value: "Infinity", Signal: "infinity_accepted"},
		{Name: "float_negative_zero", Value: "-0.00", Signal: "negative_zero_anomaly"},
		{Name: "price_zero", Value: "0", Signal: "zero_price_accepted"},
		{Name: "price_negative", Value: "-0.01", Signal: "negative_price_accepted"},
	}
}

// QuantityProbes returns negative and integer-overflow quantity values.
func QuantityProbes() []Probe {
	return []Probe{
		{Name: "qty_negative_one", Value: "-1", Signal: "negative_quantity_accepted"},
		{Name: "qty_negative_large", Value: "-1000", Signal: "negative_quantity_accepted"},
		{Name: "qty_int32_overflow", Value: "2147483648", Signal: "integer_overflow_anomaly"},
		{Name: "qty_int64_overflow", Value: "9223372036854775808", Signal: "integer_overflow_anomaly"},
		{Name: "qty_zero", Value: "0", Signal: "zero_quantity_accepted"},
	}
}

// AllProbes merges financial and quantity probes for a parameter name hint.
func AllProbes(param string) []Probe {
	lower := strings.ToLower(param)
	switch {
	case strings.Contains(lower, "qty"), strings.Contains(lower, "quantity"), strings.Contains(lower, "amount"):
		return append(QuantityProbes(), FinancialProbes()...)
	case strings.Contains(lower, "price"), strings.Contains(lower, "total"), strings.Contains(lower, "balance"):
		return append(FinancialProbes(), QuantityProbes()...)
	default:
		out := append([]Probe{}, FinancialProbes()...)
		out = append(out, QuantityProbes()...)
		return out
	}
}
