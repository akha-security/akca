package mutation

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Classify detects the semantic ValueType of a raw string value.
func Classify(value string, hint *SchemaHint) ValueType {
	if hint != nil {
		if vt := classifyFromHint(hint, value); vt != TypeUnknown {
			return vt
		}
	}

	if value == "" {
		return TypeEmpty
	}

	paramName := ""
	if hint != nil {
		paramName = hint.ParamName
	}

	if isBoolean(value) {
		return TypeBoolean
	}
	if reUUID.MatchString(value) {
		return TypeUUID
	}
	if isJWT(value) {
		return TypeJWT
	}
	if reEmail.MatchString(value) {
		return TypeEmail
	}
	if isIPv4(value) {
		return TypeIPv4
	}
	if isIPv6(value) {
		return TypeIPv6
	}
	if reTimestamp.MatchString(value) {
		return TypeTimestamp
	}
	if reDate.MatchString(value) {
		return TypeDate
	}
	if reStructuredCode.MatchString(value) {
		return TypeStructuredCode
	}
	if isCreditCard(value) {
		return TypeCreditCard
	}
	if rePhoneNumber.MatchString(value) && len(value) >= 8 {
		return TypePhoneNumber
	}
	if reFloat.MatchString(value) {
		return TypeFloat
	}
	if reInteger.MatchString(value) {
		if isIDParamName(paramName) {
			return TypeSequentialID
		}
		return TypeInteger
	}
	if reHexEncoded.MatchString(value) {
		return TypeHexEncoded
	}
	if isBase64(value) {
		return TypeBase64
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return TypeURL
	}
	if isJSON(value) {
		return TypeJSON
	}
	if strings.HasPrefix(value, "/") && len(value) > 1 {
		return TypePath
	}
	if reSlug.MatchString(value) {
		return TypeSlug
	}
	if hint != nil && len(hint.Enum) > 0 {
		for _, e := range hint.Enum {
			if e == value {
				return TypeEnum
			}
		}
	}
	if isEnumParamName(paramName) {
		return TypeEnum
	}

	return TypeUnknown
}

func classifyFromHint(hint *SchemaHint, value string) ValueType {
	switch strings.ToLower(hint.Format) {
	case "uuid":
		return TypeUUID
	case "email":
		return TypeEmail
	case "date-time", "datetime":
		return TypeTimestamp
	case "date":
		return TypeDate
	case "uri", "url":
		return TypeURL
	case "ipv4":
		return TypeIPv4
	case "ipv6":
		return TypeIPv6
	case "byte":
		return TypeBase64
	}

	switch strings.ToLower(hint.Type) {
	case "integer":
		if isIDParamName(hint.ParamName) {
			return TypeSequentialID
		}
		return TypeInteger
	case "number":
		if strings.Contains(value, ".") {
			return TypeFloat
		}
		return TypeInteger
	case "boolean":
		return TypeBoolean
	}

	if len(hint.Enum) > 0 {
		return TypeEnum
	}

	return TypeUnknown
}

var booleanValues = map[string]bool{
	"true": true, "false": true,
	"yes": true, "no": true,
	"on": true, "off": true,
}

func isBoolean(value string) bool {
	_, ok := booleanValues[strings.ToLower(value)]
	return ok
}

var (
	reUUID           = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reEmail          = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$`)
	reTimestamp      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}`)
	reDate           = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	reStructuredCode = regexp.MustCompile(`^[A-Z]{1,5}-\d{2,10}(-\d+)?$`)
	rePhoneNumber    = regexp.MustCompile(`^\+?\d[\d\s\-()]{7,}$`)
	reFloat          = regexp.MustCompile(`^-?\d+\.\d+$`)
	reInteger        = regexp.MustCompile(`^-?\d+$`)
	reHexEncoded     = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	reSlug           = regexp.MustCompile(`^[a-z0-9]+([_-][a-z0-9]+)+$`)
)

func isIPv4(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func isIPv6(value string) bool {
	if !strings.Contains(value, ":") {
		return false
	}
	ip := net.ParseIP(value)
	return ip != nil && ip.To4() == nil
}

func isJWT(value string) bool {
	if !strings.HasPrefix(value, "eyJ") {
		return false
	}
	parts := strings.Split(value, ".")
	return len(parts) == 3
}

func isCreditCard(value string) bool {
	if len(value) < 13 || len(value) > 19 {
		return false
	}
	for _, r := range value {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return luhnCheck(value)
}

func luhnCheck(number string) bool {
	sum := 0
	alt := false
	for i := len(number) - 1; i >= 0; i-- {
		n := int(number[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func isBase64(value string) bool {
	if len(value) < 8 || strings.HasPrefix(value, "/") || strings.Contains(value, " ") {
		return false
	}
	if reSlug.MatchString(value) || isCommonWord(value) {
		return false
	}
	hasPadding := strings.HasSuffix(value, "=")
	hasMixedCharset := false
	hasUpper, hasLower, hasDigit := false, false, false
	for _, r := range value {
		if unicode.IsUpper(r) {
			hasUpper = true
		} else if unicode.IsLower(r) {
			hasLower = true
		} else if unicode.IsDigit(r) {
			hasDigit = true
		}
	}
	hasMixedCharset = (hasUpper && hasLower && hasDigit) || (hasUpper && hasDigit) || (hasLower && hasDigit && hasUpper)
	if !hasPadding && !hasMixedCharset {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(value)
		if err != nil {
			return false
		}
	}
	return len(decoded) > 0
}

func isCommonWord(value string) bool {
	for _, r := range value {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return len(value) < 24
}

func isJSON(value string) bool {
	if len(value) < 2 || (value[0] != '{' && value[0] != '[') {
		return false
	}
	var js json.RawMessage
	return json.Unmarshal([]byte(value), &js) == nil
}

func isIDParamName(name string) bool {
	if name == "" {
		return false
	}
	lower := strings.ToLower(name)
	if lower == "id" || strings.HasSuffix(lower, "_id") || strings.HasSuffix(name, "Id") || strings.HasSuffix(name, "ID") {
		return true
	}
	switch lower {
	case "uid", "userid", "user_id", "account_id", "accountid",
		"member_id", "memberid", "order_id", "orderid",
		"product_id", "productid", "item_id", "itemid",
		"record_id", "recordid", "ref", "key":
		return true
	}
	return false
}

var enumParamNames = map[string]bool{
	"role": true, "status": true, "type": true, "level": true,
	"permission": true, "access_level": true, "user_role": true,
	"state": true, "category": true, "priority": true,
	"visibility": true, "scope": true, "tier": true,
}

func isEnumParamName(name string) bool {
	if name == "" {
		return false
	}
	return enumParamNames[strings.ToLower(name)]
}
