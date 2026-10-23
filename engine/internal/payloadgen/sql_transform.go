package payloadgen

import "strings"

// commentCaseSQL changes keyword spelling and separator whitespace only.
// Quoted values/identifiers and existing comments remain opaque byte strings.
func commentCaseSQL(value string) string {
	keywords := map[string]bool{}
	for _, word := range strings.Fields("select union all from where and or not null is as join on having group order by limit offset insert into update delete values set case when then else end sleep waitfor delay pg_sleep benchmark") {
		keywords[word] = true
	}
	var out strings.Builder
	for i := 0; i < len(value); {
		start := i
		switch {
		case value[i] == '\'' || value[i] == '"' || value[i] == '`' || value[i] == '[':
			quote := value[i]
			close := quote
			if quote == '[' {
				close = ']'
			}
			i++
			for i < len(value) {
				if value[i] == '\\' && i+1 < len(value) {
					i += 2
					continue
				}
				if value[i] == close {
					i++
					if i < len(value) && value[i] == close {
						i++
						continue
					}
					break
				}
				i++
			}
			out.WriteString(value[start:i])
		case strings.HasPrefix(value[i:], "--") || value[i] == '#':
			for i < len(value) && value[i] != '\n' {
				i++
			}
			if i < len(value) {
				i++
			}
			out.WriteString(value[start:i])
		case strings.HasPrefix(value[i:], "/*"):
			end := strings.Index(value[i+2:], "*/")
			if end < 0 {
				i = len(value)
			} else {
				i += end + 4
			}
			out.WriteString(value[start:i])
		case value[i] == '$':
			j := i + 1
			for j < len(value) && (value[j] == '_' || value[j] >= 'a' && value[j] <= 'z' || value[j] >= 'A' && value[j] <= 'Z' || value[j] >= '0' && value[j] <= '9') {
				j++
			}
			if j < len(value) && value[j] == '$' {
				delimiter := value[i : j+1]
				end := strings.Index(value[j+1:], delimiter)
				if end < 0 {
					i = len(value)
				} else {
					i = j + 1 + end + len(delimiter)
				}
				out.WriteString(value[start:i])
			} else {
				out.WriteByte(value[i])
				i++
			}
		case value[i] == ' ' || value[i] == '\t' || value[i] == '\r' || value[i] == '\n':
			for i < len(value) && strings.ContainsRune(" \t\r\n", rune(value[i])) {
				i++
			}
			out.WriteString("/**/")
		case sqlWordByte(value[i]):
			for i < len(value) && sqlWordByte(value[i]) {
				i++
			}
			word := value[start:i]
			if keywords[strings.ToLower(word)] {
				word = deterministicCaseMix(word)
			}
			out.WriteString(word)
		default:
			out.WriteByte(value[i])
			i++
		}
	}
	return out.String()
}

func sqlWordByte(c byte) bool {
	return c == '_' || c >= 128 || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
