package reflection

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

var (
	pathUUIDRe       = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	pathIndexParamRe = regexp.MustCompile(`^path_segment_([0-9]+)$`)
)

// EffectiveMethod returns the method that can actually carry the discovered
// injection surface. Body parameters discovered from a GET-rendered form must
// be submitted as POST; query, header, cookie and path probes preserve the
// endpoint's native method.
func EffectiveMethod(method, location string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	switch strings.ToLower(strings.TrimSpace(location)) {
	case "form", "body", "post", "multipart", "json", "graphql", "graphql_query", "websocket", "xml":
		if method == "" || method == http.MethodGet {
			return http.MethodPost
		}
	}
	if method == "" {
		return http.MethodGet
	}
	return method
}

func BuildProbeRequestWithTemplate(endpointURL, method, param, location, value, bodyTemplate string) (string, []byte, map[string]string, error) {
	req, err := MutateRequest(RequestTemplate{
		Method: method, URL: endpointURL, Body: bodyTemplate,
	}, param, location, value)
	if err != nil {
		return "", nil, nil, err
	}
	return req.URL, req.Body, req.Headers, nil
}

// NativeRequest materializes a template without injecting a parameter.
func NativeRequest(template RequestTemplate) (MutatedRequest, error) {
	if strings.TrimSpace(template.URL) == "" {
		return MutatedRequest{}, fmt.Errorf("request template URL is empty")
	}
	method := strings.ToUpper(strings.TrimSpace(template.Method))
	if method == "" {
		method = http.MethodGet
	}
	headers := cloneStringMap(template.Headers)
	if template.ContentType != "" && headerValueCI(headers, "Content-Type") == "" {
		setHeaderCI(headers, "Content-Type", template.ContentType)
	}
	return materialized(method, template.URL, []byte(template.Body), headers)
}

// MutateRequest changes one discovered injection surface while retaining the
// original request. Failed mutations return an error, never a minimal fallback.
func MutateRequest(template RequestTemplate, param, location, value string) (MutatedRequest, error) {
	method := strings.ToUpper(strings.TrimSpace(template.Method))
	endpointURL := strings.TrimSpace(template.URL)
	if endpointURL == "" {
		return MutatedRequest{}, fmt.Errorf("request template URL is empty")
	}
	loc := strings.ToLower(strings.TrimSpace(location))
	method = EffectiveMethod(method, loc)
	headers := cloneStringMap(template.Headers)
	if strings.TrimSpace(template.ContentType) != "" && headerValueCI(headers, "Content-Type") == "" {
		headers["Content-Type"] = template.ContentType
	}

	body := template.Body
	switch loc {
	case "form", "body", "post":
		form := url.Values{}
		if body != "" {
			parsed, err := url.ParseQuery(body)
			if err != nil {
				return MutatedRequest{}, fmt.Errorf("decode form template: %w", err)
			}
			form = parsed
		}
		setFirstURLValue(form, param, value)
		setHeaderCI(headers, "Content-Type", "application/x-www-form-urlencoded")
		return materialized(method, endpointURL, []byte(form.Encode()), headers)
	case "json", "graphql", "websocket":
		var doc interface{}
		if body != "" {
			decoder := json.NewDecoder(strings.NewReader(body))
			decoder.UseNumber()
			if err := decoder.Decode(&doc); err != nil {
				return MutatedRequest{}, fmt.Errorf("decode JSON template: %w", err)
			}
			if err := decoder.Decode(new(interface{})); err != io.EOF {
				return MutatedRequest{}, fmt.Errorf("JSON template contains trailing data")
			}
		} else {
			doc = make(map[string]interface{})
		}
		normParam := strings.ReplaceAll(param, "[", ".")
		normParam = strings.ReplaceAll(normParam, "]", "")
		normParam = strings.Trim(normParam, ".")
		if template.WireEncoding != "" && template.WireEncoding != "json_unicode" {
			return MutatedRequest{}, fmt.Errorf("unsupported JSON wire encoding: %s", template.WireEncoding)
		}
		if setJSONPath(doc, strings.Split(normParam, "."), value, template.WireEncoding) {
			mutated, err := json.Marshal(doc)
			if err == nil {
				if headerValueCI(headers, "Content-Type") == "" {
					headers["Content-Type"] = "application/json"
				}
				return materialized(method, endpointURL, mutated, headers)
			}
		}
	case "graphql_query":
		mutated, ok := mutateGraphQLQuery(template.Body, param, value)
		if ok {
			setHeaderCI(headers, "Content-Type", "application/graphql")
			return materialized(method, endpointURL, []byte(mutated), headers)
		}
	case "xml":
		mutated, ok := mutateXMLBody(template.Body, param, value)
		if ok {
			if headerValueCI(headers, "Content-Type") == "" {
				setHeaderCI(headers, "Content-Type", "application/xml")
			}
			return materialized(method, endpointURL, mutated, headers)
		}
	case "multipart":
		mutated, mediaType, ok := mutateMultipartBody([]byte(template.Body), headerValueCI(headers, "Content-Type"), param, value, template.AllowNewFields)
		if ok {
			setHeaderCI(headers, "Content-Type", mediaType)
			return materialized(method, endpointURL, mutated, headers)
		}
	case "header":
		setHeaderCI(headers, param, value)
		return materialized(method, endpointURL, []byte(template.Body), headers)
	case "cookie":
		setHeaderCI(headers, "Cookie", mutateCookieHeader(headerValueCI(headers, "Cookie"), param, value))
		return materialized(method, endpointURL, []byte(template.Body), headers)
	case "path":
		probeURL, _, _, err := BuildProbeRequest(endpointURL, method, param, loc, value)
		if err != nil {
			return MutatedRequest{}, err
		}
		return MutatedRequest{Method: method, URL: probeURL, Body: []byte(template.Body), Headers: headers}, nil
	case "query", "":
		probeURL, _, _, err := BuildProbeRequest(endpointURL, method, param, "query", value)
		if err != nil {
			return MutatedRequest{}, err
		}
		return MutatedRequest{Method: method, URL: probeURL, Body: []byte(template.Body), Headers: headers}, nil
	}

	// A failed mutation must never be retried on a different surface or with a
	// reconstructed body: that would drop CSRF tokens, siblings and envelopes.
	return MutatedRequest{}, fmt.Errorf("cannot mutate %q on %s request template", param, loc)
}

func mutateXMLBody(body, param, value string) ([]byte, bool) {
	if strings.TrimSpace(body) == "" {
		return nil, false
	}
	wantedPath, wantedAttr, _ := strings.Cut(param, "@")
	decoder := xml.NewDecoder(strings.NewReader(body))
	var output bytes.Buffer
	encoder := xml.NewEncoder(&output)
	stack := make([]string, 0, 8)
	mutated := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false
		}
		switch typed := token.(type) {
		case xml.StartElement:
			if !mutated && wantedAttr == "" && strings.EqualFold(strings.Join(stack, "."), wantedPath) {
				return nil, false
			}
			stack = append(stack, typed.Name.Local)
			if !mutated && wantedAttr != "" && strings.EqualFold(strings.Join(stack, "."), wantedPath) {
				for index := range typed.Attr {
					if strings.EqualFold(typed.Attr[index].Name.Local, wantedAttr) {
						typed.Attr[index].Value = value
						mutated = true
					}
				}
				token = typed
			}
		case xml.CharData:
			if !mutated && wantedAttr == "" && strings.EqualFold(strings.Join(stack, "."), wantedPath) && strings.TrimSpace(string(typed)) != "" {
				token = xml.CharData([]byte(value))
				mutated = true
			}
		case xml.EndElement:
			if !mutated && wantedAttr == "" && strings.EqualFold(strings.Join(stack, "."), wantedPath) {
				if err := encoder.EncodeToken(xml.CharData([]byte(value))); err != nil {
					return nil, false
				}
				mutated = true
			}
			if err := encoder.EncodeToken(token); err != nil {
				return nil, false
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if err := encoder.EncodeToken(token); err != nil {
			return nil, false
		}
	}
	if encoder.Flush() != nil || !mutated {
		return nil, false
	}
	return output.Bytes(), true
}

func mutateMultipartBody(body []byte, contentType, param, value string, allowNewFields ...bool) ([]byte, string, bool) {
	mediaType, parameters, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(strings.ToLower(mediaType), "multipart/") || parameters["boundary"] == "" {
		return nil, "", false
	}
	reader := multipart.NewReader(bytes.NewReader(body), parameters["boundary"])
	var output bytes.Buffer
	writer := multipart.NewWriter(&output)
	if err := writer.SetBoundary(parameters["boundary"]); err != nil {
		return nil, "", false
	}
	mutated := false
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", false
		}
		partBody, readErr := io.ReadAll(io.LimitReader(part, (16<<20)+1))
		_ = part.Close()
		if readErr != nil || len(partBody) > 16<<20 {
			return nil, "", false
		}
		outPart, createErr := writer.CreatePart(part.Header)
		if createErr != nil {
			return nil, "", false
		}
		if !mutated && part.FormName() == param {
			partBody = []byte(value)
			mutated = true
		}
		if _, err := outPart.Write(partBody); err != nil {
			return nil, "", false
		}
	}
	if !mutated && len(allowNewFields) > 0 && allowNewFields[0] {
		if err := writer.WriteField(param, value); err != nil {
			return nil, "", false
		}
		mutated = true
	}
	if err := writer.Close(); err != nil || !mutated {
		return nil, "", false
	}
	return output.Bytes(), writer.FormDataContentType(), true
}

func mutateGraphQLQuery(query, variable, value string) (string, bool) {
	if strings.TrimSpace(query) == "" || strings.TrimSpace(variable) == "" {
		return "", false
	}
	// Raw application/graphql requests have no separate variables object. Only
	// mutate an explicit default value or a literal argument; never rewrite the
	// query shape or splice into field names.
	escaped := regexp.QuoteMeta(variable)
	scalar := `("(?:\\.|[^"\\])*"|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)`
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)(\$` + escaped + `\s*:\s*[\w\[\]!]+\s*=\s*)` + scalar),
		regexp.MustCompile(`(?m)(\b` + escaped + `\s*:\s*)` + scalar),
	}
	for _, pattern := range patterns {
		for _, match := range pattern.FindAllStringSubmatchIndex(query, -1) {
			if !graphQLCodePosition(query, match[0]) {
				continue
			}
			start, end := match[4], match[5]
			// Block strings require their own serializer. Do not rewrite a prefix
			// of one as an ordinary quoted scalar.
			if strings.HasPrefix(query[start:], `"""`) {
				continue
			}
			if end < len(query) && (isGraphQLName(query[end]) || query[end] == '.') {
				continue
			}
			replacement := strconv.Quote(value)
			if query[start] != '"' {
				var scalarValue interface{}
				d := json.NewDecoder(strings.NewReader(value))
				d.UseNumber()
				if d.Decode(&scalarValue) == nil && d.Decode(new(interface{})) == io.EOF {
					switch scalarValue.(type) {
					case json.Number, bool, nil:
						replacement = value
					}
				}
			}
			return query[:start] + replacement + query[end:], true
		}
	}
	return "", false
}

func isGraphQLName(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// GraphQLParameterNames returns scalar argument/default names which can be
// mutated without rebuilding a raw application/graphql request.
func GraphQLParameterNames(query string) []string {
	pattern := regexp.MustCompile(`(?:\$)?([A-Za-z_][A-Za-z0-9_]*)\s*:`)
	seen := map[string]bool{}
	var names []string
	for _, match := range pattern.FindAllStringSubmatchIndex(query, -1) {
		name := query[match[2]:match[3]]
		if seen[name] || !graphQLCodePosition(query, match[0]) {
			continue
		}
		if _, ok := mutateGraphQLQuery(query, name, "akca_probe"); ok {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

// Ignore apparent arguments inside comments, quoted strings and block strings.
func graphQLCodePosition(query string, position int) bool {
	for i := 0; i < position; i++ {
		if query[i] == '#' {
			for i < len(query) && query[i] != '\n' {
				i++
			}
			if i >= position {
				return false
			}
		}
		if i >= len(query) {
			break
		}
		if strings.HasPrefix(query[i:], `"""`) {
			i += 3
			for i < len(query) {
				if strings.HasPrefix(query[i:], `\"""`) {
					i += 4
					continue
				}
				if strings.HasPrefix(query[i:], `"""`) {
					break
				}
				i++
			}
			if i >= len(query) {
				return false
			}
			i += 2
			if i >= position {
				return false
			}
		} else if query[i] == '"' {
			for i++; i < len(query); i++ {
				if query[i] == '\\' {
					i++
					continue
				}
				if query[i] == '"' {
					break
				}
			}
			if i >= position {
				return false
			}
		}
	}
	return true
}

func mutateCookieHeader(raw, name, value string) string {
	parts := strings.Split(raw, ";")
	out := make([]string, 0, len(parts)+1)
	replaced := false
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, _, found := strings.Cut(part, "=")
		if found && strings.EqualFold(strings.TrimSpace(key), name) {
			out = append(out, name+"="+value)
			replaced = true
			continue
		}
		out = append(out, part)
	}
	if !replaced {
		out = append(out, name+"="+value)
	}
	return strings.Join(out, "; ")
}

func materialized(method, endpointURL string, body []byte, headers map[string]string) (MutatedRequest, error) {
	u, err := url.Parse(endpointURL)
	if err != nil {
		return MutatedRequest{}, err
	}
	return MutatedRequest{Method: method, URL: u.String(), Body: body, Headers: headers}, nil
}

func cloneStringMap(values map[string]string) map[string]string {
	out := make(map[string]string, len(values)+1)
	for key, value := range values {
		out[key] = value
	}
	return out
}

func headerValueCI(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func setHeaderCI(headers map[string]string, name, value string) {
	for key := range headers {
		if strings.EqualFold(key, name) {
			delete(headers, key)
		}
	}
	headers[name] = value
}

func setJSONPath(current interface{}, path []string, value string, wireEncoding ...string) bool {
	if len(path) == 0 {
		return false
	}
	switch node := current.(type) {
	case map[string]interface{}:
		if len(path) == 1 {
			currentVal, exists := node[path[0]]
			if exists {
				coerced, ok := schemaCompatibleJSONValue(currentVal, value)
				if !ok {
					return false
				}
				node[path[0]] = encodeJSONStringValue(coerced, wireEncoding)
				return true
			}
			node[path[0]] = encodeJSONStringValue(value, wireEncoding)
			return true
		}
		next, ok := node[path[0]]
		if !ok {
			nextMap := make(map[string]interface{})
			node[path[0]] = nextMap
			return setJSONPath(nextMap, path[1:], value, wireEncoding...)
		}
		return setJSONPath(next, path[1:], value, wireEncoding...)
	case []interface{}:
		idx, err := strconv.Atoi(path[0])
		if err == nil && idx >= 0 && idx < len(node) {
			if len(path) == 1 {
				coerced, ok := schemaCompatibleJSONValue(node[idx], value)
				if !ok {
					return false
				}
				node[idx] = encodeJSONStringValue(coerced, wireEncoding)
				return true
			}
			return setJSONPath(node[idx], path[1:], value, wireEncoding...)
		}
		// Fallback for unindexed path like "id" targeting an array of objects:
		mutatedAny := false
		for i := range node {
			if setJSONPath(node[i], path, value, wireEncoding...) {
				mutatedAny = true
			}
		}
		return mutatedAny
	default:
		return false
	}
}

func encodeJSONStringValue(value interface{}, encoding []string) interface{} {
	if len(encoding) > 0 && encoding[0] == "json_unicode" {
		if text, ok := value.(string); ok {
			return unicodeJSONString(text)
		}
	}
	return value
}

type unicodeJSONString string

func (s unicodeJSONString) MarshalJSON() ([]byte, error) {
	var out strings.Builder
	out.WriteByte('"')
	for _, unit := range utf16.Encode([]rune(s)) {
		fmt.Fprintf(&out, `\u%04x`, unit)
	}
	out.WriteByte('"')
	return []byte(out.String()), nil
}

func schemaCompatibleJSONValue(current interface{}, value string) (interface{}, bool) {
	switch current.(type) {
	case map[string]interface{}, []interface{}:
		// Never overwrite an object or array container node with a scalar probe string!
		return nil, false
	case bool:
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed, true
		}
		return value, true
	case float64:
		if parsed, err := strconv.ParseFloat(value, 64); err == nil {
			return parsed, true
		}
		return value, true
	case json.Number:
		if json.Valid([]byte(value)) && len(value) > 0 && (value[0] == '-' || value[0] >= '0' && value[0] <= '9') {
			return json.Number(value), true
		}
		return value, true
	case string, nil:
		return value, true
	default:
		return value, true
	}
}

// BuildProbeRequest injects a value into the correct request surface based on
// the discovered parameter location (query, form, JSON, header, cookie, path).
// Shared by the reflection analyzer and vulnerability modules so probes target
// the real injection point instead of always using the query string.
func BuildProbeRequest(endpointURL, method, param, location, value string) (string, []byte, map[string]string, error) {
	u, err := url.Parse(endpointURL)
	if err != nil {
		return "", nil, nil, err
	}
	headers := map[string]string{}
	switch strings.ToLower(location) {
	case "form", "multipart":
		form := url.Values{}
		setFirstURLValue(form, param, value)
		headers["Content-Type"] = "application/x-www-form-urlencoded"
		if strings.ToUpper(method) == "" || strings.ToUpper(method) == "GET" {
			method = "POST"
		}
		return u.String(), []byte(form.Encode()), headers, nil
	case "json", "graphql":
		doc := make(map[string]interface{})
		normParam := strings.ReplaceAll(param, "[", ".")
		normParam = strings.ReplaceAll(normParam, "]", "")
		normParam = strings.Trim(normParam, ".")
		setJSONPath(doc, strings.Split(normParam, "."), value)
		body, err := json.Marshal(doc)
		if err != nil {
			body = []byte(fmt.Sprintf("{%q:%q}", param, value))
		}
		headers["Content-Type"] = "application/json"
		if strings.ToUpper(method) == "" || strings.ToUpper(method) == "GET" {
			method = "POST"
		}
		return u.String(), body, headers, nil
	case "xml":
		body := fmt.Sprintf("<%s>%s</%s>", param, value, param)
		headers["Content-Type"] = "application/xml"
		if strings.ToUpper(method) == "" || strings.ToUpper(method) == "GET" {
			method = "POST"
		}
		return u.String(), []byte(body), headers, nil
	case "header":
		headers[param] = value
		return u.String(), nil, headers, nil
	case "cookie":
		headers["Cookie"] = param + "=" + value
		return u.String(), nil, headers, nil
	case "path":
		// Work on escaped segments so an encoded slash in a sibling stays one
		// segment, and keep the leading/trailing separators byte-for-byte.
		segments := strings.Split(u.EscapedPath(), "/")
		first := 0
		if len(segments) > 0 && segments[0] == "" {
			first = 1
		}
		targetIdx := -1
		if match := pathIndexParamRe.FindStringSubmatch(param); len(match) == 2 {
			if index, parseErr := strconv.Atoi(match[1]); parseErr == nil {
				if index >= 0 && first+index < len(segments) && segments[first+index] != "" {
					targetIdx = first + index
				}
			}
			if targetIdx < 0 {
				return "", nil, nil, fmt.Errorf("path parameter index out of range: %s", param)
			}
		}
		if targetIdx < 0 {
			for i, segment := range segments {
				decoded, _ := url.PathUnescape(segment)
				if decoded == "{"+param+"}" || decoded == ":"+param || decoded == "["+param+"]" {
					targetIdx = i
					break
				}
			}
		}
		if targetIdx < 0 {
			for i := len(segments) - 1; i >= first; i-- {
				s, _ := url.PathUnescape(segments[i])
				if len(s) > 0 && ((s[0] >= '0' && s[0] <= '9') || pathUUIDRe.MatchString(s)) {
					targetIdx = i
					break
				}
			}
		}
		if targetIdx < 0 {
			for i := len(segments) - 1; i >= first; i-- {
				if segments[i] != "" {
					targetIdx = i
					break
				}
			}
		}
		if targetIdx < 0 {
			return "", nil, nil, fmt.Errorf("no path segment to mutate")
		}
		segments[targetIdx] = url.PathEscape(value)
		u.RawPath = strings.Join(segments, "/")
		u.Path, err = url.PathUnescape(u.RawPath)
		if err != nil {
			return "", nil, nil, err
		}
		return u.String(), nil, headers, nil
	default:
		q := u.Query()
		setFirstURLValue(q, param, value)
		u.RawQuery = q.Encode()
		return u.String(), nil, headers, nil
	}
}

// setFirstURLValue mutates one occurrence without collapsing HTTP parameter
// pollution/repeated-field shapes captured from the real request.
func setFirstURLValue(values url.Values, name, value string) {
	existing, ok := values[name]
	if !ok || len(existing) == 0 {
		values[name] = []string{value}
		return
	}
	updated := append([]string(nil), existing...)
	updated[0] = value
	values[name] = updated
}
