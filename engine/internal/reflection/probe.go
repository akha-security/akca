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
	case "form", "multipart", "json", "graphql", "graphql_query", "websocket", "xml":
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

// MutateRequest changes exactly one discovered injection surface while
// retaining the rest of the original request.  Older call sites use
// BuildProbeRequestWithTemplate, which is kept as a compatibility adapter.
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

	body := strings.TrimSpace(template.Body)
	switch loc {
	case "form", "body", "post":
		form := url.Values{}
		if body != "" {
			if parsed, err := url.ParseQuery(body); err == nil {
				form = parsed
			}
		}
		setFirstURLValue(form, param, value)
		setHeaderCI(headers, "Content-Type", "application/x-www-form-urlencoded")
		return materialized(method, endpointURL, []byte(form.Encode()), headers)
	case "json", "graphql", "websocket":
		var doc interface{}
		if body != "" {
			_ = json.Unmarshal([]byte(body), &doc)
		}
		if doc == nil {
			doc = make(map[string]interface{})
		}
		normParam := strings.ReplaceAll(param, "[", ".")
		normParam = strings.ReplaceAll(normParam, "]", "")
		normParam = strings.Trim(normParam, ".")
		if setJSONPath(doc, strings.Split(normParam, "."), value) {
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
		mutated, mediaType, ok := mutateMultipartBody([]byte(template.Body), template.ContentType, param, value)
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

	probeURL, probeBody, probeHeaders, err := BuildProbeRequest(endpointURL, method, param, loc, value)
	if err != nil {
		return MutatedRequest{}, err
	}
	for key, headerValue := range probeHeaders {
		setHeaderCI(headers, key, headerValue)
	}
	return MutatedRequest{Method: method, URL: probeURL, Body: probeBody, Headers: headers}, nil
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
			deferPop := true
			if err := encoder.EncodeToken(token); err != nil {
				return nil, false
			}
			if deferPop && len(stack) > 0 {
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

func mutateMultipartBody(body []byte, contentType, param, value string) ([]byte, string, bool) {
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
		partBody, readErr := io.ReadAll(io.LimitReader(part, 16<<20))
		_ = part.Close()
		if readErr != nil {
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
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)(\$` + escaped + `\s*:\s*[^=,)]+\s*=\s*)("[^"]*"|-?[0-9.]+|true|false|null)`),
		regexp.MustCompile(`(?m)(\b` + escaped + `\s*:\s*)("[^"]*"|-?[0-9.]+|true|false|null)`),
	}
	replacement := strconv.Quote(value)
	if value == "true" || value == "false" || value == "null" {
		replacement = value
	} else if _, err := strconv.ParseFloat(value, 64); err == nil {
		replacement = value
	}
	for _, pattern := range patterns {
		if pattern.MatchString(query) {
			return pattern.ReplaceAllString(query, `${1}`+replacement), true
		}
	}
	return "", false
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
			headers[key] = value
			return
		}
	}
	headers[name] = value
}

func setJSONPath(current interface{}, path []string, value string) bool {
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
				node[path[0]] = coerced
				return true
			}
			node[path[0]] = value
			return true
		}
		next, ok := node[path[0]]
		if !ok {
			nextMap := make(map[string]interface{})
			node[path[0]] = nextMap
			return setJSONPath(nextMap, path[1:], value)
		}
		return setJSONPath(next, path[1:], value)
	case []interface{}:
		idx, err := strconv.Atoi(path[0])
		if err == nil && idx >= 0 && idx < len(node) {
			if len(path) == 1 {
				coerced, ok := schemaCompatibleJSONValue(node[idx], value)
				if !ok {
					return false
				}
				node[idx] = coerced
				return true
			}
			return setJSONPath(node[idx], path[1:], value)
		}
		// Fallback for unindexed path like "id" targeting an array of objects:
		mutatedAny := false
		for i := range node {
			if setJSONPath(node[i], path, value) {
				mutatedAny = true
			}
		}
		return mutatedAny
	default:
		return false
	}
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
		if strings.Contains(value, ".") {
			if _, err := strconv.ParseFloat(value, 64); err == nil {
				return json.Number(value), true
			}
		}
		if _, err := strconv.ParseInt(value, 10, 64); err == nil {
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
		replaced := false
		if match := pathIndexParamRe.FindStringSubmatch(param); len(match) == 2 {
			if index, parseErr := strconv.Atoi(match[1]); parseErr == nil {
				segments := strings.Split(strings.Trim(u.Path, "/"), "/")
				if index >= 0 && index < len(segments) {
					segments[index] = value
					prefix := ""
					if strings.HasPrefix(u.Path, "/") {
						prefix = "/"
					}
					u.Path = prefix + strings.Join(segments, "/")
					u.RawPath = ""
					replaced = true
				}
			}
		}
		for _, placeholder := range []string{"{" + param + "}", ":" + param, "[" + param + "]"} {
			if replaced {
				break
			}
			if strings.Contains(u.Path, placeholder) {
				u.Path = strings.ReplaceAll(u.Path, placeholder, value)
				u.RawPath = ""
				replaced = true
				break
			}
		}
		if !replaced {
			segs := strings.Split(strings.Trim(u.Path, "/"), "/")
			targetIdx := -1
			for i := len(segs) - 1; i >= 0; i-- {
				s := segs[i]
				if len(s) > 0 && ((s[0] >= '0' && s[0] <= '9') || pathUUIDRe.MatchString(s)) {
					targetIdx = i
					break
				}
			}
			if targetIdx >= 0 {
				segs[targetIdx] = value
				prefix := ""
				if strings.HasPrefix(u.Path, "/") {
					prefix = "/"
				}
				u.Path = prefix + strings.Join(segs, "/")
				u.RawPath = ""
				replaced = true
			}
		}
		if !replaced {
			// Concrete API replays commonly bind a discovered ID into the last
			// segment. Mutate that segment rather than creating a different
			// child route such as /orders/123/payload.
			trimmed := strings.TrimRight(u.Path, "/")
			if slash := strings.LastIndex(trimmed, "/"); slash >= 0 {
				u.Path = trimmed[:slash+1] + value
			} else {
				u.Path = value
			}
			u.RawPath = ""
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
