package reflection

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var pathUUIDRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// EffectiveMethod returns the method that can actually carry the discovered
// injection surface. Body parameters discovered from a GET-rendered form must
// be submitted as POST; query, header, cookie and path probes preserve the
// endpoint's native method.
func EffectiveMethod(method, location string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	switch strings.ToLower(strings.TrimSpace(location)) {
	case "form", "multipart", "json", "graphql", "xml":
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
		form.Set(param, value)
		setHeaderCI(headers, "Content-Type", "application/x-www-form-urlencoded")
		return materialized(method, endpointURL, []byte(form.Encode()), headers)
	case "json", "graphql":
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
		form.Set(param, value)
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
		for _, placeholder := range []string{"{" + param + "}", ":" + param, "[" + param + "]"} {
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
		q.Set(param, value)
		u.RawQuery = q.Encode()
		return u.String(), nil, headers, nil
	}
}
