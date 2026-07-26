package reflection

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

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
	if !strings.EqualFold(location, "json") && !strings.EqualFold(location, "graphql") || strings.TrimSpace(bodyTemplate) == "" {
		return BuildProbeRequest(endpointURL, method, param, location, value)
	}
	var doc interface{}
	if err := json.Unmarshal([]byte(bodyTemplate), &doc); err != nil {
		return BuildProbeRequest(endpointURL, method, param, location, value)
	}
	if !setJSONPath(doc, strings.Split(param, "."), value) {
		return "", nil, nil, fmt.Errorf("schema-preserving JSON mutation rejected for path %q", param)
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return "", nil, nil, err
	}
	u, err := url.Parse(endpointURL)
	if err != nil {
		return "", nil, nil, err
	}
	return u.String(), body, map[string]string{"Content-Type": "application/json"}, nil
}

func setJSONPath(current interface{}, path []string, value string) bool {
	if len(path) == 0 {
		return false
	}
	switch node := current.(type) {
	case map[string]interface{}:
		if len(path) == 1 {
			current, exists := node[path[0]]
			if !exists {
				return false
			}
			coerced, ok := schemaCompatibleJSONValue(current, value)
			if !ok {
				return false
			}
			node[path[0]] = coerced
			return true
		}
		next, ok := node[path[0]]
		return ok && setJSONPath(next, path[1:], value)
	case []interface{}:
		idx, err := strconv.Atoi(path[0])
		if err != nil || idx < 0 || idx >= len(node) {
			return false
		}
		if len(path) == 1 {
			coerced, ok := schemaCompatibleJSONValue(node[idx], value)
			if !ok {
				return false
			}
			node[idx] = coerced
			return true
		}
		return setJSONPath(node[idx], path[1:], value)
	default:
		return false
	}
}

func schemaCompatibleJSONValue(current interface{}, value string) (interface{}, bool) {
	switch current.(type) {
	case bool:
		parsed, err := strconv.ParseBool(value)
		return parsed, err == nil
	case float64:
		parsed, err := strconv.ParseFloat(value, 64)
		return parsed, err == nil
	case json.Number:
		if strings.Contains(value, ".") {
			_, err := strconv.ParseFloat(value, 64)
			return json.Number(value), err == nil
		}
		_, err := strconv.ParseInt(value, 10, 64)
		return json.Number(value), err == nil
	case string, nil:
		return value, true
	default:
		// Object/array replacement would change the request schema and is not
		// allowed through a scalar vulnerability probe.
		return nil, false
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
		body := fmt.Sprintf("{%q:%q}", param, value)
		headers["Content-Type"] = "application/json"
		if strings.ToUpper(method) == "" || strings.ToUpper(method) == "GET" {
			method = "POST"
		}
		return u.String(), []byte(body), headers, nil
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
