package specingest

import (
	"encoding/json"
	"fmt"
	"strings"
)

type postmanCollection struct {
	Info struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Schema      string `json:"schema"`
	} `json:"info"`
	Item []postmanItem `json:"item"`
}

type postmanItem struct {
	Name    string          `json:"name"`
	Item    []postmanItem   `json:"item,omitempty"` // nested folders
	Request *postmanRequest `json:"request,omitempty"`
}

type postmanRequest struct {
	Method string          `json:"method"`
	Header []postmanHeader `json:"header"`
	Body   *postmanBody    `json:"body,omitempty"`
	URL    json.RawMessage `json:"url"` // string or object
}

type postmanHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type postmanBody struct {
	Mode       string                 `json:"mode"`
	Raw        string                 `json:"raw,omitempty"`
	URLEncoded []postmanFormParameter `json:"urlencoded,omitempty"`
	FormData   []postmanFormParameter `json:"formdata,omitempty"`
}

type postmanFormParameter struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

type postmanURLObject struct {
	Raw   string   `json:"raw"`
	Host  []string `json:"host"`
	Path  []string `json:"path"`
	Query []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"query"`
	Variable []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"variable"`
}

func parsePostman(data []byte) (*IngestResult, error) {
	var col postmanCollection
	if err := json.Unmarshal(data, &col); err != nil {
		return nil, err
	}

	if col.Info.Schema == "" && len(col.Item) == 0 {
		return nil, fmt.Errorf("not a Postman collection")
	}

	var endpoints []ParsedEndpoint
	var walkItems func(items []postmanItem, folder string)
	walkItems = func(items []postmanItem, folder string) {
		for _, item := range items {
			if len(item.Item) > 0 {
				newFolder := item.Name
				if folder != "" {
					newFolder = folder + " / " + item.Name
				}
				walkItems(item.Item, newFolder)
			}
			if item.Request != nil {
				ep := extractPostmanEndpoint(item.Request, item.Name, folder)
				if ep.Path != "" || ep.Method != "" {
					endpoints = append(endpoints, ep)
				}
			}
		}
	}

	walkItems(col.Item, "")

	return &IngestResult{
		Format:    FormatPostman,
		Title:     col.Info.Name,
		Endpoints: endpoints,
	}, nil
}

func extractPostmanEndpoint(req *postmanRequest, name, folder string) ParsedEndpoint {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = "GET"
	}

	headers := make(map[string]string)
	for _, h := range req.Header {
		if h.Key != "" {
			headers[h.Key] = h.Value
		}
	}

	ep := ParsedEndpoint{
		Method:  method,
		Summary: name,
		Headers: headers,
	}
	if folder != "" {
		ep.Tags = []string{folder}
	}

	// Parse URL (can be raw string or URL object)
	var rawURLStr string
	if err := json.Unmarshal(req.URL, &rawURLStr); err == nil {
		ep.Path = rawURLStr
	} else {
		var urlObj postmanURLObject
		if err := json.Unmarshal(req.URL, &urlObj); err == nil {
			if urlObj.Raw != "" {
				ep.Path = urlObj.Raw
			} else if len(urlObj.Path) > 0 {
				ep.Path = "/" + strings.Join(urlObj.Path, "/")
			}

			// Extract query parameters
			for _, q := range urlObj.Query {
				if q.Key != "" {
					ep.Parameters = append(ep.Parameters, ParameterSpec{
						Name:     q.Key,
						Location: LocationQuery,
						Default:  q.Value,
					})
				}
			}

			// Extract path variables
			for _, v := range urlObj.Variable {
				if v.Key != "" {
					ep.Parameters = append(ep.Parameters, ParameterSpec{
						Name:     v.Key,
						Location: LocationPath,
						Default:  v.Value,
						Required: true,
					})
				}
			}
		}
	}

	// Parse Body
	if req.Body != nil {
		switch req.Body.Mode {
		case "raw":
			ep.BodyTemplate = req.Body.Raw
			if strings.HasPrefix(strings.TrimSpace(req.Body.Raw), "{") {
				ep.ContentType = "application/json"
			}
		case "urlencoded":
			ep.ContentType = "application/x-www-form-urlencoded"
			var pairs []string
			for _, param := range req.Body.URLEncoded {
				if param.Key != "" {
					pairs = append(pairs, fmt.Sprintf("%s=%s", param.Key, param.Value))
					ep.Parameters = append(ep.Parameters, ParameterSpec{
						Name:     param.Key,
						Location: LocationForm,
						Default:  param.Value,
					})
				}
			}
			ep.BodyTemplate = strings.Join(pairs, "&")
		case "formdata":
			ep.ContentType = "multipart/form-data"
			for _, param := range req.Body.FormData {
				if param.Key != "" {
					ep.Parameters = append(ep.Parameters, ParameterSpec{
						Name:     param.Key,
						Location: LocationForm,
						Default:  param.Value,
					})
				}
			}
		}
	}

	return ep
}
