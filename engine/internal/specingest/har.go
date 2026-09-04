package specingest

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type harDoc struct {
	Log struct {
		Version string `json:"version"`
		Creator struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"creator"`
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

type harEntry struct {
	Request harRequest `json:"request"`
}

type harRequest struct {
	Method      string       `json:"method"`
	URL         string       `json:"url"`
	HTTPVersion string       `json:"httpVersion"`
	Headers     []harHeader  `json:"headers"`
	QueryString []harQuery   `json:"queryString"`
	Cookies     []harCookie  `json:"cookies"`
	PostData    *harPostData `json:"postData,omitempty"`
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harQuery struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harPostData struct {
	MimeType string     `json:"mimeType"`
	Text     string     `json:"text"`
	Params   []harParam `json:"params,omitempty"`
}

type harParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func parseHAR(data []byte) (*IngestResult, error) {
	var doc harDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	if doc.Log.Version == "" && len(doc.Log.Entries) == 0 {
		return nil, fmt.Errorf("not a HAR archive")
	}

	var endpoints []ParsedEndpoint
	seenEndpoints := make(map[string]bool)

	for _, entry := range doc.Log.Entries {
		req := entry.Request
		if req.URL == "" {
			continue
		}

		u, err := url.Parse(req.URL)
		if err != nil {
			continue
		}

		// Skip static noise assets
		ext := strings.ToLower(u.Path)
		if strings.HasSuffix(ext, ".png") || strings.HasSuffix(ext, ".jpg") ||
			strings.HasSuffix(ext, ".jpeg") || strings.HasSuffix(ext, ".gif") ||
			strings.HasSuffix(ext, ".svg") || strings.HasSuffix(ext, ".ico") ||
			strings.HasSuffix(ext, ".woff") || strings.HasSuffix(ext, ".woff2") ||
			strings.HasSuffix(ext, ".ttf") || strings.HasSuffix(ext, ".eot") {
			continue
		}

		dedupeKey := fmt.Sprintf("%s %s://%s%s", req.Method, u.Scheme, u.Host, u.Path)
		if seenEndpoints[dedupeKey] {
			continue
		}
		seenEndpoints[dedupeKey] = true

		headers := make(map[string]string)
		for _, h := range req.Headers {
			if !isIgnoredHARHeader(h.Name) {
				headers[h.Name] = h.Value
			}
		}

		ep := ParsedEndpoint{
			Method:  strings.ToUpper(req.Method),
			Path:    req.URL,
			Headers: headers,
		}

		// Query params
		for _, q := range req.QueryString {
			if q.Name != "" {
				ep.Parameters = append(ep.Parameters, ParameterSpec{
					Name:     q.Name,
					Location: LocationQuery,
					Default:  q.Value,
				})
			}
		}

		// Body
		if req.PostData != nil {
			ep.ContentType = req.PostData.MimeType
			ep.BodyTemplate = req.PostData.Text
			if len(req.PostData.Params) > 0 {
				for _, p := range req.PostData.Params {
					if p.Name != "" {
						ep.Parameters = append(ep.Parameters, ParameterSpec{
							Name:     p.Name,
							Location: LocationForm,
							Default:  p.Value,
						})
					}
				}
			}
		}

		endpoints = append(endpoints, ep)
	}

	title := "HTTP Archive"
	if doc.Log.Creator.Name != "" {
		title = fmt.Sprintf("HAR recorded by %s %s", doc.Log.Creator.Name, doc.Log.Creator.Version)
	}

	return &IngestResult{
		Format:    FormatHAR,
		Title:     title,
		Version:   doc.Log.Version,
		Endpoints: endpoints,
	}, nil
}

func isIgnoredHARHeader(name string) bool {
	lower := strings.ToLower(name)
	return lower == "content-length" || lower == "host" || lower == "connection" ||
		lower == "accept-encoding" || lower == "user-agent"
}
