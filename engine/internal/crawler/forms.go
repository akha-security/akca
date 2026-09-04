package crawler

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/akha-security/akca/engine/internal/urlutil"
	"golang.org/x/net/html"
)

func extractForms(baseURL, rawHTML string) []DiscoveredEndpoint {
	doc, err := html.Parse(strings.NewReader(rawHTML))
	if err != nil {
		return nil
	}
	var out []DiscoveredEndpoint
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			action := strings.TrimSpace(nodeAttr(n, "action"))
			if action == "" {
				action = baseURL
			}
			resolved, resolveErr := ResolveReference(baseURL, action)
			if resolveErr == nil && resolved != "" && urlutil.IsPlausibleEndpointURL(resolved) {
				method := strings.ToUpper(strings.TrimSpace(nodeAttr(n, "method")))
				if method == "" {
					method = http.MethodGet
				}
				switch method {
				case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				default:
					method = http.MethodGet
				}
				enctype := strings.ToLower(strings.TrimSpace(nodeAttr(n, "enctype")))
				fields := url.Values{}
				collectFormControls(n, fields)
				tmpl := buildFormRequestTemplate(resolved, method, enctype, fields)
				out = append(out, DiscoveredEndpoint{URL: resolved, Method: method, Source: SourceForm, Confidence: 0.98, WhyDiscovered: "parsed html form action", RequestTemplate: tmpl})
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	return out
}

func collectFormControls(form *html.Node, values url.Values) {
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && nodeAttr(n, "disabled") == "" {
			name := strings.TrimSpace(nodeAttr(n, "name"))
			switch n.Data {
			case "input":
				inputType := strings.ToLower(nodeAttr(n, "type"))
				if inputType == "" {
					inputType = "text"
				}
				if name != "" && inputType != "submit" && inputType != "button" && inputType != "image" && inputType != "reset" {
					if (inputType == "checkbox" || inputType == "radio") && nodeAttr(n, "checked") == "" {
						break
					}
					if inputType == "file" {
						addFormValue(values, name, "test.png")
					} else {
						addFormValue(values, name, smartFormValue(name, inputType, nodeAttr(n, "value")))
					}
				}
			case "textarea":
				if name != "" {
					addFormValue(values, name, smartFormValue(name, "textarea", nodeTextContent(n)))
				}
			case "select":
				if name != "" {
					addSelectValues(values, name, n)
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(form)
}

func nodeAttr(n *html.Node, name string) string {
	for _, attr := range n.Attr {
		if strings.EqualFold(attr.Key, name) {
			if attr.Val == "" {
				return name
			}
			return attr.Val
		}
	}
	return ""
}

func nodeTextContent(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(cur *html.Node) {
		if cur.Type == html.TextNode {
			b.WriteString(cur.Data)
		}
		for child := cur.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)
	return strings.TrimSpace(b.String())
}

func addFormValue(values url.Values, name, value string) {
	if strings.TrimSpace(value) == "" {
		value = smartFormValue(name, "", value)
	}
	values.Add(name, value)
}

func smartFormValue(name, inputType, defaultValue string) string {
	if strings.TrimSpace(defaultValue) != "" {
		return defaultValue
	}
	lowerName := strings.ToLower(name)
	lowerType := strings.ToLower(inputType)

	switch {
	case lowerType == "email" || strings.Contains(lowerName, "email") || strings.Contains(lowerName, "mail"):
		return "test@example.com"
	case lowerType == "number" || lowerType == "range" || strings.Contains(lowerName, "qty") ||
		strings.Contains(lowerName, "quantity") || strings.Contains(lowerName, "age") || lowerName == "id" || strings.HasSuffix(lowerName, "_id"):
		return "1"
	case lowerType == "date" || lowerType == "datetime-local" || strings.Contains(lowerName, "date") || strings.Contains(lowerName, "time"):
		return "2026-01-01"
	case lowerType == "tel" || strings.Contains(lowerName, "phone") || strings.Contains(lowerName, "tel") || strings.Contains(lowerName, "mobile"):
		return "+15550199"
	case lowerType == "url" || strings.Contains(lowerName, "url") || strings.Contains(lowerName, "site") || strings.Contains(lowerName, "link"):
		return "http://example.com"
	case strings.Contains(lowerName, "user") || strings.Contains(lowerName, "login") || strings.Contains(lowerName, "author"):
		return "admin"
	case strings.Contains(lowerName, "pass") || strings.Contains(lowerName, "secret"):
		return "Password123!"
	case strings.Contains(lowerName, "search") || strings.Contains(lowerName, "query") || lowerName == "q":
		return "test"
	default:
		return "akca"
	}
}

func addSelectValues(values url.Values, name string, selectNode *html.Node) {
	added := false
	for option := selectNode.FirstChild; option != nil; option = option.NextSibling {
		if option.Type != html.ElementNode || option.Data != "option" {
			continue
		}
		if nodeAttr(option, "selected") != "" {
			value := nodeAttr(option, "value")
			if value == "" {
				value = nodeTextContent(option)
			}
			addFormValue(values, name, value)
			added = true
		}
	}
	if !added {
		addFormValue(values, name, "akca")
	}
}

func buildFormRequestTemplate(rawURL, method, enctype string, fields url.Values) *RequestTemplate {
	tmpl := &RequestTemplate{Method: method, URL: rawURL}
	if len(fields) == 0 {
		return tmpl
	}
	encoded := fields.Encode()
	if method == http.MethodGet {
		u, err := url.Parse(rawURL)
		if err != nil {
			return tmpl
		}
		q := u.Query()
		for key, vals := range fields {
			for _, value := range vals {
				q.Add(key, value)
			}
		}
		u.RawQuery = q.Encode()
		tmpl.URL = u.String()
		return tmpl
	}
	tmpl.Body = encoded
	if strings.Contains(enctype, "multipart") {
		tmpl.ContentType = "multipart/form-data"
	} else if strings.Contains(enctype, "json") {
		tmpl.ContentType = "application/json"
	} else {
		tmpl.ContentType = "application/x-www-form-urlencoded"
	}
	tmpl.Headers = map[string]string{"Content-Type": tmpl.ContentType}
	return tmpl
}
