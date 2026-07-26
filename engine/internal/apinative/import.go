package apinative

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

func Import(data []byte, opts ImportOptions) (Inventory, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return Inventory{}, fmt.Errorf("empty API definition")
	}
	if bytes.HasPrefix(trimmed, []byte("<")) {
		return importWSDL(trimmed, opts)
	}
	if bytes.Contains(trimmed, []byte("syntax =")) || bytes.Contains(trimmed, []byte("service ")) {
		return importProto(string(trimmed), opts)
	}
	if bytes.Contains(trimmed, []byte("type Query")) || bytes.Contains(trimmed, []byte("type Mutation")) {
		return importGraphQL(string(trimmed), opts)
	}
	var doc map[string]interface{}
	if json.Unmarshal(trimmed, &doc) != nil {
		if err := yaml.Unmarshal(trimmed, &doc); err != nil {
			return Inventory{}, fmt.Errorf("unsupported API definition: %w", err)
		}
		doc = normalizeYAMLMap(doc)
	}
	switch {
	case doc["openapi"] != nil || doc["swagger"] != nil:
		return importOpenAPI(doc, opts)
	case doc["asyncapi"] != nil:
		return importAsyncAPI(doc, opts)
	case doc["log"] != nil:
		return importHAR(doc, opts)
	case doc["values"] != nil && (doc["_postman_variable_scope"] == "environment" || doc["name"] != nil):
		return importPostmanEnvironment(doc), nil
	case doc["info"] != nil && doc["item"] != nil:
		return importPostman(doc, opts)
	default:
		return Inventory{}, fmt.Errorf("unrecognized API definition")
	}
}

func importOpenAPI(doc map[string]interface{}, opts ImportOptions) (Inventory, error) {
	out := Inventory{Format: FormatOpenAPI}
	if info, ok := doc["info"].(map[string]interface{}); ok {
		out.Title = stringValue(info["title"])
	}
	out.BaseURLs = openAPIBaseURLs(doc, opts.BaseURL)
	paths, _ := doc["paths"].(map[string]interface{})
	pathNames := sortedKeys(paths)
	for _, endpointPath := range pathNames {
		pathItem, _ := resolveLocalRefs(doc, paths[endpointPath], 0, map[string]bool{}).(map[string]interface{})
		for _, method := range []string{"get", "post", "put", "patch", "delete", "head", "options", "trace"} {
			rawOperation, ok := pathItem[method].(map[string]interface{})
			if !ok {
				continue
			}
			op := Operation{
				ID: stringValue(rawOperation["operationId"]), Method: strings.ToUpper(method),
				Path: endpointPath, SourceFormat: FormatOpenAPI, ResponseSchemas: map[string]interface{}{},
			}
			if op.ID == "" {
				op.ID = strings.ToLower(op.Method) + "_" + strings.Trim(strings.ReplaceAll(endpointPath, "/", "_"), "_")
			}
			rawOperation, _ = resolveLocalRefs(doc, rawOperation, 0, map[string]bool{}).(map[string]interface{})
			op.Parameters = append(op.Parameters, openAPIParameters(doc, pathItem["parameters"])...)
			op.Parameters = append(op.Parameters, openAPIParameters(doc, rawOperation["parameters"])...)
			op.AuthSchemes = securityNames(rawOperation["security"])
			if rawOperation["security"] == nil {
				op.AuthSchemes = securityNames(doc["security"])
			}
			if requestBody, ok := rawOperation["requestBody"].(map[string]interface{}); ok {
				requestBody, _ = resolveLocalRefs(doc, requestBody, 0, map[string]bool{}).(map[string]interface{})
				if content, ok := requestBody["content"].(map[string]interface{}); ok {
					for _, contentType := range sortedKeys(content) {
						media, _ := content[contentType].(map[string]interface{})
						op.ContentType = contentType
						op.RequestSchema = resolveLocalRefs(doc, media["schema"], 0, map[string]bool{})
						op.BodyTemplate = RequestBodyFromSchema(op.RequestSchema)
						op.Parameters = append(op.Parameters, RequestBodyParameters(op.RequestSchema)...)
						break
					}
				}
			}
			for _, parameter := range op.Parameters {
				if parameter.In == "body" && parameter.Schema != nil {
					op.RequestSchema = resolveLocalRefs(doc, parameter.Schema, 0, map[string]bool{})
					op.ContentType = "application/json"
					op.BodyTemplate = RequestBodyFromSchema(op.RequestSchema)
					op.Parameters = append(op.Parameters, RequestBodyParameters(op.RequestSchema)...)
				}
			}
			if responses, ok := rawOperation["responses"].(map[string]interface{}); ok {
				for status, response := range responses {
					responseMap, _ := resolveLocalRefs(doc, response, 0, map[string]bool{}).(map[string]interface{})
					if content, ok := responseMap["content"].(map[string]interface{}); ok {
						for _, media := range content {
							if mediaMap, ok := media.(map[string]interface{}); ok {
								op.ResponseSchemas[status] = resolveLocalRefs(doc, mediaMap["schema"], 0, map[string]bool{})
								break
							}
						}
					} else if responseMap["schema"] != nil {
						op.ResponseSchemas[status] = resolveLocalRefs(doc, responseMap["schema"], 0, map[string]bool{})
					}
				}
			}
			base := opts.BaseURL
			if len(out.BaseURLs) > 0 {
				base = out.BaseURLs[0]
			}
			op.URL = joinURL(base, endpointPath)
			out.Operations = append(out.Operations, op)
		}
	}
	return out, nil
}

func openAPIBaseURLs(doc map[string]interface{}, fallback string) []string {
	var out []string
	if servers, ok := doc["servers"].([]interface{}); ok {
		for _, raw := range servers {
			if server, ok := raw.(map[string]interface{}); ok {
				if value := stringValue(server["url"]); value != "" {
					if variables, ok := server["variables"].(map[string]interface{}); ok {
						replacements := make(map[string]string, len(variables))
						for name, rawVariable := range variables {
							variable, _ := rawVariable.(map[string]interface{})
							replacements[name] = stringValue(variable["default"])
						}
						value = expandVariables(value, replacements)
						for name, replacement := range replacements {
							value = strings.ReplaceAll(value, "{"+name+"}", replacement)
						}
					}
					out = append(out, value)
				}
			}
		}
	}
	if len(out) == 0 && doc["swagger"] != nil {
		host := stringValue(doc["host"])
		basePath := stringValue(doc["basePath"])
		scheme := "https"
		if schemes, ok := doc["schemes"].([]interface{}); ok && len(schemes) > 0 {
			scheme = stringValue(schemes[0])
		}
		if host != "" {
			out = append(out, scheme+"://"+host+basePath)
		}
	}
	if len(out) == 0 && fallback != "" {
		out = append(out, fallback)
	}
	return out
}

func openAPIParameters(doc map[string]interface{}, raw interface{}) []Parameter {
	items, _ := raw.([]interface{})
	out := make([]Parameter, 0, len(items))
	for _, item := range items {
		value, ok := resolveLocalRefs(doc, item, 0, map[string]bool{}).(map[string]interface{})
		if !ok {
			continue
		}
		schema, _ := value["schema"].(map[string]interface{})
		source := value
		if len(schema) > 0 {
			source = schema
		}
		parameter := Parameter{
			Name: stringValue(value["name"]), In: stringValue(value["in"]),
			Type: stringValue(source["type"]), Format: stringValue(source["format"]),
			Required: value["required"] == true, Example: source["example"], Schema: value["schema"],
		}
		parameter.Enum, _ = source["enum"].([]interface{})
		if minimum, ok := numberValue(source["minimum"]); ok {
			parameter.Minimum = &minimum
		}
		if maximum, ok := numberValue(source["maximum"]); ok {
			parameter.Maximum = &maximum
		}
		out = append(out, parameter)
	}
	return out
}

func resolveLocalRefs(root map[string]interface{}, value interface{}, depth int, stack map[string]bool) interface{} {
	if depth > 32 {
		return value
	}
	switch typed := value.(type) {
	case []interface{}:
		out := make([]interface{}, len(typed))
		for index, child := range typed {
			out[index] = resolveLocalRefs(root, child, depth+1, stack)
		}
		return out
	case map[string]interface{}:
		if ref := stringValue(typed["$ref"]); strings.HasPrefix(ref, "#/") {
			if stack[ref] {
				return map[string]interface{}{}
			}
			target, ok := localRef(root, ref)
			if !ok {
				return typed
			}
			nextStack := make(map[string]bool, len(stack)+1)
			for key, used := range stack {
				nextStack[key] = used
			}
			nextStack[ref] = true
			resolved := resolveLocalRefs(root, target, depth+1, nextStack)
			resolvedMap, _ := resolved.(map[string]interface{})
			merged := make(map[string]interface{}, len(resolvedMap)+len(typed))
			for key, child := range resolvedMap {
				merged[key] = child
			}
			for key, child := range typed {
				if key != "$ref" {
					merged[key] = resolveLocalRefs(root, child, depth+1, nextStack)
				}
			}
			return merged
		}
		out := make(map[string]interface{}, len(typed))
		for key, child := range typed {
			out[key] = resolveLocalRefs(root, child, depth+1, stack)
		}
		return out
	default:
		return value
	}
}

func localRef(root map[string]interface{}, ref string) (interface{}, bool) {
	var current interface{} = root
	for _, encoded := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		key := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", "/"), "~0", "~")
		object, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		current, ok = object[key]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func securityNames(raw interface{}) []string {
	items, _ := raw.([]interface{})
	set := map[string]struct{}{}
	for _, item := range items {
		if object, ok := item.(map[string]interface{}); ok {
			for key := range object {
				set[key] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func importPostman(doc map[string]interface{}, opts ImportOptions) (Inventory, error) {
	out := Inventory{Format: FormatPostman}
	if info, ok := doc["info"].(map[string]interface{}); ok {
		out.Title = stringValue(info["name"])
	}
	var walk func([]interface{})
	walk = func(items []interface{}) {
		for _, raw := range items {
			item, _ := raw.(map[string]interface{})
			if children, ok := item["item"].([]interface{}); ok {
				walk(children)
				continue
			}
			request, ok := item["request"].(map[string]interface{})
			if !ok {
				continue
			}
			op := Operation{ID: stringValue(item["name"]), Method: strings.ToUpper(stringValue(request["method"])), SourceFormat: FormatPostman}
			switch rawURL := request["url"].(type) {
			case string:
				op.URL = expandVariables(rawURL, opts.Environment)
			case map[string]interface{}:
				op.URL = expandVariables(stringValue(rawURL["raw"]), opts.Environment)
			}
			op.Path = op.URL
			if body, ok := request["body"].(map[string]interface{}); ok {
				op.BodyTemplate = expandVariables(stringValue(body["raw"]), opts.Environment)
				op.ContentType = "application/json"
			}
			out.Operations = append(out.Operations, op)
		}
	}
	items, _ := doc["item"].([]interface{})
	walk(items)
	return out, nil
}

func importPostmanEnvironment(doc map[string]interface{}) Inventory {
	out := Inventory{Title: stringValue(doc["name"]), Format: FormatPostmanEnvironment, Variables: map[string]string{}}
	values, _ := doc["values"].([]interface{})
	for _, raw := range values {
		item, _ := raw.(map[string]interface{})
		if item["enabled"] == false {
			continue
		}
		key := stringValue(item["key"])
		if key != "" {
			out.Variables[key] = stringValue(item["value"])
		}
	}
	return out
}

func importHAR(doc map[string]interface{}, _ ImportOptions) (Inventory, error) {
	out := Inventory{Title: "HAR traffic", Format: FormatHAR}
	log, _ := doc["log"].(map[string]interface{})
	entries, _ := log["entries"].([]interface{})
	for index, raw := range entries {
		entry, _ := raw.(map[string]interface{})
		request, _ := entry["request"].(map[string]interface{})
		op := Operation{
			ID: fmt.Sprintf("har_%d", index+1), Method: strings.ToUpper(stringValue(request["method"])),
			URL: stringValue(request["url"]), Path: stringValue(request["url"]), SourceFormat: FormatHAR,
		}
		if postData, ok := request["postData"].(map[string]interface{}); ok {
			op.ContentType = stringValue(postData["mimeType"])
			op.BodyTemplate = stringValue(postData["text"])
		}
		if query, ok := request["queryString"].([]interface{}); ok {
			for _, rawParameter := range query {
				value, _ := rawParameter.(map[string]interface{})
				op.Parameters = append(op.Parameters, Parameter{Name: stringValue(value["name"]), In: "query", Type: "string"})
			}
		}
		out.Operations = append(out.Operations, op)
	}
	return out, nil
}

type wsdlDocument struct {
	XMLName  xml.Name
	Services []struct {
		Ports []struct {
			Address struct {
				Location string `xml:"location,attr"`
			} `xml:"address"`
		} `xml:"port"`
	} `xml:"service"`
	PortTypes []struct {
		Operations []struct {
			Name string `xml:"name,attr"`
		} `xml:"operation"`
	} `xml:"portType"`
}

func importWSDL(data []byte, opts ImportOptions) (Inventory, error) {
	var doc wsdlDocument
	if err := xml.Unmarshal(data, &doc); err != nil {
		return Inventory{}, err
	}
	out := Inventory{Title: "WSDL service", Format: FormatWSDL}
	base := opts.BaseURL
	for _, service := range doc.Services {
		for _, port := range service.Ports {
			if port.Address.Location != "" {
				base = port.Address.Location
				out.BaseURLs = append(out.BaseURLs, base)
			}
		}
	}
	for _, portType := range doc.PortTypes {
		for _, operation := range portType.Operations {
			out.Operations = append(out.Operations, Operation{
				ID: operation.Name, Method: "POST", Path: base, URL: base,
				ContentType: "text/xml", SourceFormat: FormatWSDL,
			})
		}
	}
	return out, nil
}

var graphqlTypeRE = regexp.MustCompile(`(?s)type\s+(Query|Mutation)\s*\{([^}]*)\}`)
var graphqlFieldRE = regexp.MustCompile(`(?m)^\s*([_A-Za-z][_0-9A-Za-z]*)\s*(?:\(([^)]*)\))?\s*:\s*([!\[\]_0-9A-Za-z]+)`)
var graphqlArgRE = regexp.MustCompile(`([_A-Za-z][_0-9A-Za-z]*)\s*:\s*([!\[\]_0-9A-Za-z]+)`)

func importGraphQL(sdl string, opts ImportOptions) (Inventory, error) {
	out := Inventory{Title: "GraphQL schema", Format: FormatGraphQL}
	for _, block := range graphqlTypeRE.FindAllStringSubmatch(sdl, -1) {
		method := "POST"
		for _, field := range graphqlFieldRE.FindAllStringSubmatch(block[2], -1) {
			op := Operation{
				ID: field[1], Method: method, Path: "/graphql", URL: joinURL(opts.BaseURL, "/graphql"),
				ContentType: "application/json", SourceFormat: FormatGraphQL,
			}
			queryKind := strings.ToLower(block[1])
			var declarations, arguments []string
			variables := map[string]interface{}{}
			properties := map[string]interface{}{}
			for _, argument := range graphqlArgRE.FindAllStringSubmatch(field[2], -1) {
				name, graphqlType := argument[1], argument[2]
				declarations = append(declarations, "$"+name+": "+graphqlType)
				arguments = append(arguments, name+": $"+name)
				schema, example := graphqlArgumentSchema(graphqlType)
				properties[name] = schema
				variables[name] = example
				op.Parameters = append(op.Parameters, Parameter{
					Name: "variables." + name, In: "graphql",
					Type: stringValue(schema["type"]), Required: strings.Contains(graphqlType, "!"), Schema: schema,
				})
			}
			signature := ""
			if len(declarations) > 0 {
				signature = "(" + strings.Join(declarations, ", ") + ")"
			}
			callArguments := ""
			if len(arguments) > 0 {
				callArguments = "(" + strings.Join(arguments, ", ") + ")"
			}
			selection := ""
			if !graphqlScalar(field[3]) {
				selection = " { __typename }"
			}
			query := fmt.Sprintf("%s %s%s { %s%s%s }", queryKind, field[1], signature, field[1], callArguments, selection)
			body, _ := json.Marshal(map[string]interface{}{"query": query, "variables": variables})
			op.BodyTemplate = string(body)
			op.RequestSchema = map[string]interface{}{
				"type": "object", "properties": map[string]interface{}{
					"variables": map[string]interface{}{"type": "object", "properties": properties},
				},
			}
			out.Operations = append(out.Operations, op)
		}
	}
	return out, nil
}

func graphqlArgumentSchema(graphqlType string) (map[string]interface{}, interface{}) {
	base := strings.Trim(graphqlType, "![]")
	isArray := strings.Contains(graphqlType, "[")
	schema := map[string]interface{}{"type": "string"}
	var example interface{} = "akca"
	switch base {
	case "Int":
		schema["type"], example = "integer", 1
	case "Float":
		schema["type"], example = "number", 1.0
	case "Boolean":
		schema["type"], example = "boolean", true
	case "ID":
		schema["type"], schema["format"], example = "string", "id", "akca-id"
	}
	if isArray {
		itemSchema := schema
		schema = map[string]interface{}{"type": "array", "items": itemSchema}
		example = []interface{}{example}
	}
	return schema, example
}

func graphqlScalar(graphqlType string) bool {
	switch strings.Trim(graphqlType, "![]") {
	case "Int", "Float", "String", "Boolean", "ID":
		return true
	default:
		return false
	}
}

var protoServiceRE = regexp.MustCompile(`(?s)service\s+([A-Za-z_]\w*)\s*\{([^}]*)\}`)
var protoRPCRE = regexp.MustCompile(`rpc\s+([A-Za-z_]\w*)\s*\(\s*([.\w]+)\s*\)\s*returns\s*\(\s*([.\w]+)\s*\)`)

func importProto(proto string, opts ImportOptions) (Inventory, error) {
	out := Inventory{Title: "gRPC services", Format: FormatProto}
	for _, service := range protoServiceRE.FindAllStringSubmatch(proto, -1) {
		for _, rpc := range protoRPCRE.FindAllStringSubmatch(service[2], -1) {
			endpointPath := "/" + service[1] + "/" + rpc[1]
			out.Operations = append(out.Operations, Operation{
				ID: rpc[1], Method: "GRPC", Path: endpointPath, URL: joinURL(opts.BaseURL, endpointPath),
				ContentType: "application/grpc", RequestSchema: map[string]interface{}{"message": rpc[2]},
				ResponseSchemas: map[string]interface{}{"200": map[string]interface{}{"message": rpc[3]}},
				SourceFormat:    FormatProto,
			})
		}
	}
	return out, nil
}

func importAsyncAPI(doc map[string]interface{}, opts ImportOptions) (Inventory, error) {
	out := Inventory{Format: FormatAsyncAPI}
	if info, ok := doc["info"].(map[string]interface{}); ok {
		out.Title = stringValue(info["title"])
	}
	channels, _ := doc["channels"].(map[string]interface{})
	for _, channel := range sortedKeys(channels) {
		channelItem, _ := channels[channel].(map[string]interface{})
		for _, action := range []string{"publish", "subscribe"} {
			message, ok := channelItem[action].(map[string]interface{})
			if !ok {
				continue
			}
			op := Operation{
				ID: stringValue(message["operationId"]), Method: strings.ToUpper(action),
				Path: channel, URL: joinURL(opts.BaseURL, channel), SourceFormat: FormatAsyncAPI,
			}
			if rawMessage, ok := message["message"].(map[string]interface{}); ok {
				op.RequestSchema = rawMessage["payload"]
				op.BodyTemplate = RequestBodyFromSchema(op.RequestSchema)
			}
			out.Operations = append(out.Operations, op)
		}
	}
	return out, nil
}

func sortedKeys(values map[string]interface{}) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func normalizeYAMLMap(value map[string]interface{}) map[string]interface{} {
	raw, _ := json.Marshal(value)
	var out map[string]interface{}
	_ = json.Unmarshal(raw, &out)
	return out
}
