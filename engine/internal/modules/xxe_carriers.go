package modules

import (
	"archive/zip"
	"bytes"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"strings"

	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/reflection"
)

type xxeCarrier struct {
	name        string
	contentType string
	extension   string
	multipart   bool
}

func xxeCarriers(target ScanTarget) []xxeCarrier {
	ct := strings.ToLower(target.Profile.ContentType)
	location := strings.ToLower(strings.TrimSpace(target.Location))
	if location == "" {
		location = strings.ToLower(strings.TrimSpace(target.Profile.ParameterLocation))
	}
	surface := strings.ToLower(strings.Join([]string{target.EndpointURL, target.EndpointType, target.Parameter, target.BodyTemplate}, " "))
	isMultipart := strings.Contains(ct, "multipart/") || location == "multipart"

	var names []string
	switch {
	case strings.Contains(ct, "svg") || strings.Contains(surface, ".svg"):
		names = []string{"svg"}
	case strings.Contains(ct, "rss") || strings.Contains(surface, "rss"):
		names = []string{"rss"}
	case strings.Contains(ct, "atom") || strings.Contains(surface, "atom"):
		names = []string{"atom"}
	case strings.Contains(ct, "wordprocessingml") || strings.Contains(surface, "docx"):
		names = []string{"docx"}
	case strings.Contains(ct, "spreadsheetml") || strings.Contains(surface, "xlsx"):
		names = []string{"xlsx"}
	case isMultipart || strings.Contains(surface, "upload") || strings.Contains(surface, "attachment"):
		names = []string{"svg", "rss", "atom", "docx", "xlsx"}
	case strings.Contains(ct, "json") || strings.Contains(surface, "/api") || strings.Contains(surface, "/v1") || strings.Contains(surface, "/v2"):
		names = []string{"xml", "text_xml"}
	default:
		names = []string{"xml"}
	}

	out := make([]xxeCarrier, 0, len(names))
	for _, name := range names {
		carrier := xxeCarrier{name: name, multipart: isMultipart}
		switch name {
		case "svg":
			carrier.contentType, carrier.extension = "image/svg+xml", ".svg"
		case "rss":
			carrier.contentType, carrier.extension = "application/rss+xml", ".rss"
		case "atom":
			carrier.contentType, carrier.extension = "application/atom+xml", ".atom"
		case "docx":
			carrier.contentType, carrier.extension = "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx"
		case "xlsx":
			carrier.contentType, carrier.extension = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx"
		case "text_xml":
			carrier.contentType, carrier.extension = "text/xml", ".xml"
		default:
			carrier.contentType, carrier.extension = "application/xml", ".xml"
			if strings.Contains(ct, "xml") || strings.Contains(ct, "soap") {
				carrier.contentType = strings.TrimSpace(strings.SplitN(ct, ";", 2)[0])
			}
		}
		out = append(out, carrier)
	}
	return out
}

func buildXXECarrierRequest(carrier xxeCarrier, target ScanTarget, payload payloadgen.Payload, baseline bool, oastURL string) ([]byte, string, error) {
	xml, ok := xxeCarrierXML(carrier.name, payload, baseline, oastURL)
	if !ok {
		return nil, "", nil
	}
	body := []byte(xml)
	if carrier.name == "docx" || carrier.name == "xlsx" {
		var err error
		body, err = buildOOXMLXXE(carrier.name, xml)
		if err != nil {
			return nil, "", err
		}
	}
	if !carrier.multipart {
		contentType := carrier.contentType
		if carrier.name == "xml" && payload.ExpectedSignal == "soap_xxe" && !strings.Contains(contentType, "soap") {
			contentType = "text/xml"
		}
		return body, contentType, nil
	}
	field := strings.TrimSpace(target.Parameter)
	if field == "" || strings.EqualFold(field, "body") {
		field = "file"
	}
	return buildXXEMultipart(field, "akca-xxe"+carrier.extension, carrier.contentType, body)
}

func (c xxeCarrier) encoding() string {
	mode := "raw"
	if c.multipart {
		mode = "multipart"
	}
	return "xxe_carrier:" + c.name + ":" + mode
}

func xxeCarrierFromEncoding(encoding string) (xxeCarrier, bool) {
	parts := strings.Split(strings.TrimSpace(encoding), ":")
	if len(parts) != 3 || parts[0] != "xxe_carrier" {
		return xxeCarrier{}, false
	}
	for _, carrier := range xxeCarriers(ScanTarget{Profile: reflectionProfileForXXECarrier(parts[1])}) {
		carrier.multipart = parts[2] == "multipart"
		return carrier, true
	}
	return xxeCarrier{}, false
}

func reflectionProfileForXXECarrier(name string) reflection.ReflectionProfile {
	contentTypes := map[string]string{
		"svg": "image/svg+xml", "rss": "application/rss+xml", "atom": "application/atom+xml",
		"docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"xml":  "application/xml",
	}
	return reflection.ReflectionProfile{ContentType: contentTypes[name]}
}

func xxeCarrierXML(name string, payload payloadgen.Payload, baseline bool, oastURL string) (string, bool) {
	if name == "xml" {
		if baseline {
			return `<root>baseline</root>`, true
		}
		return payload.Value, true
	}
	if payload.ExpectedSignal == "soap_xxe" || (payload.Variant == "svg_xxe" && name != "svg" && name != "xml") {
		return "", false
	}
	rootOpen, rootClose := xxeCarrierRoot(name)
	if baseline {
		return `<?xml version="1.0"?>` + rootOpen + "baseline" + rootClose, true
	}
	if payload.IsNegativeControl {
		return `<?xml version="1.0"?>` + rootOpen + payload.Value + rootClose, true
	}
	entity := `<!ENTITY xxe "AKCA_XXE_TEST">`
	if payload.ExpectedSignal == "blind_oast" {
		if strings.TrimSpace(oastURL) == "" {
			return "", false
		}
		entity = `<!ENTITY xxe SYSTEM "` + oastURL + `">`
	}
	doctype := xxeCarrierDoctype(name)
	return `<?xml version="1.0"?><!DOCTYPE ` + doctype + ` [` + entity + `]>` + rootOpen + `&xxe;` + rootClose, true
}

func xxeCarrierRoot(name string) (string, string) {
	switch name {
	case "svg":
		return `<svg xmlns="http://www.w3.org/2000/svg"><text>`, `</text></svg>`
	case "rss":
		return `<rss version="2.0"><channel><title>`, `</title></channel></rss>`
	case "atom":
		return `<feed xmlns="http://www.w3.org/2005/Atom"><title>`, `</title></feed>`
	case "docx":
		return `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>`, `</w:t></w:r></w:p></w:body></w:document>`
	case "xlsx":
		return `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><definedNames><definedName name="akca">`, `</definedName></definedNames></workbook>`
	default:
		return `<root>`, `</root>`
	}
}

func xxeCarrierDoctype(name string) string {
	if name == "docx" {
		return "w:document"
	}
	if name == "xlsx" {
		return "workbook"
	}
	return name
}

func buildOOXMLXXE(kind, documentXML string) ([]byte, error) {
	var buffer bytes.Buffer
	zw := zip.NewWriter(&buffer)
	mainPart := "/word/document.xml"
	mainType := "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
	target := "word/document.xml"
	if kind == "xlsx" {
		mainPart = "/xl/workbook.xml"
		mainType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
		target = "xl/workbook.xml"
	}
	entries := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="` + mainPart + `" ContentType="` + mainType + `"/></Types>`,
		"_rels/.rels":         `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="` + target + `"/></Relationships>`,
	}
	if kind == "docx" {
		entries["word/document.xml"] = documentXML
	} else {
		entries["xl/workbook.xml"] = documentXML
	}
	for name, content := range entries {
		entry, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func buildXXEMultipart(field, filename, fileContentType string, content []byte) ([]byte, string, error) {
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, strings.ReplaceAll(field, `"`, ""), filename))
	header.Set("Content-Type", fileContentType)
	part, err := writer.CreatePart(header)
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(content); err != nil {
		return nil, "", err
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return buffer.Bytes(), writer.FormDataContentType(), nil
}
