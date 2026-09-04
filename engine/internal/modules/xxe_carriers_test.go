package modules

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/akha-security/akca/engine/internal/config"
	"github.com/akha-security/akca/engine/internal/httpclient"
	"github.com/akha-security/akca/engine/internal/payloadgen"
	"github.com/akha-security/akca/engine/internal/reflection"
	"github.com/akha-security/akca/engine/internal/scope"
	"github.com/akha-security/akca/engine/internal/verification"
)

func TestXXECarrierDetection(t *testing.T) {
	tests := []struct {
		contentType string
		url         string
		want        string
	}{
		{"image/svg+xml", "https://example.test/render", "svg"},
		{"application/rss+xml", "https://example.test/import", "rss"},
		{"application/atom+xml", "https://example.test/feed", "atom"},
		{"application/vnd.openxmlformats-officedocument.wordprocessingml.document", "https://example.test/import", "docx"},
		{"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "https://example.test/import", "xlsx"},
	}
	for _, tt := range tests {
		carriers := xxeCarriers(ScanTarget{EndpointURL: tt.url, Profile: reflection.ReflectionProfile{ContentType: tt.contentType}})
		if len(carriers) != 1 || carriers[0].name != tt.want {
			t.Fatalf("content type %q carriers = %#v, want %s", tt.contentType, carriers, tt.want)
		}
	}

	upload := xxeCarriers(ScanTarget{
		EndpointURL: "https://example.test/upload", Parameter: "document", Location: "multipart",
		Profile: reflection.ReflectionProfile{ContentType: "multipart/form-data"},
	})
	if got := carrierNames(upload); strings.Join(got, ",") != "svg,rss,atom,docx,xlsx" {
		t.Fatalf("generic upload carriers = %v", got)
	}
}

func TestXXECarrierBodiesPreserveFormat(t *testing.T) {
	p := payloadgen.Payload{VulnClass: "xxe", ExpectedSignal: "blind_oast"}
	callback := "http://token.oast.test/"
	for _, name := range []string{"svg", "rss", "atom"} {
		carrier := xxeCarriers(ScanTarget{EndpointURL: "https://example.test/" + name, Profile: reflection.ReflectionProfile{ContentType: carrierContentType(name)}})[0]
		body, contentType, err := buildXXECarrierRequest(carrier, ScanTarget{}, p, false, callback)
		if err != nil {
			t.Fatal(err)
		}
		if contentType != carrierContentType(name) || !bytes.Contains(body, []byte(callback)) ||
			!bytes.Contains(body, []byte("<!DOCTYPE "+xxeCarrierDoctype(name))) {
			t.Fatalf("invalid %s carrier: content-type=%q body=%q", name, contentType, body)
		}
	}

	for _, name := range []string{"docx", "xlsx"} {
		carrier := xxeCarriers(ScanTarget{EndpointURL: "https://example.test/" + name, Profile: reflection.ReflectionProfile{ContentType: carrierContentType(name)}})[0]
		body, contentType, err := buildXXECarrierRequest(carrier, ScanTarget{}, p, false, callback)
		if err != nil {
			t.Fatal(err)
		}
		if contentType != carrierContentType(name) {
			t.Fatalf("%s content type = %q", name, contentType)
		}
		xml := officeMainXML(t, name, body)
		if !strings.Contains(xml, callback) || !strings.Contains(xml, "<!DOCTYPE") {
			t.Fatalf("%s main XML lacks XXE callback: %q", name, xml)
		}
	}
}

func TestXXEMultipartOfficeCarrier(t *testing.T) {
	target := ScanTarget{Parameter: "document", Location: "multipart"}
	carrier := xxeCarrier{name: "xlsx", contentType: carrierContentType("xlsx"), extension: ".xlsx", multipart: true}
	body, contentType, err := buildXXECarrierRequest(carrier, target,
		payloadgen.Payload{VulnClass: "xxe", ExpectedSignal: "blind_oast"}, false, "http://token.oast.test/")
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "multipart/form-data" {
		t.Fatalf("multipart content type = %q, err=%v", contentType, err)
	}
	part, err := multipart.NewReader(bytes.NewReader(body), params["boundary"]).NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if part.FormName() != "document" || part.FileName() != "akca-xxe.xlsx" || part.Header.Get("Content-Type") != carrierContentType("xlsx") {
		t.Fatalf("unexpected multipart part: name=%q filename=%q type=%q", part.FormName(), part.FileName(), part.Header.Get("Content-Type"))
	}
	content, _ := io.ReadAll(part)
	if !strings.Contains(officeMainXML(t, "xlsx", content), "token.oast.test") {
		t.Fatal("multipart XLSX does not contain the OAST entity")
	}
}

type xxeOfficeClient struct{}

func (xxeOfficeClient) Do(_ context.Context, method, rawURL string, body []byte, headers map[string]string) (httpclient.RequestResponse, error) {
	response := "baseline"
	if strings.Contains(officeMainXMLBytes("docx", body), `<!ENTITY xxe "AKCA_XXE_TEST">`) {
		response = "AKCA_XXE_TEST"
	}
	return httpclient.RequestResponse{
		Request:  httpclient.RequestRecord{Method: method, URL: rawURL, Body: string(body), Headers: headers},
		Response: httpclient.ResponseRecord{StatusCode: 200, Body: response},
	}, nil
}

func TestXXEDOCXCallbackCarrierCanProduceDifferentialFinding(t *testing.T) {
	cfg := config.DefaultScanConfig()
	target := ScanTarget{
		EndpointURL: "https://example.test/import", Method: "POST", Parameter: "document", Location: "body",
		Profile: reflection.ReflectionProfile{ContentType: carrierContentType("docx")},
	}
	runner := NewRunner("scan-xxe-docx", xxeOfficeClient{}, scope.NewEngine(cfg), nil,
		verification.NewEngine(nil, nil), nil, func(string, string, map[string]interface{}) error { return nil }, cfg)
	findings := runner.runXXE(context.Background(), target)
	if len(findings) != 1 || findings[0].VulnClass != "xxe" || !findings[0].Evidence.Verification.ProofSatisfied {
		t.Fatalf("DOCX XXE findings = %#v", findings)
	}
}

func carrierNames(carriers []xxeCarrier) []string {
	out := make([]string, 0, len(carriers))
	for _, carrier := range carriers {
		out = append(out, carrier.name)
	}
	return out
}

func carrierContentType(name string) string {
	for _, carrier := range xxeCarriers(ScanTarget{EndpointURL: "https://example.test/file." + name}) {
		if carrier.name == name {
			return carrier.contentType
		}
	}
	return ""
}

func officeMainXML(t *testing.T, kind string, body []byte) string {
	t.Helper()
	xml := officeMainXMLBytes(kind, body)
	if xml == "" {
		t.Fatalf("%s archive has no readable main XML", kind)
	}
	return xml
}

func officeMainXMLBytes(kind string, body []byte) string {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return ""
	}
	want := "word/document.xml"
	if kind == "xlsx" {
		want = "xl/workbook.xml"
	}
	for _, file := range zr.File {
		if file.Name != want {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			return ""
		}
		content, _ := io.ReadAll(reader)
		_ = reader.Close()
		return string(content)
	}
	return ""
}
