package app

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestReadAPIBundlePreservesDefinitionsAndIncludes(t *testing.T) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, body := range map[string]string{"api.raml": "#%RAML 1.0\ntitle: Test\n", "types/user.raml": "type: object\n"} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	bundle, err := readAPIBundle(buffer.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle) != 2 || !looksLikeAPIDefinition("api.raml", bundle["api.raml"]) || looksLikeAPIDefinition("types/user.raml", bundle["types/user.raml"]) {
		t.Fatalf("unexpected bundle classification: %#v", bundle)
	}
}

func TestReadAPIBundleRejectsTraversal(t *testing.T) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	entry, err := writer.Create("../outside.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write([]byte("openapi: 3.1.0"))
	_ = writer.Close()
	if _, err := readAPIBundle(buffer.Bytes()); err == nil {
		t.Fatal("zip-slip path must be rejected")
	}
}
