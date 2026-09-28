package modules

import "testing"

func TestComponentFingerprintsReachCuratedCatalogIdentities(t *testing.T) {
	cases := []struct {
		body, product, version string
	}{
		{"Apache/2.4.67", "http_server", "2.4.67"},
		{"next.js/15.1.8", "nextjs", "15.1.8"},
		{"react-server-dom-webpack@19.1.1", "react-server-dom", "19.1.1"},
	}
	for _, tc := range cases {
		components := detectComponents(nil, tc.body)
		found := false
		for _, component := range components {
			if component.Product == tc.product && component.Version == tc.version {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q did not produce %s %s: %+v", tc.body, tc.product, tc.version, components)
		}
	}
}
