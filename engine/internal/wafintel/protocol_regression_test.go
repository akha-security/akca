package wafintel_test

import (
	"github.com/akha-security/akca/engine/internal/wafintel"
	"testing"
)

func TestUnsupportedProtocolMarkersAreNotAdvertisedOrEmitted(t *testing.T) {
	for _, vendor := range []string{"Cloudflare", "Akamai", "Imperva", "F5 BIG-IP"} {
		strategy := wafintel.SelectStrategy(vendor, wafintel.NewLearningProfile("target.test"))
		for _, protocol := range strategy.Protocol {
			switch protocol {
			case "chunked", "line_fold", "timing_jitter", "fragmentation":
				t.Fatalf("%s advertises unimplemented transport %s", vendor, protocol)
			}
		}
	}
	_, headers := wafintel.ApplyStrategy("test", wafintel.Strategy{Protocol: []string{"chunked", "line_fold", "timing_jitter"}})
	if len(headers) != 0 {
		t.Fatalf("inert transport flags emitted as headers: %v", headers)
	}
}
