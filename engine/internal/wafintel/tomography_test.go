package wafintel

import (
	"context"
	"net/url"
	"testing"
)

type tomographyReflectClient struct {
	extraURLDecodes int
	reflectValues   bool
}

func (c tomographyReflectClient) Do(_ context.Context, _ string, rawURL string, _ []byte, _ map[string]string) (int, string, error) {
	if !c.reflectValues {
		return 200, "no reflection", nil
	}
	u, _ := url.Parse(rawURL)
	value := u.Query().Get("akca_tomography")
	if value == "" {
		value = u.Query().Get("akca_tomography_plus")
	}
	for i := 0; i < c.extraURLDecodes; i++ {
		value, _ = url.QueryUnescape(value)
	}
	return 200, "reflected=" + value, nil
}

func TestParserTomographyObservesQueryNormalization(t *testing.T) {
	runner := &Runner{client: tomographyReflectClient{extraURLDecodes: 1, reflectValues: true}}
	learn := runner.probeParserTomography(context.Background(), "https://example.com/echo", 200, "baseline", NewLearningProfile("example.com"))
	if !learn.Decoder.QueryURLDecodeObserved || learn.Decoder.QueryURLDecodeDepth != 2 {
		t.Fatalf("expected two observed URL decode layers, got %+v", learn.Decoder)
	}
	if !learn.Decoder.QueryPlusObserved || !learn.Decoder.QueryPlusAsSpace {
		t.Fatalf("expected query plus-to-space normalization, got %+v", learn.Decoder)
	}
}

func TestParserTomographyDoesNotGuessWithoutReflection(t *testing.T) {
	runner := &Runner{client: tomographyReflectClient{reflectValues: false}}
	learn := runner.probeParserTomography(context.Background(), "https://example.com/", 200, "baseline", NewLearningProfile("example.com"))
	if learn.Decoder.QueryURLDecodeObserved || learn.Decoder.QueryPlusObserved {
		t.Fatalf("non-reflecting endpoint must remain unknown, got %+v", learn.Decoder)
	}
}

func TestParserTomographyMarksConflictingRoutes(t *testing.T) {
	profile := DecoderProfile{}
	recordQueryURLDecodeDepth(&profile, 2)
	recordQueryURLDecodeDepth(&profile, 1)
	recordQueryPlusBehavior(&profile, true)
	recordQueryPlusBehavior(&profile, false)
	if !profile.QueryURLDecodeConflict || !profile.QueryPlusConflict {
		t.Fatalf("conflicting route behavior must disable host-wide assumptions: %+v", profile)
	}
	if profile.QueryURLDecodeDepth != 2 || !profile.QueryPlusAsSpace {
		t.Fatalf("first confirmed observation should remain intact for diagnostics: %+v", profile)
	}
}
