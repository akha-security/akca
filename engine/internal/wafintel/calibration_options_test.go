package wafintel_test

import (
	"context"
	"testing"

	"github.com/akha-security/akca/engine/internal/models"
	"github.com/akha-security/akca/engine/internal/storage"
	"github.com/akha-security/akca/engine/internal/wafintel"
)

type calibrationRecorder struct {
	calls   int
	headers []map[string]string
}

func (c *calibrationRecorder) Do(_ context.Context, _ string, _ string, _ []byte, headers map[string]string) (int, string, error) {
	c.calls++
	c.headers = append(c.headers, headers)
	return 200, "ok", nil
}

func TestCalibrationHonorsOptOutAndSeparatesProtocolHeaders(t *testing.T) {
	db, err := storage.Open(t.TempDir() + "/calibration.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if err = db.EnsureScan("calibration"); err != nil {
		t.Fatal(err)
	}
	if err = db.SaveWAFProfile("calibration", models.WAFProfile{Host: "waf.test", Vendor: "Fastly"}); err != nil {
		t.Fatal(err)
	}
	client := &calibrationRecorder{}
	r := wafintel.NewRunner("calibration", db, func(string, string, map[string]interface{}) error { return nil })
	r.SetClient(client)
	if err = r.CalibrateWithOptions(context.Background(), []string{"https://waf.test"}, wafintel.CalibrationOptions{DisablePayloadAdaptation: true}); err != nil {
		t.Fatal(err)
	}
	if client.calls != 0 {
		t.Fatalf("disabled adaptation still sent %d calibration probes", client.calls)
	}
	if err = r.Calibrate(context.Background(), []string{"https://waf.test"}); err != nil {
		t.Fatal(err)
	}
	if client.calls == 0 {
		t.Fatal("auto calibration did not run")
	}
	for _, headers := range client.headers {
		if len(headers) != 0 {
			t.Fatalf("default calibration enabled protocol headers: %v", headers)
		}
	}
	client.headers = nil
	if err = r.CalibrateWithOptions(context.Background(), []string{"https://waf.test"}, wafintel.CalibrationOptions{AllowProtocolMutations: true}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, headers := range client.headers {
		found = found || headers["X-Forwarded-For"] != ""
	}
	if !found {
		t.Fatal("explicit protocol header opt-in was not applied")
	}
}
