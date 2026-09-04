package anomaly

import (
	"testing"
)

func TestAnomalyEngine(t *testing.T) {
	engine := NewDefaultEngine()

	// Create 10 normal responses (status 200, normal HTML)
	var records []*ResponseRecord
	for i := 0; i < 10; i++ {
		attrs := ExtractAttributes(200, "<html><head><title>Dashboard</title></head><body>Welcome User</body></html>", map[string]string{"Content-Type": "text/html"})
		records = append(records, NewResponseRecord(attrs, "normal"))
	}

	// Create 1 anomalous response (status 500, SQL error, different title and div)
	anomAttrs := ExtractAttributes(500, "<html><head><title>Database Fatal Error</title></head><body><div id='sql-stack'>Syntax error in SQL statement</div></body></html>", map[string]string{"Content-Type": "text/html", "Server": "Apache"})
	anomRecord := NewResponseRecord(anomAttrs, "anomalous")
	records = append(records, anomRecord)

	err := engine.RankAndSort(records)
	if err != nil {
		t.Fatalf("RankAndSort failed: %v", err)
	}

	// The first record must be the anomalous response with the highest score!
	if records[0].Metadata != "anomalous" {
		t.Fatalf("expected highest ranked record to be anomalous, got: %v with score %d", records[0].Metadata, records[0].Score)
	}

	if records[0].Score <= records[len(records)-1].Score {
		t.Fatalf("anomalous score %d should be higher than normal score %d", records[0].Score, records[len(records)-1].Score)
	}
}
