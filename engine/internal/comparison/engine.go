package comparison

import (
	"encoding/json"

	"github.com/akha-security/akca/engine/internal/storage"
)

type Engine struct {
	db *storage.DB
}

func NewEngine(db *storage.DB) *Engine {
	return &Engine{db: db}
}

type Diff struct {
	storage.ComparisonDiff
}

func (e *Engine) Compare(prevScanID, currScanID string) (Diff, error) {
	prevFindings, _ := e.db.ListFindings(prevScanID, 5000, 0)
	currFindings, _ := e.db.ListFindings(currScanID, 5000, 0)
	prevEndpoints, _ := e.db.ListEndpointURLs(prevScanID)
	currEndpoints, _ := e.db.ListEndpointURLs(currScanID)

	prevF := map[string]storage.FindingRecord{}
	currF := map[string]storage.FindingRecord{}
	for _, f := range prevFindings {
		prevF[key(f)] = f
	}
	for _, f := range currFindings {
		currF[key(f)] = f
	}

	diff := Diff{ComparisonDiff: storage.ComparisonDiff{
		PreviousScanID: prevScanID,
		CurrentScanID:  currScanID,
		Summary:        map[string]interface{}{},
	}}
	for k, f := range currF {
		if old, ok := prevF[k]; !ok {
			diff.NewFindings = append(diff.NewFindings, f.Title)
		} else if old.Severity != f.Severity || old.Confidence != f.Confidence {
			diff.ChangedFindings = append(diff.ChangedFindings, f.Title)
		}
	}
	for k, f := range prevF {
		if _, ok := currF[k]; !ok {
			diff.ResolvedFindings = append(diff.ResolvedFindings, f.Title)
		}
	}

	prevE := toSet(prevEndpoints)
	currE := toSet(currEndpoints)
	for u := range currE {
		if !prevE[u] {
			diff.NewEndpoints = append(diff.NewEndpoints, u)
		}
	}
	for u := range prevE {
		if !currE[u] {
			diff.RemovedEndpoints = append(diff.RemovedEndpoints, u)
		}
	}
	diff.Summary["new_count"] = len(diff.NewFindings)
	diff.Summary["resolved_count"] = len(diff.ResolvedFindings)
	diff.Summary["changed_count"] = len(diff.ChangedFindings)
	diff.Summary["new_endpoints"] = len(diff.NewEndpoints)
	diff.Summary["removed_endpoints"] = len(diff.RemovedEndpoints)

	raw, _ := json.Marshal(diff.ComparisonDiff)
	if err := e.db.SaveComparisonDiff(prevScanID, currScanID, string(raw)); err != nil {
		return diff, err
	}
	return diff, nil
}

func key(f storage.FindingRecord) string {
	return f.VulnClass + "|" + f.Title + "|" + f.EndpointURL
}

func toSet(urls []string) map[string]bool {
	m := make(map[string]bool, len(urls))
	for _, u := range urls {
		m[u] = true
	}
	return m
}
